"""MCP client transports wrapped with Agent Receipts policy + audit."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from agentauth.capabilities.delegation import DelegationToken
from agentauth.receipts.mcp import MCP_TOOL_CALL_ACTION, ReceiptedMcpGateway, ToolCallResult
from agentauth.core.runtime import ActionDescriptor, SideEffectLevel
from agentauth.receipts.wrapper import AgentWrapper

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.sse import sse_client
    from mcp.client.stdio import stdio_client
    from mcp.client.streamable_http import streamablehttp_client
    from mcp.types import CallToolResult
except ImportError as exc:  # pragma: no cover
    ClientSession = None  # type: ignore[misc, assignment]
    StdioServerParameters = None  # type: ignore[misc, assignment]
    stdio_client = None  # type: ignore[misc, assignment]
    sse_client = None  # type: ignore[misc, assignment]
    streamablehttp_client = None  # type: ignore[misc, assignment]
    CallToolResult = Any  # type: ignore[misc, assignment]
    _MCP_IMPORT_ERROR = exc
else:
    _MCP_IMPORT_ERROR = None

McpTransport = Literal["stdio", "sse", "streamable-http"]
MCP_API_KEY_ENV = "AGENT_RECEIPTS_MCP_API_KEY"


def require_mcp() -> None:
    if _MCP_IMPORT_ERROR is not None:
        raise ImportError(
            "MCP SDK required. Install with: pip install 'agent-receipts[mcp]'"
        ) from _MCP_IMPORT_ERROR


def parse_call_tool_result(result: CallToolResult) -> Any:
    """Extract JSON payload from MCP CallToolResult."""
    if result.isError:
        texts = [c.text for c in result.content if hasattr(c, "text") and c.text]
        raise RuntimeError(f"MCP tool error: {' '.join(texts)}")

    if result.structuredContent is not None:
        return result.structuredContent

    for block in result.content:
        text = getattr(block, "text", None)
        if not text:
            continue
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"text": text}
    return {}


def default_server_script() -> Path:
    root = Path(__file__).resolve().parents[2]
    script = root / "examples" / "mcp_live_server.py"
    if script.is_file():
        return script
    return Path(__file__).resolve().parent / "mcp_server.py"


def sse_url(host: str, port: int, path: str = "/sse") -> str:
    return f"http://{host}:{port}{path}"


def streamable_http_url(host: str, port: int, path: str = "/mcp") -> str:
    return f"http://{host}:{port}{path}"


@dataclass
class McpConnectionSpec:
    """Connection parameters for fraud MCP server."""

    transport: McpTransport = "stdio"
    command: str = field(default_factory=lambda: sys.executable)
    args: list[str] = field(default_factory=lambda: [str(default_server_script())])
    env: dict[str, str] | None = None
    host: str = "127.0.0.1"
    port: int = 8000
    url: str | None = None
    api_key: str | None = None

    def http_headers(self) -> dict[str, str] | None:
        key = self.api_key or os.environ.get(MCP_API_KEY_ENV, "").strip()
        if not key:
            return None
        return {"X-API-Key": key}

    def client_url(self) -> str:
        if self.url:
            return self.url
        if self.transport == "sse":
            return sse_url(self.host, self.port)
        if self.transport == "streamable-http":
            return streamable_http_url(self.host, self.port)
        raise ValueError("stdio transport has no URL")

    def server_argv(self) -> list[str]:
        return [
            str(default_server_script()),
            "--transport",
            self.transport,
            "--host",
            self.host,
            "--port",
            str(self.port),
        ]


def default_stdio_spec() -> McpConnectionSpec:
    return McpConnectionSpec(transport="stdio")


def default_sse_spec(port: int = 8000) -> McpConnectionSpec:
    return McpConnectionSpec(transport="sse", port=port)


def default_streamable_http_spec(port: int = 8000) -> McpConnectionSpec:
    return McpConnectionSpec(transport="streamable-http", port=port)


# Backward-compatible alias
McpServerSpec = McpConnectionSpec


def default_fraud_server_spec() -> McpConnectionSpec:
    return default_stdio_spec()


@asynccontextmanager
async def connect_mcp(spec: McpConnectionSpec) -> AsyncIterator[ClientSession]:
    """Connect to fraud MCP server using the configured transport."""
    require_mcp()
    if spec.transport == "stdio":
        async with connect_fraud_mcp_stdio(spec) as session:
            yield session
    elif spec.transport == "sse":
        async with connect_fraud_mcp_sse(
            spec.client_url(),
            headers=spec.http_headers(),
        ) as session:
            yield session
    elif spec.transport == "streamable-http":
        async with connect_fraud_mcp_http(
            spec.client_url(),
            headers=spec.http_headers(),
        ) as session:
            yield session
    else:
        raise ValueError(f"unknown transport: {spec.transport}")


@asynccontextmanager
async def connect_fraud_mcp_stdio(
    spec: McpConnectionSpec | None = None,
) -> AsyncIterator[ClientSession]:
    spec = spec or default_stdio_spec()
    params = StdioServerParameters(
        command=spec.command,
        args=spec.args,
        env=spec.env,
    )
    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def connect_fraud_mcp_sse(
    url: str,
    *,
    headers: dict[str, Any] | None = None,
) -> AsyncIterator[ClientSession]:
    async with sse_client(url, headers=headers) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@asynccontextmanager
async def connect_fraud_mcp_http(
    url: str,
    *,
    headers: dict[str, Any] | None = None,
) -> AsyncIterator[ClientSession]:
    async with streamablehttp_client(url, headers=headers) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


# Legacy name
connect_fraud_mcp_server = connect_mcp


class ReceiptedMcpClient:
    """
    Call tools on a live MCP server with receipts (policy, delegation, audit, optional ZK).

    Use `mode="prove"` and `prove_composed=True` on the wrapped AgentWrapper for
    composed EZKL + Halo2 proofs on tool outputs that include `fraud_score`.
    """

    def __init__(
        self,
        agent: AgentWrapper,
        session: Any,
        *,
        server_name: str = "agent-receipts-fraud",
        delegation: DelegationToken | None = None,
        transport: McpTransport = "stdio",
    ) -> None:
        require_mcp()
        self.agent = agent
        self.session = session
        self.server_name = server_name
        self.transport = transport
        self._policy = ReceiptedMcpGateway(
            agent,
            server_name=server_name,
            delegation=delegation,
        )

    async def list_tools(self) -> list[str]:
        tools = await self.session.list_tools()
        return [t.name for t in tools.tools]

    def _transport_label(self) -> str:
        return f"mcp_{self.transport.replace('-', '_')}"

    def _action_descriptor(self, tool_name: str) -> ActionDescriptor:
        return ActionDescriptor(
            action_name=f"{MCP_TOOL_CALL_ACTION}/{tool_name}",
            action_category="mcp_tool_call",
            resource_type="mcp_tool",
            resource_ref=f"{self.server_name}:{tool_name}",
            side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
    ) -> ToolCallResult:
        args = dict(arguments or {})
        violations = self._policy._collect_violations(name, arguments=args)
        action = self._policy._action_descriptor(name, args)

        tools = await self.list_tools()
        if name not in tools:
            violations.append(f"tool {name} not on MCP server")

        blocked = self._policy._should_block(violations, action) or name not in tools
        transport = self._transport_label()
        touched_resources = [f"mcp://{self.server_name}/{name}"]

        if blocked:
            output = self._policy._tool_output(name, status="blocked", violations=violations)
            run = self.agent.record(
                action=action,
                context={
                    "input": args,
                    "authorization": self._policy._auth_context(name, args, blocked=True),
                    "transport": transport,
                    "touched_resources": touched_resources,
                },
                output=output,
                extra_violations=violations,
                check_policy_output=False,
            )
            return ToolCallResult.from_run(name, args, run, blocked=True)

        try:
            mcp_result = await self.session.call_tool(name, args)
            raw = parse_call_tool_result(mcp_result)
        except Exception as exc:
            violations = [*violations, f"mcp error: {exc}"]
            output = self._policy._tool_output(name, status="error", violations=violations)
            run = self.agent.record(
                action=action,
                context={
                    "input": args,
                    "authorization": self._policy._auth_context(name, args, blocked=False),
                    "transport": transport,
                    "touched_resources": touched_resources,
                },
                output=output,
                extra_violations=violations,
                check_policy_output=False,
            )
            return ToolCallResult.from_run(name, args, run, blocked=True)

        output = self._policy._tool_output(name, status="ok", result=raw)
        if isinstance(raw, dict):
            violations = [*violations, *self.agent.policy.check_output(raw)]

        run = self.agent.record(
            action=action,
            context={
                "input": args,
                "authorization": self._policy._auth_context(name, args, blocked=False),
                "transport": transport,
                "touched_resources": touched_resources,
            },
            output=output,
            extra_violations=violations,
        )
        recommended = None
        if self.agent.mode == "recommend" and violations:
            recommended = "review_tool_output"
        result = ToolCallResult.from_run(name, args, run, blocked=False)
        result.recommended_action = recommended
        return result
