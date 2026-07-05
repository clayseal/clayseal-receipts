from __future__ import annotations

from typing import Any

from agentauth.receipts.mcp import ReceiptedMcpGateway, ToolCallResult
from agentauth.receipts.mcp_client import ReceiptedMcpClient, parse_call_tool_result, require_mcp


async def receipted_call_tool(
    client: ReceiptedMcpClient,
    name: str,
    arguments: dict[str, Any] | None = None,
) -> Any:
    """Call a tool through ReceiptedMcpClient and return the parsed result payload."""
    result = await client.call_tool(name, arguments)
    if result.blocked:
        raise PermissionError(
            f"MCP tool {name!r} blocked by policy: {result.policy_violations}"
        )
    return result.output.get("result")


def wrap_mcp_session(
    session: Any,
    gateway: ReceiptedMcpGateway,
) -> ReceiptedMcpClient:
    """
    Wrap an existing MCP ClientSession with receipt generation.

    Prefer `ReceiptedMcpClient` directly for new code.
    """
    require_mcp()
    client = ReceiptedMcpClient(gateway.agent, session, server_name=gateway.server_name)
    client._policy = gateway
    return client


async def call_tool_via_gateway_session(
    session: Any,
    gateway: ReceiptedMcpGateway,
    name: str,
    arguments: dict[str, Any] | None = None,
) -> ToolCallResult:
    """Bridge helper: remote MCP call with gateway policy enforcement."""
    client = wrap_mcp_session(session, gateway)
    return await client.call_tool(name, arguments)


__all__ = [
    "call_tool_via_gateway_session",
    "parse_call_tool_result",
    "receipted_call_tool",
    "wrap_mcp_session",
]
