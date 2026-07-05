"""SSE / streamable-http MCP transport integration tests."""

from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from agentauth.receipts import AgentWrapper, Policy, capability_allows, mcp_tool_capability
from agentauth.receipts.mcp_client import McpConnectionSpec, ReceiptedMcpClient, connect_mcp

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "examples" / "mcp_live_server.py"


def _authorizer(*tools: str):
    capabilities = [mcp_tool_capability(tool) for tool in tools]

    def authorize(resource: str, action: str) -> dict:
        allowed = capability_allows(capabilities, resource, action)
        return {"allowed": allowed, "reason": "authorized" if allowed else "denied"}

    return authorize


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _start_server(transport: str, port: int) -> subprocess.Popen:
    return subprocess.Popen(
        [
            sys.executable,
            str(SERVER),
            "--transport",
            transport,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


async def _wait_for_server(
    spec: McpConnectionSpec,
    proc: subprocess.Popen,
    timeout: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"MCP server exited early (code {proc.returncode})")
        try:
            async with connect_mcp(spec) as session:
                await session.list_tools()
            return
        except Exception as exc:
            last_error = exc
            await asyncio.sleep(0.3)
    raise TimeoutError(f"server not ready: {last_error}")


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["sse", "streamable-http"])
async def test_remote_mcp_transport_with_receipts(transport: str):
    port = _free_port()
    proc = _start_server(transport, port)
    spec = McpConnectionSpec(transport=transport, host="127.0.0.1", port=port)

    try:
        await _wait_for_server(spec, proc)

        policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
        agent = AgentWrapper(
            model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
            policy=policy,
            mode="shadow",
            audit_db=":memory:",
            capability_authorizer=_authorizer("score_fraud_model"),
        )
        async with connect_mcp(spec) as session:
            client = ReceiptedMcpClient(agent, session, transport=transport)
            tools = await client.list_tools()
            assert "score_fraud_model" in tools

            result = await client.call_tool(
                "score_fraud_model",
                {"transaction_id": "remote-1", "amount": 2000.0},
            )
            assert result.output["status"] == "ok"
            assert result.output["result"]["fraud_score"] == 0.2
            assert result.execution_context.action.action_category == "mcp_tool_call"
            assert result.execution_context.touched_resources == [
                "mcp://agent-receipts-fraud/score_fraud_model"
            ]

        agent.audit.verify_chain()
        assert len(agent.audit) == 1
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.mark.asyncio
@pytest.mark.skipif(
    not (ROOT / "target" / "release" / "agent-receipts").is_file(),
    reason="release CLI not built in ./target",
)
async def test_sse_prove_composed_on_live_mcp(allow_stub_proofs):
    port = _free_port()
    proc = _start_server("sse", port)
    spec = McpConnectionSpec(transport="sse", host="127.0.0.1", port=port)

    try:
        await _wait_for_server(spec, proc)

        policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
        from agentauth.receipts.certificate import dev_certificate

        cert = dev_certificate(
            policy.commitment(),
            model_hash="sha256:fraud-head-onnx-v1",
        )
        agent = AgentWrapper(
            model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
            policy=policy,
            certificate=cert,
            mode="prove",
            prove_composed=True,
            audit_db=":memory:",
            model_provenance_hash="sha256:fraud-head-onnx-v1",
            capability_authorizer=_authorizer("score_fraud_model"),
        )

        async with connect_mcp(spec) as session:
            client = ReceiptedMcpClient(agent, session, transport="sse")
            result = await client.call_tool(
                "score_fraud_model",
                {"transaction_id": "prove-remote", "amount": 4000.0},
            )
            assert result.output["status"] == "ok"
            assert result.proof.bundle.composed_proof or result.proof.bundle.policy_proof
            verification = result.proof.verify()
            if result.proof.attestation_path.value == "shadow":
                assert verification["valid"] is False
                assert any("shadow mode" in reason for reason in verification["reasons"])
            else:
                assert verification["valid"] is True, verification

        agent.audit.verify_chain()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
