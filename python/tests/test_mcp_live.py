"""Live stdio MCP server + ReceiptedMcpClient integration tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from agentauth.receipts import AgentWrapper, Policy, capability_allows, mcp_tool_capability
from agentauth.receipts.mcp_client import (
    McpServerSpec,
    ReceiptedMcpClient,
    connect_fraud_mcp_server,
)

ROOT = Path(__file__).resolve().parents[2]


def _authorizer(*tools: str):
    capabilities = [mcp_tool_capability(tool) for tool in tools]

    def authorize(resource: str, action: str) -> dict:
        allowed = capability_allows(capabilities, resource, action)
        return {"allowed": allowed, "reason": "authorized" if allowed else "denied"}

    return authorize


@pytest.mark.asyncio
async def test_live_mcp_tool_call_with_receipt():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
        capability_authorizer=_authorizer("score_fraud_model"),
    )
    spec = McpServerSpec(
        command=sys.executable,
        args=[str(ROOT / "examples" / "mcp_live_server.py")],
    )
    async with connect_fraud_mcp_server(spec) as session:
        client = ReceiptedMcpClient(agent, session)
        tools = await client.list_tools()
        assert "score_fraud_model" in tools

        result = await client.call_tool(
            "score_fraud_model",
            {"transaction_id": "t1", "amount": 5000.0},
        )
        assert result.output["status"] == "ok"
        assert result.output["result"]["fraud_score"] == 0.5
        assert result.audit_record.action == "mcp.tools/call/score_fraud_model"
        assert result.execution_context.action.action_category == "mcp_tool_call"
        assert (
            result.execution_context.action.resource_ref
            == "agent-receipts-fraud:score_fraud_model"
        )
        assert result.execution_context.touched_resources == [
            "mcp://agent-receipts-fraud/score_fraud_model"
        ]

        blocked = await client.call_tool("transfer_funds", {"amount": 1})
        assert blocked.blocked is True

    agent.audit.verify_chain()
    assert len(agent.audit) == 2
