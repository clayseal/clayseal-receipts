#!/usr/bin/env python3
"""Live MCP pilot: stdio server + ReceiptedMcpClient with audit chain."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import AgentWrapper, Policy  # noqa: E402
from agentauth.receipts.mcp_client import (  # noqa: E402
    McpServerSpec,
    ReceiptedMcpClient,
    connect_fraud_mcp_server,
)


async def main() -> None:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
        policy=policy,
        mode="shadow",
        audit_db=ROOT / ".audit" / "mcp_live.sqlite",
    )

    server = McpServerSpec(
        command=sys.executable,
        args=[str(ROOT / "examples" / "mcp_live_server.py")],
    )

    async with connect_fraud_mcp_server(server) as session:
        client = ReceiptedMcpClient(agent, session, server_name="agent-receipts-fraud-live")
        tools = await client.list_tools()
        print("MCP tools:", tools)

        scored = await client.call_tool(
            "score_fraud_model",
            {"transaction_id": "tx-live-1", "amount": 7500.0},
        )
        print("score_fraud_model:", scored.output["status"], scored.output.get("result"))
        print("proof_id:", scored.proof.proof_id)

        meta = await client.call_tool(
            "score_transaction",
            {"transaction_id": "tx-live-1"},
        )
        print("score_transaction:", meta.output["status"])

        blocked = await client.call_tool("transfer_funds", {"amount": 1})
        print("blocked:", blocked.blocked, blocked.policy_violations)

    agent.audit.verify_chain()
    print("audit records:", len(agent.audit))


if __name__ == "__main__":
    asyncio.run(main())
