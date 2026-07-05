#!/usr/bin/env python3
"""Receipted MCP client over SSE (server must already be running)."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import AgentWrapper, Policy  # noqa: E402
from agentauth.receipts.mcp_client import (  # noqa: E402
    ReceiptedMcpClient,
    connect_mcp,
    default_sse_spec,
)


async def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    spec = default_sse_spec(port=port)

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
        policy=policy,
        mode="bounded_auto",
        audit_db=ROOT / ".audit" / "mcp_sse.sqlite",
    )

    print("SSE URL:", spec.client_url())
    async with connect_mcp(spec) as session:
        client = ReceiptedMcpClient(agent, session, transport="sse")
        tools = await client.list_tools()
        print("tools:", tools)

        result = await client.call_tool(
            "score_fraud_model",
            {"transaction_id": "tx-sse-1", "amount": 9000.0},
        )
        print("score:", result.output["status"], result.output.get("result"))
        print("proof_id:", result.proof.proof_id)

    agent.audit.verify_chain()
    print("audit ok, records:", len(agent.audit))


if __name__ == "__main__":
    asyncio.run(main())
