#!/usr/bin/env python3
"""Live MCP client in prove mode with composed EZKL + Halo2 proofs on score_fraud_model."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import AgentWrapper, Policy, locate_cli  # noqa: E402
from agentauth.receipts.certificate import dev_certificate  # noqa: E402
from agentauth.receipts.mcp_client import (  # noqa: E402
    McpConnectionSpec,
    ReceiptedMcpClient,
    connect_mcp,
)


async def main() -> None:
    cli = locate_cli()
    print("agent-receipts CLI:", cli.binary or cli.message)
    if not cli.available:
        print("Build: CARGO_TARGET_DIR=$PWD/target cargo build -p agent-receipts-cli --release")
        sys.exit(1)

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    model_hash = "sha256:fraud-head-onnx-v1"
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.0},
        policy=policy,
        certificate=dev_certificate(policy.commitment(), model_hash=model_hash),
        mode="prove",
        prove_composed=True,
        audit_db=ROOT / ".audit" / "mcp_live_prove.sqlite",
        model_provenance_hash=model_hash,
    )

    transport = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if transport == "stdio":
        spec = McpConnectionSpec(
            command=sys.executable,
            args=[str(ROOT / "examples" / "mcp_live_server.py")],
        )
    elif transport == "sse":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
        spec = McpConnectionSpec(transport="sse", port=port)
        print("Connect to SSE server at", spec.client_url())
        print("Start server: python3 examples/mcp_live_server.py --transport sse --port", port)
    else:
        print("Usage: mcp_live_prove_client.py [stdio|sse] [port]")
        sys.exit(2)

    async with connect_mcp(spec) as session:
        client = ReceiptedMcpClient(
            agent,
            session,
            server_name="agent-receipts-fraud-live",
            transport=spec.transport,
        )
        tools = await client.list_tools()
        print("MCP tools:", tools)

        result = await client.call_tool(
            "score_fraud_model",
            {"transaction_id": "tx-prove-1", "amount": 3500.0},
        )
        print("status:", result.output["status"])
        print("fraud_score:", result.output.get("result", {}).get("fraud_score"))
        composed = result.proof.bundle.composed_proof
        policy_proof = result.proof.bundle.policy_proof
        print("composed bytes:", len(composed or b""))
        print("policy bytes:", len(policy_proof or b""))
        print("proof verify:", result.proof.verify())

    agent.audit.verify_chain()
    print("audit records:", len(agent.audit))


if __name__ == "__main__":
    asyncio.run(main())
