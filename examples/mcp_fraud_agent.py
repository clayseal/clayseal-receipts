#!/usr/bin/env python3
"""MCP tool gateway demo: Biscuit capabilities, audit chain, delegation."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import common  # noqa: E402

from agentauth.receipts import (  # noqa: E402
    Policy,
    ReceiptedMcpGateway,
    issue_delegation,
    mcp_tool_capability,
)
from agentauth.receipts.fraud_tools import (  # noqa: E402
    fetch_customer_profile,
    score_fraud_model,
    score_transaction,
)
from agentauth.receipts.integration import wrap_agentauth_session


def toy_fraud_agent(inp: dict) -> dict:
    return score_fraud_model(inp)


def main() -> None:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    auth, _api_key, _url = common.bootstrap("MCP Demo")
    identity = auth.identify(
        agent_type="fraud-reviewer",
        owner="risk-team@example.com",
        capabilities=[
            mcp_tool_capability("score_transaction"),
            mcp_tool_capability("fetch_customer_profile"),
        ],
    )
    agent = wrap_agentauth_session(
        identity,
        model=toy_fraud_agent,
        policy=policy,
        mode="shadow",
        audit_db=ROOT / ".audit" / "mcp_demo.sqlite",
    )
    gateway = ReceiptedMcpGateway(agent, server_name="fraud-mcp")

    gateway.register_tool("score_transaction", score_transaction)
    gateway.register_tool("fetch_customer_profile", fetch_customer_profile)

    run = agent.run({"transaction_id": "tx-100", "amount": 1200.0})
    print("agent.run decision:", run.output["decision"], "proof:", run.proof.proof_id)

    ok = gateway.call_tool(
        "score_transaction",
        {"transaction_id": "tx-100"},
    )
    print("tool ok:", ok.output["status"], "audit seq:", ok.audit_record.seq)

    blocked = gateway.call_tool("transfer_funds", {"amount": 1_000_000})
    print("blocked tool:", blocked.blocked, "violations:", blocked.policy_violations)

    child = issue_delegation(
        None,
        delegate_agent_id=uuid4(),
        capabilities=[mcp_tool_capability("score_transaction")],
    )
    worker_agent = wrap_agentauth_session(
        identity,
        model=toy_fraud_agent,
        policy=policy,
        mode="bounded_auto",
        audit_db=ROOT / ".audit" / "mcp_worker.sqlite",
        certificate=agent.certificate,
    )
    worker_gateway = ReceiptedMcpGateway(
        worker_agent,
        server_name="fraud-mcp-worker",
        delegation=child,
    )
    worker_gateway.register_tool("score_transaction", score_transaction)
    worker_gateway.register_tool("fetch_customer_profile", fetch_customer_profile)

    allowed = worker_gateway.call_tool("score_transaction", {"transaction_id": "tx-200"})
    print("worker allowed:", allowed.output["status"])

    denied = worker_gateway.call_tool("fetch_customer_profile", {"customer_id": "c-1"})
    print("worker denied:", denied.blocked, denied.policy_violations)

    agent.audit.verify_chain()
    print("audit chain length:", len(agent.audit))


if __name__ == "__main__":
    main()
