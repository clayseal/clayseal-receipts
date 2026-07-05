#!/usr/bin/env python3
"""Shadow-mode demo: policy check + execution proof + audit chain (no ZK latency)."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import AgentWrapper, Policy  # noqa: E402


def toy_fraud_agent(inp: dict) -> dict:
    amount = float(inp.get("amount", 0))
    score = min(1.0, amount / 10_000.0)
    decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
    return {"decision": decision, "fraud_score": round(score, 4)}


def main() -> None:
    policy_path = ROOT / "policies" / "fraud_decision.yaml"
    policy = Policy.from_yaml(policy_path)

    agent = AgentWrapper(
        model=toy_fraud_agent,
        policy=policy,
        mode="shadow",
        audit_db=ROOT / ".audit" / "demo_chain.sqlite",
    )

    cases = [
        {"transaction_id": "tx-1", "amount": 50.0},
        {"transaction_id": "tx-2", "amount": 5_000.0},
        {"transaction_id": "tx-3", "amount": 95_000.0},
    ]

    for case in cases:
        result = agent.run(case, action="score_transaction")
        print("---")
        print("input:", case)
        print("output:", result.output)
        print("violations:", result.policy_violations)
        print("proof_id:", result.proof.proof_id)
        print("verify:", result.proof.verify())

    agent.audit.verify_chain()
    print("---")
    print("audit chain length:", len(agent.audit), "— integrity OK")


if __name__ == "__main__":
    main()
