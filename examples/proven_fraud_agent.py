#!/usr/bin/env python3
"""Prove mode: attach a Halo2 policy-range proof when the Rust CLI is built."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import (  # noqa: E402
    AgentWrapper,
    Policy,
    locate_cli,
    verify_structural_policy,
)
from agentauth.receipts.certificate import dev_certificate  # noqa: E402


def toy_fraud_agent(inp: dict) -> dict:
    amount = float(inp.get("amount", 0))
    score = min(1.0, amount / 10_000.0)
    decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
    return {"decision": decision, "fraud_score": round(score, 4)}


def main() -> None:
    status = locate_cli()
    print("prover:", status.message, status.binary or "")
    if not status.available:
        print("Build the CLI first:")
        print("  cargo build -p agent-receipts-cli --release")
        print("  cargo run -p agent-receipts-cli -- setup")
        sys.exit(1)

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=toy_fraud_agent,
        policy=policy,
        certificate=dev_certificate(policy.commitment()),
        mode="prove",
        prove_composed=False,
        audit_db=ROOT / ".audit" / "proven_chain.sqlite",
    )

    result = agent.run({"transaction_id": "tx-1", "amount": 250.0}, action="score_transaction")
    policy_proof = result.proof.bundle.policy_proof or b""
    print("output:", result.output)
    print("policy_proof bytes:", len(policy_proof))
    print("policy_proof verify:", verify_structural_policy(policy_proof))
    agent.audit.verify_chain()
    print("audit ok, length:", len(agent.audit))


if __name__ == "__main__":
    main()
