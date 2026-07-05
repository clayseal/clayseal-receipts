#!/usr/bin/env python3
"""Prove mode with composed EZKL inference + Halo2 policy proofs."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentauth.receipts import AgentWrapper, Policy, locate_cli  # noqa: E402
from agentauth.receipts.certificate import dev_certificate  # noqa: E402


def onnx_fraud_agent(inp: dict) -> dict:
    amount = float(inp.get("amount", 0))
    score = min(1.0, amount / 10_000.0)
    decision = "deny" if score > 0.8 else "review" if score > 0.4 else "approve"
    return {"decision": decision, "fraud_score": round(score, 4)}


def main() -> None:
    cli = locate_cli()
    print("agent-receipts CLI:", cli.binary or cli.message)
    if not cli.available:
        print("Build: CARGO_TARGET_DIR=$PWD/target cargo build -p agent-receipts-cli --release")
        sys.exit(1)

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    model_hash = "sha256:fraud-head-onnx-v1"
    agent = AgentWrapper(
        model=onnx_fraud_agent,
        policy=policy,
        certificate=dev_certificate(policy.commitment(), model_hash=model_hash),
        mode="prove",
        prove_composed=True,
        audit_db=ROOT / ".audit" / "composed_chain.sqlite",
        model_provenance_hash=model_hash,
    )

    result = agent.run({"transaction_id": "tx-42", "amount": 2500.0})
    print("output:", result.output)
    print("composed bytes:", len(result.proof.bundle.composed_proof or b""))
    print("verify:", result.proof.verify())
    agent.audit.verify_chain()
    print("audit ok, records:", len(agent.audit))


if __name__ == "__main__":
    main()
