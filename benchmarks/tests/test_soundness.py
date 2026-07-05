"""Soundness benchmark gate: the baseline ladder must order as
plaintext_log  <  naive_canonical  <  agentauth on tamper detection, and AgentAuth
must catch the projection class that the naive signed-receipt design misses."""

from __future__ import annotations

import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.baselines import naive_canonical_verify, plaintext_verify  # noqa: E402

from agentauth.receipts import AgentWrapper, Policy  # noqa: E402
from agentauth.receipts.certificate import dev_certificate  # noqa: E402
from agentauth.receipts.export import (  # noqa: E402
    build_receipt_bundle,
    verify_receipt_bundle,
)
from agentauth.receipts.tamper import leaf_mutations  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]


def _bundle() -> dict:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t1", "amount": 100.0})
    return build_receipt_bundle(result, certificate=cert, policy=policy)


def _sigs(res: dict) -> list[str]:
    return sorted(f"{i.get('code')}|{i.get('message')}" for i in (res.get("issues") or []))


def _flagged(verify_fn, clean: dict, path: str) -> bool:
    mutation = {m.path: m for m in leaf_mutations(clean)}[path]
    base = verify_fn(clean)
    after = verify_fn(mutation.apply(clean))
    return base.get("valid") != after.get("valid") or _sigs(base) != _sigs(after)


def test_plaintext_baseline_accepts_all_tampers():
    bundle = _bundle()
    for path in ("policy.name", "output.decision", "authority.issuer"):
        assert _flagged(plaintext_verify, bundle, path) is False


def test_naive_misses_projection_but_catches_canonical():
    bundle = _bundle()
    # Canonical core (output) — the naive signed-receipt design catches this.
    assert _flagged(naive_canonical_verify, bundle, "output.decision") is True
    # Human-facing projection (policy display block) — naive misses it.
    assert _flagged(naive_canonical_verify, bundle, "policy.name") is False


def test_agentauth_catches_both_classes():
    bundle = _bundle()
    assert _flagged(verify_receipt_bundle, bundle, "output.decision") is True
    assert _flagged(verify_receipt_bundle, bundle, "policy.name") is True
    assert _flagged(verify_receipt_bundle, bundle, "authority.issuer") is True
