from __future__ import annotations

from pathlib import Path

import pytest

from agentauth.receipts import AgentWrapper, Policy
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle
from agentauth.core.signing import generate_keypair, sign_bundle
from agentauth.receipts.tamper import (
    TamperCoverageReport,
    analyze_bundle_tampering,
    attacker_resign_mutation,
    cross_bundle_replay_mutations,
)

ROOT = Path(__file__).resolve().parents[2]


def _shadow_bundle(*, amount: float = 100.0) -> dict:
    from agentauth.receipts.audit import AuditChain
    from agentauth.core.signing import generate_keypair

    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    signing_key = generate_keypair()
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.2},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    agent.audit = AuditChain.in_memory(signing_key=signing_key)
    result = agent.run({"transaction_id": f"t-{amount}", "amount": amount})
    return build_receipt_bundle(
        result, certificate=cert, policy=policy, audit_chain=agent.audit
    )


def test_tamper_analysis_detects_known_bound_fields():
    bundle = _shadow_bundle()
    report = analyze_bundle_tampering(bundle)

    assert isinstance(report, TamperCoverageReport)
    by_path = {item.path: item for item in report.outcomes}
    assert by_path["output.decision"].detected is True
    assert by_path["certificate.principal.principal_id"].detected is True
    assert by_path["decision.policy_satisfied"].detected is True


def test_projection_binding_leaves_no_unexpected_security_survivors():
    """Regression gate (EV-RT-2 / EV-RT-3 / EV-RT-5): tampering any cryptographically-bound
    field must be detected. Only audit_record.seq is tolerated — the DB ordinal has no
    proof anchor. audit_record.signature is bound when log_public_key is in-bundle."""
    bundle = _shadow_bundle()
    report = analyze_bundle_tampering(bundle)

    security_prefixes = (
        "authority.",
        "policy.",
        "evidence.",
        "execution_context.",
        "certificate.",
        "output.",
        "session.",
        "audit_record.",
        "execution_proof.",
    )
    # Mirrors of the context-bound action/authority — informational, not integrity.
    informational = (
        "audit_record.action",
        "audit_record.authorization_context.action",
        "audit_record.authorization_context.authority",
    )
    allowed = {"audit_record.seq"}
    survivors = {item.path for item in report.survivors if item.path}
    security_survivors = {
        path
        for path in survivors
        if path.startswith(security_prefixes) and not path.startswith(informational)
    }
    assert security_survivors <= allowed, (
        f"unbound security-relevant fields: {sorted(security_survivors - allowed)}"
    )

    # The projections EV-RT-2/EV-RT-3 bind must be actively detected.
    by_path = {item.path: item for item in report.outcomes}
    for path in (
        "authority.issuer",
        "authority.authority_id",
        "policy.name",
        "policy.commitment",
        "evidence.assurance.tee_verified",
        "evidence.decision_record.policy_satisfied",
        "audit_record.record_hash",
        "audit_record.created_at",
    ):
        assert path in by_path, f"expected path missing from bundle: {path}"
        assert by_path[path].detected, f"tampering undetected for bound field: {path}"


def test_cross_bundle_execution_proof_swap_detected():
    first = _shadow_bundle(amount=100.0)
    second = _shadow_bundle(amount=250.0)
    mutations = cross_bundle_replay_mutations(first, second)
    report = analyze_bundle_tampering(
        first,
        mutations=[item for item in mutations if item.path == "execution_proof"],
    )

    assert report.total_mutations == 1
    assert report.outcomes[0].detected is True


def test_attacker_resign_mutation_detected(trusted_signer, monkeypatch):
    bundle = _shadow_bundle()
    sign_bundle(bundle, trusted_signer, role="agent")
    attacker = generate_keypair()
    report = analyze_bundle_tampering(
        bundle,
        mutations=[attacker_resign_mutation(attacker)],
    )

    assert report.total_mutations == 1
    assert report.outcomes[0].detected is True
    assert "signature_invalid" in report.outcomes[0].issue_codes_after


@pytest.mark.skipif(
    not (ROOT / "target" / "release" / "agent-receipts").is_file(),
    reason="release CLI not built",
)
def test_tamper_analysis_invalidates_valid_prove_bundle(allow_stub_proofs):
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    cert = dev_certificate(policy.commitment())
    agent = AgentWrapper(
        model=lambda inp: {"decision": "approve", "fraud_score": 0.25},
        policy=policy,
        certificate=cert,
        mode="prove",
        prove_composed=False,
        prove_inference=True,
        audit_db=":memory:",
    )
    result = agent.run({"transaction_id": "t2", "amount": 2500.0})
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    report = analyze_bundle_tampering(bundle)

    assert report.baseline_valid is True
    by_path = {item.path: item for item in report.outcomes}
    assert by_path["output.decision"].invalidated is True
    assert by_path["execution_context.input.amount"].invalidated is True
