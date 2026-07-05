"""SOTA-3: ordered assurance taxonomy, RATS mapping, verifier thresholds."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentauth.receipts import (
    AgentWrapper,
    Policy,
    TrustTier,
    meets_assurance_threshold,
    tier_ordinal,
    trust_tier_for_level,
)
from agentauth.receipts.assurance import (
    AssuranceLevel,
    RatsRole,
    assurance_from_proof,
    enrich_assurance_dict,
    parse_trust_tier,
    rats_roles_reference,
)
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof, ProofBundle
from agentauth.receipts.verification import VerifyErrorCode

ROOT = Path(__file__).resolve().parents[2]


def test_trust_tier_ordering_is_monotonic():
    tiers = list(TrustTier)
    ordinals = [tier_ordinal(t) for t in tiers]
    assert ordinals == sorted(ordinals)
    assert len(set(ordinals)) == len(ordinals)


def test_assurance_level_maps_to_expected_tier():
    assert trust_tier_for_level(AssuranceLevel.SHADOW) == TrustTier.DECLARED
    assert trust_tier_for_level(AssuranceLevel.OPERATOR_SIGNED) == TrustTier.SIGNED
    assert trust_tier_for_level(AssuranceLevel.TEE_HYBRID_CLAIMED) == TrustTier.SIGNED
    assert trust_tier_for_level(AssuranceLevel.TEE_ATTESTED) == TrustTier.TEE_ATTESTED
    assert trust_tier_for_level(AssuranceLevel.POLICY_PROVED) == TrustTier.ZK_POLICY_PROVED
    assert trust_tier_for_level(AssuranceLevel.COMPOSED_PROVED) == TrustTier.ZK_EXECUTION_PROVED


def test_meets_assurance_threshold():
    assert meets_assurance_threshold(TrustTier.DECLARED, TrustTier.DECLARED)
    assert meets_assurance_threshold(TrustTier.ZK_POLICY_PROVED, TrustTier.SIGNED)
    assert not meets_assurance_threshold(TrustTier.DECLARED, TrustTier.SIGNED)
    assert not meets_assurance_threshold("shadow", "signed")
    assert meets_assurance_threshold("policy_proved", TrustTier.ZK_POLICY_PROVED)


def test_parse_trust_tier_accepts_level_or_tier():
    assert parse_trust_tier("signed") == TrustTier.SIGNED
    assert parse_trust_tier("shadow") == TrustTier.DECLARED
    assert parse_trust_tier(AssuranceLevel.COMPOSED_PROVED) == TrustTier.ZK_EXECUTION_PROVED


def test_assurance_summary_includes_taxonomy_fields():
    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.SHADOW,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    summary = assurance_from_proof(proof)
    payload = summary.to_dict()
    assert payload["level"] == "shadow"
    assert payload["tier"] == "declared"
    assert payload["tier_ordinal"] == 0
    assert payload["tier_scale"] == "agent-receipts.trust-tier.v1"


def test_enrich_assurance_dict_backfills_missing_tier():
    enriched = enrich_assurance_dict({"level": "policy_proved"})
    assert enriched["tier"] == "zk_policy_proved"
    assert enriched["tier_ordinal"] == 5


def test_rats_roles_reference():
    roles = rats_roles_reference()
    assert roles["agent_prover"] == RatsRole.ATTESTER.value
    assert roles["agent_receipts_verifier"] == RatsRole.VERIFIER.value
    assert roles["evidence_consumer"] == RatsRole.RELYING_PARTY.value


def test_verify_bundle_emits_assurance_tier():
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    check = verify_receipt_bundle(bundle)
    assert check["assurance"]["tier"] == "declared"
    assert check["assurance"]["tier_ordinal"] == 0


def test_verify_bundle_min_assurance_tier_rejects_low_tier():
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    check = verify_receipt_bundle(bundle, min_assurance_tier="signed")
    assert check["valid"] is False
    assert check["assurance"]["meets_minimum"] is False
    assert check["assurance"]["required_tier"] == "signed"
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.ASSURANCE_THRESHOLD_NOT_MET.value in codes


def test_verify_bundle_min_assurance_tier_accepts_matching_tier():
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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    check = verify_receipt_bundle(bundle, min_assurance_tier="declared")
    assert check["assurance"]["meets_minimum"] is True
    # Shadow receipts still fail crypto verification; threshold alone does not force valid.
    assert check["assurance"]["required_tier"] == "declared"


def test_verify_bundle_rejects_inflated_stored_assurance_tier():
    from agentauth.receipts.verification import VerifyErrorCode

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
    bundle = build_receipt_bundle(result, certificate=cert, policy=policy)
    stored = bundle["evidence"]["assurance"]
    stored["tier"] = TrustTier.TEE_ATTESTED.value
    check = verify_receipt_bundle(bundle, min_assurance_tier="tee_attested")
    codes = {item["code"] for item in check["issues"]}
    assert VerifyErrorCode.UNSUPPORTED_ASSURANCE.value in codes
    assert VerifyErrorCode.ASSURANCE_THRESHOLD_NOT_MET.value in codes
    assert check["assurance"]["meets_minimum"] is False


@pytest.mark.parametrize(
    ("level", "expected_tier", "expected_ordinal"),
    [
        ("policy_proved", "zk_policy_proved", 5),
        ("composed_proved", "zk_execution_proved", 6),
    ],
)
def test_policy_and_composed_levels_map_to_zk_tiers(level, expected_tier, expected_ordinal):
    proof = ExecutionProof.from_action(
        dev_certificate("pol"),
        {"input": {}},
        {"decision": "approve"},
        policy_satisfied=True,
        path=AttestationPath.FULL_ZK,
        decision_outcome=DecisionOutcome.ALLOW,
    )
    if level == "policy_proved":
        proof.bundle = ProofBundle(policy_proof=b"{}", verification_key_id="policy_range_v3")
    else:
        proof.bundle = ProofBundle(composed_proof=b"{}", verification_key_id="composed")
    summary = assurance_from_proof(proof)
    assert summary.to_dict()["tier"] == expected_tier
    assert summary.to_dict()["tier_ordinal"] == expected_ordinal
