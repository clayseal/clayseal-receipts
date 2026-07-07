"""Tests for min_authority_trust_tier verifier parameter."""

from __future__ import annotations

from agentauth.receipts.export import verify_receipt_bundle
from agentauth.receipts.verification import VerifyErrorCode


def _bundle_with_authority(*, trust_tier: str, evidence_verified: bool = True) -> dict:
    return {
        "schema": "agent-receipts.receipt-bundle.v2",
        "execution_proof": {
            "proof_id": "00000000-0000-4000-8000-000000000001",
            "agent_id": "00000000-0000-4000-8000-000000000002",
            "certificate_ref": "sha256:cert",
            "policy_commitment": "sha256:policy",
            "context_hash": "sha256:ctx",
            "output_hash": "sha256:out",
            "attestation_path": "shadow",
            "policy_satisfied": True,
            "decision_outcome": "allow",
            "authority_version": 1,
            "session_id": None,
            "created_at": "2026-01-01T00:00:00+00:00",
            "obligations": [],
            "bundle": {},
        },
        "output": {"ok": True},
        "verification": {"valid": True, "reasons": []},
        "certificate": {
            "agent_id": "00000000-0000-4000-8000-000000000002",
            "policy_commitment": "sha256:policy",
            "issued_at": "2026-01-01T00:00:00+00:00",
            "expires_at": "2030-01-01T00:00:00+00:00",
            "principal": {"principal_id": "p1", "organization": "org"},
        },
        "decision": {"outcome": "allow", "policy_satisfied": True, "violations": []},
        "authority": {
            "authority_id": "agent-1",
            "subject_id": "spiffe://example/agent",
            "issuer": "clay-seal",
            "trust_tier": trust_tier,
            "evidence_verified": evidence_verified,
            "proof_of_possession": trust_tier == "sender_constrained",
        },
        "action": {"action_name": "agent.run"},
        "execution_context": {
            "input": {},
            "authority": {
                "authority_id": "agent-1",
                "subject_id": "spiffe://example/agent",
                "issuer": "clay-seal",
                "trust_tier": trust_tier,
                "evidence_verified": evidence_verified,
                "proof_of_possession": trust_tier == "sender_constrained",
            },
        },
        "evidence": {
            "summary": {
                "outcome": "allow",
                "policy_satisfied": True,
                "attestation_path": "shadow",
            },
            "assurance": {"level": "shadow", "tier": "shadow"},
        },
    }


def test_min_authority_trust_tier_uses_distinct_issue_code(monkeypatch):
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", "1")
    bundle = _bundle_with_authority(trust_tier="declared")
    result = verify_receipt_bundle(bundle, min_authority_trust_tier="workload_attested")
    codes = {item["code"] for item in result.get("issues", [])}
    assert VerifyErrorCode.AUTHORITY_TRUST_THRESHOLD_NOT_MET.value in codes
