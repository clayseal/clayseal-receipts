"""SOTA-16: Notarized Agents additive borrows."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from agentauth.receipts.audit import AuditChain
from agentauth.receipts.export import _witness_divergence_issues
from agentauth.capabilities.mandate import issue_mandate, mandated_hpke_recipient_bytes
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.receipts.revocation import SignerRevocationRegistry
from agentauth.receipts.scitt_bundle import build_scitt_section, scitt_section_issues
from agentauth.core.signing import generate_keypair
from agentauth.receipts.tool_witness import (
    build_tool_witness_body,
    sign_tool_witness,
    verify_tool_witness,
)
from agentauth.receipts.verification import VerifyErrorCode
from agentauth.receipts.wimse import mandate_ref_from_envelope, owner_hpke_pk_b64url


def _proof() -> ExecutionProof:
    return ExecutionProof(
        proof_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        certificate_ref="cert",
        policy_commitment="pc",
        context_hash="ch",
        output_hash="oh",
        attestation_path=AttestationPath.SHADOW,
        policy_satisfied=True,
        decision_outcome=DecisionOutcome.ALLOW,
        authority_version=1,
        session_id=None,
        created_at=datetime.now(timezone.utc),
    )


def test_owner_hpke_pk_bound_in_mandate_and_scitt():
    mandate_key = generate_keypair()
    recipient = X25519PrivateKey.generate()
    recipient_pk = recipient.public_key().public_bytes_raw()
    envelope = issue_mandate(
        issuer=mandate_key.public_key_hex,
        key=mandate_key,
        owner_hpke_pk=owner_hpke_pk_b64url(recipient_pk),
        ttl_seconds=3600,
    )
    mandate_section = {
        **envelope["document"],
        "grant_id": envelope["document"]["grant_id"],
        "commitment": mandate_ref_from_envelope(envelope),
        "document": envelope["document"],
        "signature": envelope["signature"],
    }
    bundle = {
        "action": {"action_name": "x"},
        "mandate": mandate_section,
    }
    assert mandated_hpke_recipient_bytes(bundle) == recipient_pk

    issuer_key = generate_keypair()
    section = build_scitt_section(
        bundle,
        issuer_key=issuer_key,
        issuer="issuer",
        subject="subject",
        confidential_recipient_public_key=recipient_pk,
        mandate_section=mandate_section,
    )
    assert section["confidential"]["recipient_public_key"] == recipient_pk.hex()

    wrong_pk = X25519PrivateKey.generate().public_key().public_bytes_raw()
    with pytest.raises(ValueError, match="owner_hpke_pk"):
        build_scitt_section(
            bundle,
            issuer_key=issuer_key,
            issuer="issuer",
            subject="subject",
            confidential_recipient_public_key=wrong_pk,
            mandate_section=mandate_section,
        )


def test_scitt_verify_rejects_hpke_recipient_mismatch():
    mandate_key = generate_keypair()
    recipient = X25519PrivateKey.generate()
    wrong = X25519PrivateKey.generate()
    envelope = issue_mandate(
        issuer=mandate_key.public_key_hex,
        key=mandate_key,
        owner_hpke_pk=owner_hpke_pk_b64url(recipient.public_key().public_bytes_raw()),
        ttl_seconds=3600,
    )
    mandate_section = {
        "grant_id": envelope["document"]["grant_id"],
        "document": envelope["document"],
        "signature": envelope["signature"],
    }
    bundle = {"mandate": mandate_section, "scitt": {"confidential": {"recipient_public_key": wrong.public_key().public_bytes_raw().hex()}}}
    issues = scitt_section_issues(bundle)
    assert any("recipient_public_key" in item for item in issues)


def test_signer_revocation_uses_integrated_time():
    key = generate_keypair()
    registry = SignerRevocationRegistry()
    chain = AuditChain.in_memory(signing_key=key, revocation_registry=registry)
    proof = _proof()

    chain.append(proof, "action-1")
    chain.append(proof, "action-2")
    registry.revoke(key.public_key_hex, at_seq=2)
    with pytest.raises(ValueError, match="revoked"):
        chain.verify_signatures()


def test_records_for_mandate_ref():
    key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    mandate_key = generate_keypair()
    envelope = issue_mandate(issuer=mandate_key.public_key_hex, key=mandate_key, ttl_seconds=3600)
    ref = mandate_ref_from_envelope(envelope)
    proof = _proof()
    chain.append(proof, "payments.refund", authorization_context={"mandate_ref": ref})
    chain.append(proof, "other", authorization_context={"mandate_ref": "other"})
    matched = chain.records_for_mandate_ref(ref)
    assert len(matched) == 1
    assert matched[0].action == "payments.refund"


def test_tool_witness_verifies_independently():
    tool_key = generate_keypair()
    body = build_tool_witness_body(
        input_hash="a" * 64,
        output_hash="b" * 64,
        mandate_ref="c" * 64,
        action_name="payments.refund",
    )
    descriptor = sign_tool_witness(body, tool_key)
    assert verify_tool_witness(descriptor) == []


def test_witness_divergence_flags_missing_tool_cosign():
    bundle = {
        "action": {
            "action_name": "payments.refund",
            "side_effect_level": "bounded_write",
        },
    }
    issues = _witness_divergence_issues(bundle)
    assert len(issues) == 1
    assert issues[0].code == VerifyErrorCode.WITNESS_DIVERGENCE
