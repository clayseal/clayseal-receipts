from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.core.signing import (
    generate_keypair,
    key_id_for_public_key_hex,
    sign_bundle,
    verify,
    verify_bundle_signatures,
)


def _proof(i: int) -> ExecutionProof:
    return ExecutionProof(
        proof_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        certificate_ref="cert",
        policy_commitment="pc",
        context_hash="ch",
        output_hash=f"oh{i}",
        attestation_path=AttestationPath.SHADOW,
        policy_satisfied=True,
        decision_outcome=DecisionOutcome.ALLOW,
        authority_version=1,
        session_id=None,
        created_at=datetime.now(timezone.utc),
    )


def test_sign_and_verify_roundtrip():
    key = generate_keypair()
    obj = {"output_commitment": "cafe", "n": 1}
    sig = key.sign(obj)
    assert verify(obj, sig)


def test_verify_rejects_tampered_object():
    key = generate_keypair()
    sig = key.sign({"output_commitment": "cafe"})
    assert not verify({"output_commitment": "beef"}, sig)


def test_bundle_signature_roundtrip_and_tamper():
    key = generate_keypair()
    bundle = {"schema": "x", "output": {"decision": "approve"}}
    sign_bundle(bundle, key, role="agent")
    untrusted = verify_bundle_signatures(bundle)
    assert untrusted["signed"] is True
    assert untrusted["cryptographically_valid"] is True
    assert untrusted["valid"] is False
    assert "no trusted signer policy configured" in untrusted["reasons"]

    trusted = verify_bundle_signatures(
        bundle,
        trusted_public_keys={key.public_key_hex},
    )
    assert trusted["valid"] is True

    bundle["output"]["decision"] = "deny"  # tamper after signing
    result = verify_bundle_signatures(bundle, trusted_public_keys={key.public_key_hex})
    assert not result["valid"]
    assert result["reasons"]


def test_unsigned_bundle_reports_not_signed():
    result = verify_bundle_signatures({"schema": "x"})
    assert result["signed"] is False
    assert result["valid"] is False


def test_bundle_signature_rejects_untrusted_key():
    key = generate_keypair()
    other = generate_keypair()
    bundle = {"schema": "x", "output": {"decision": "approve"}}
    sign_bundle(bundle, key, role="agent")
    result = verify_bundle_signatures(
        bundle,
        trusted_public_keys={other.public_key_hex},
    )
    assert result["cryptographically_valid"] is True
    assert result["valid"] is False
    assert any("untrusted signer" in reason for reason in result["reasons"])


def test_bundle_signature_rejects_mismatched_key_id():
    key = generate_keypair()
    bundle = {"schema": "x", "output": {"decision": "approve"}}
    sign_bundle(bundle, key, role="agent")
    bundle["signatures"][0]["key_id"] = key_id_for_public_key_hex("00" * 32)
    result = verify_bundle_signatures(
        bundle,
        trusted_public_keys={key.public_key_hex},
    )
    assert result["cryptographically_valid"] is False
    assert result["valid"] is False
    assert any(
        "invalid signature" in reason or "key_id does not match" in reason
        for reason in result["reasons"]
    )


def test_audit_records_signed_when_key_present():
    key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    rec = chain.append(_proof(0), action="act0")
    assert rec.signature is not None
    assert verify({"record_hash": rec.record_hash}, rec.signature)


def test_signed_checkpoint_detects_full_chain_rewrite():
    key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    for i in range(3):
        chain.append(_proof(i), action=f"act{i}")

    checkpoint = chain.signed_checkpoint()
    assert chain.verify_checkpoint(checkpoint) is True

    # Simulate a full-chain rewrite: append a 4th record, recomputing hashes
    # consistently. The Merkle root / count change, so the signed checkpoint
    # no longer matches.
    chain.append(_proof(99), action="act99")
    assert chain.verify_checkpoint(checkpoint) is False


def test_verify_signatures_accepts_signed_chain():
    key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    for i in range(3):
        chain.append(_proof(i), action=f"act{i}")
    chain.verify_signatures()  # no raise
    chain.verify_signatures(expected_public_key=key.public_key_hex)  # no raise


def test_verify_signatures_rejects_unexpected_key():
    key = generate_keypair()
    other = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    chain.append(_proof(0), action="act0")
    try:
        chain.verify_signatures(expected_public_key=other.public_key_hex)
    except ValueError as exc:
        assert "unexpected key" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected unexpected-key rejection")


def test_verify_signatures_flags_unsigned_record():
    chain = AuditChain.in_memory()  # no key -> records unsigned
    chain.append(_proof(0), action="act0")
    try:
        chain.verify_signatures()
    except ValueError as exc:
        assert "unsigned" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected unsigned-record rejection")


def test_verify_signatures_rejects_untrusted_signer(monkeypatch):
    key = generate_keypair()
    other = generate_keypair()
    bundle = {"schema": "x", "output": {"decision": "approve"}}
    sign_bundle(bundle, key, role="agent")
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNERS", other.public_key_hex)
    result = verify_bundle_signatures(
        bundle,
        trusted_public_keys={other.public_key_hex},
    )
    assert result["signed"] is True
    assert result["valid"] is False
    assert any("untrusted signer" in reason for reason in result["reasons"])


def test_verify_signatures_accepts_trusted_signer(monkeypatch):
    key = generate_keypair()
    bundle = {"schema": "x", "output": {"decision": "approve"}}
    sign_bundle(bundle, key, role="agent")
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNERS", key.public_key_hex)
    result = verify_bundle_signatures(
        bundle,
        trusted_public_keys={key.public_key_hex},
    )
    assert result["valid"] is True


def test_checkpoint_without_key_is_unsigned_but_consistent():
    chain = AuditChain.in_memory()
    for i in range(2):
        chain.append(_proof(i), action=f"act{i}")
    checkpoint = chain.signed_checkpoint()
    assert "signature" not in checkpoint
    assert chain.verify_checkpoint(checkpoint) is True


def test_load_or_create_key_sets_restrictive_permissions(tmp_path):
    from agentauth.core.signing import load_or_create_key

    key_path = tmp_path / "agent_ed25519.key"
    load_or_create_key(key_path)
    assert (key_path.stat().st_mode & 0o777) == 0o600


def test_load_or_create_key_encrypted_roundtrip(tmp_path):
    from agentauth.core.signing import load_or_create_key

    key_path = tmp_path / "agent_ed25519.key"
    first = load_or_create_key(key_path, password="local-secret")
    second = load_or_create_key(key_path, password="local-secret")
    assert first.public_key_hex == second.public_key_hex


def test_load_or_create_key_requires_password_for_encrypted_key(tmp_path):
    from agentauth.core.signing import load_or_create_key

    key_path = tmp_path / "agent_ed25519.key"
    load_or_create_key(key_path, password="local-secret")
    with pytest.raises(ValueError, match="password-protected"):
        load_or_create_key(key_path)


def test_load_or_create_key_refuses_unencrypted_create_when_required(tmp_path):
    from agentauth.core.signing import load_or_create_key

    key_path = tmp_path / "agent_ed25519.key"
    with pytest.raises(ValueError, match="refusing to create unencrypted"):
        load_or_create_key(key_path, require_encryption=True)
