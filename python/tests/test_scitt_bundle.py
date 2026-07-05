"""End-to-end SCITT bundle integration (SOTA-11)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

cbor2 = pytest.importorskip("cbor2")

from agentauth.receipts import scitt
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.certificate import dev_certificate
from agentauth.core.decision import DecisionResult
from agentauth.receipts.export import build_receipt_bundle, verify_receipt_bundle
from agentauth.receipts.policy import Policy
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext
from agentauth.receipts.scitt_bundle import (
    bundle_from_cbor,
    bundle_to_cbor,
    build_scitt_section,
    open_confidential_payload,
    scitt_section_issues,
)
from agentauth.core.signing import generate_keypair
from agentauth.receipts.wrapper import RunResult

ROOT = Path(__file__).resolve().parents[2]


def _policy_and_cert():
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    return policy, dev_certificate(policy.commitment())


def _run_result() -> RunResult:
    proof = ExecutionProof(
        proof_id=uuid.uuid4(),
        agent_id=uuid.uuid4(),
        certificate_ref="cert",
        policy_commitment="pc",
        context_hash="ctx",
        output_hash="out",
        attestation_path=AttestationPath.SHADOW,
        policy_satisfied=True,
        decision_outcome=DecisionOutcome.ALLOW,
        authority_version=1,
        session_id=None,
        created_at=datetime.now(timezone.utc),
    )
    decision = DecisionResult(
        outcome=DecisionOutcome.ALLOW,
        policy_satisfied=True,
    )
    authority = AuthorityContext(authority_id="auth-1")
    action = ActionDescriptor(action_name="agent.run")
    execution_context = ExecutionContext(authority=authority, action=action, input={})
    return RunResult(
        output={"ok": True},
        proof=proof,
        decision=decision,
        execution_context=execution_context,
        audit_record=None,
    )


def test_cbor_roundtrip_matches_json_projection():
    policy, cert = _policy_and_cert()
    result = _run_result()
    bundle = build_receipt_bundle(result, certificate=cert)
    decoded = bundle_from_cbor(bundle_to_cbor(bundle))
    assert decoded["execution_proof"]["output_hash"] == bundle["execution_proof"]["output_hash"]


def test_build_scitt_section_and_verify_receipt_bundle():
    policy, cert = _policy_and_cert()
    issuer = generate_keypair()
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    result = _run_result()
    chain.append(result.proof, action="agent.run")
    result.audit_record = chain.iter_records()[-1]

    bundle = build_receipt_bundle(
        result,
        certificate=cert,
        audit_chain=chain,
        scitt_issuer_key=issuer,
        scitt_issuer="issuer.example",
        scitt_subject=str(result.proof.agent_id),
    )
    assert "scitt" in bundle
    assert scitt_section_issues(bundle) == []

    signed = bytes.fromhex(bundle["scitt"]["signed_statement"])
    assert scitt.verify_statement(signed, issuer.public_key) is not None

    receipt = bytes.fromhex(bundle["scitt"]["audit_inclusion_receipt"])
    record_hash = bundle["audit_record"]["record_hash"]
    assert scitt.verify_receipt(bytes.fromhex(record_hash), receipt, log_key.public_key)

    check = verify_receipt_bundle(bundle)
    assert not any(issue["code"] == "scitt_invalid" for issue in check["issues"])


def test_scitt_section_rejects_tampered_bundle():
    policy, cert = _policy_and_cert()
    issuer = generate_keypair()
    log_key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=log_key)
    result = _run_result()
    record = chain.append(result.proof, action="agent.run")
    result.audit_record = record

    bundle = build_receipt_bundle(
        result,
        certificate=cert,
        audit_chain=chain,
        scitt_issuer_key=issuer,
    )
    bundle["output"] = {"evil": True}
    issues = scitt_section_issues(bundle)
    assert any("payload does not match" in item for item in issues)


def test_confidential_hpke_roundtrip():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    policy, cert = _policy_and_cert()
    issuer = generate_keypair()
    recipient = X25519PrivateKey.generate()
    recipient_pk = recipient.public_key().public_bytes_raw()

    result = _run_result()
    bundle = build_receipt_bundle(result, certificate=cert)
    section = build_scitt_section(
        bundle,
        issuer_key=issuer,
        issuer="i",
        subject="s",
        confidential_recipient_public_key=recipient_pk,
    )
    opened = open_confidential_payload(section, recipient)
    assert bundle_from_cbor(opened)["output"] == bundle["output"]


def test_verify_receipt_bundle_cbor_artifact(tmp_path: Path):
    from agentauth.receipts.export import load_receipt_bundle_cbor, write_receipt_bundle_cbor

    policy, cert = _policy_and_cert()
    bundle = build_receipt_bundle(_run_result(), certificate=cert)
    path = tmp_path / "receipt.cbor"
    write_receipt_bundle_cbor(path, bundle)
    loaded = load_receipt_bundle_cbor(path)
    assert loaded["schema"] == bundle["schema"]
