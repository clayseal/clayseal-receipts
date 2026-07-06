"""DSSE/in-toto receipt attestations (Phase 3 BYO audit)."""

from __future__ import annotations

import base64
import json

from agentauth.core.signing import generate_keypair

from agentauth.receipts import intoto

BUNDLE = {
    "schema": "agent-receipts.bundle.v2",
    "execution_proof": {"proof_id": "b6c1..42"},
    "decision": {"outcome": "allow"},
}


def test_pae_matches_dsse_spec_golden_vector():
    # PAE("DSSEv1", type, body) with explicit lengths, space-separated.
    assert intoto.pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )


def test_statement_shape_and_subject_digest():
    statement = intoto.receipt_statement(BUNDLE)
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["predicateType"] == "https://agentauth.dev/receipt/v1"
    assert statement["predicate"] == BUNDLE
    subject = statement["subject"][0]
    assert subject["name"] == "b6c1..42"
    assert subject["digest"]["sha256"] == intoto.bundle_subject_digest(BUNDLE)
    assert len(subject["digest"]["sha256"]) == 64


def test_attest_and_verify_roundtrip():
    key = generate_keypair()
    envelope = intoto.attest_receipt_bundle(BUNDLE, key)
    assert envelope["payloadType"] == "application/vnd.in-toto+json"
    assert envelope["signatures"][0]["keyid"] == key.key_id
    statement = intoto.verify_receipt_attestation(envelope, key.public_key, bundle=BUNDLE)
    assert statement is not None
    assert statement["predicate"] == BUNDLE


def test_wrong_key_and_tampered_payload_rejected():
    key = generate_keypair()
    envelope = intoto.attest_receipt_bundle(BUNDLE, key)
    assert intoto.verify_receipt_attestation(envelope, generate_keypair().public_key) is None

    tampered = dict(envelope)
    statement = json.loads(base64.standard_b64decode(envelope["payload"]))
    statement["predicate"]["decision"]["outcome"] = "deny"
    tampered["payload"] = base64.standard_b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    assert intoto.verify_receipt_attestation(tampered, key.public_key) is None


def test_subject_digest_binding_rejects_different_bundle():
    key = generate_keypair()
    envelope = intoto.attest_receipt_bundle(BUNDLE, key)
    other = {**BUNDLE, "decision": {"outcome": "deny"}}
    assert intoto.verify_receipt_attestation(envelope, key.public_key, bundle=other) is None


def test_verify_envelope_accepts_foreign_predicate_types():
    # e.g. OpenSSF Model Signing statements: same DSSE framing, different predicate.
    key = generate_keypair()
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "model.safetensors", "digest": {"sha256": "ab" * 32}}],
        "predicateType": "https://model_signing/signature/v1.0",
        "predicate": {},
    }
    envelope = intoto.sign_statement(statement, key)
    assert intoto.verify_envelope(envelope, key.public_key) == statement
    # …but the receipt-specific verifier rejects the foreign predicate type.
    assert intoto.verify_receipt_attestation(envelope, key.public_key) is None
