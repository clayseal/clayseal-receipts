"""SCITT-aligned receipts: COSE Signed Statements + COSE Receipts (SOTA-11)."""

from __future__ import annotations

import pytest

cbor2 = pytest.importorskip("cbor2")

from agentauth.receipts import scitt  # noqa: E402
from agentauth.core.signing import generate_keypair  # noqa: E402


def _statement(issuer="issuer.example", subject="agent-42", payload=b"hello"):
    key = generate_keypair()
    return key, scitt.sign_statement(payload, key, issuer=issuer, subject=subject)


# --- Signed Statements ----------------------------------------------------- #


def test_sign_statement_is_cose_sign1_eddsa():
    key, stmt = _statement(payload=b"claim")
    arr = cbor2.loads(stmt)
    assert isinstance(arr, list) and len(arr) == 4
    protected = cbor2.loads(arr[0])
    assert protected[1] == -8  # alg: EdDSA


def test_statement_roundtrip_and_tamper():
    key, stmt = _statement(payload=b"claim")
    assert scitt.verify_statement(stmt, key.public_key) == b"claim"
    # wrong key
    assert scitt.verify_statement(stmt, generate_keypair().public_key) is None
    # tampered payload (re-pack a different payload, same signature) fails
    p, u, _payload, sig = cbor2.loads(stmt)
    forged = cbor2.dumps([p, u, b"evil", sig])
    assert scitt.verify_statement(forged, key.public_key) is None


def test_sign_receipt_bundle_payload_is_cbor():
    key = generate_keypair()
    bundle = {"schema": "v2", "output_hash": "abc", "decision": {"outcome": "allow"}}
    stmt = scitt.sign_receipt_bundle(bundle, key, issuer="i", subject="s")
    payload = scitt.verify_statement(stmt, key.public_key)
    assert cbor2.loads(payload) == bundle


# --- Transparency Service + COSE Receipts ---------------------------------- #


def test_register_and_verify_receipt():
    ts_key = generate_keypair()
    ts = scitt.TransparencyService(ts_key, service_id="ts.example/log")
    _, stmt = _statement(payload=b"s0")
    receipt = ts.register(stmt)
    assert scitt.verify_receipt(stmt, receipt, ts.public_key)
    # wrong service key
    assert not scitt.verify_receipt(stmt, receipt, generate_keypair().public_key)
    # a different statement does not match this receipt
    _, other = _statement(payload=b"other")
    assert not scitt.verify_receipt(other, receipt, ts.public_key)


def test_receipts_stay_valid_as_log_grows():
    ts = scitt.TransparencyService(generate_keypair(), service_id="ts.example/log")
    statements, receipts = [], []
    for i in range(6):
        _, stmt = _statement(payload=f"s{i}".encode())
        statements.append(stmt)
        receipts.append(ts.register(stmt))
    # Every receipt still verifies (each commits to the root at its issuance size).
    for stmt, receipt in zip(statements, receipts):
        assert scitt.verify_receipt(stmt, receipt, ts.public_key)
    # Cross-pairing fails (receipt[0] is not a proof for statement[3]).
    assert not scitt.verify_receipt(statements[3], receipts[0], ts.public_key)


def test_tampered_inclusion_proof_rejected():
    ts = scitt.TransparencyService(generate_keypair(), service_id="ts.example/log")
    _, stmt = _statement(payload=b"s0")
    ts.register(stmt)
    _, stmt2 = _statement(payload=b"s1")
    receipt = ts.register(stmt2)
    # Corrupt the inclusion-proof leaf index in the receipt's unprotected header.
    p, u, payload, sig = cbor2.loads(receipt)
    u = dict(u)
    proofs = u[396][-1]
    ts_size, leaf_index, path = cbor2.loads(proofs[0])
    u[396] = {-1: [cbor2.dumps([ts_size, leaf_index + 5, path])]}
    bad = cbor2.dumps([p, u, payload, sig])
    assert not scitt.verify_receipt(stmt2, bad, ts.public_key)


def test_transparent_statement_embeds_receipt():
    ts = scitt.TransparencyService(generate_keypair(), service_id="ts.example/log")
    _, stmt = _statement(payload=b"s0")
    receipt = ts.register(stmt)
    transparent = scitt.transparent_statement(stmt, receipt)
    # Receipt is recoverable from the statement's unprotected header (label 394).
    _p, unprotected, _payload, _sig = cbor2.loads(transparent)
    assert unprotected[394] == receipt
    assert scitt.verify_receipt(stmt, unprotected[394], ts.public_key)


# --- consistency receipts -------------------------------------------------- #


def test_consistency_receipt_accepts_append_only_growth():
    ts = scitt.TransparencyService(generate_keypair(), service_id="ts.example/log")
    for i in range(3):
        ts.register(_statement(payload=f"s{i}".encode())[1])
    old_root = ts.root()
    for i in range(3, 7):
        ts.register(_statement(payload=f"s{i}".encode())[1])
    receipt = ts.consistency_receipt(3)
    assert scitt.verify_consistency_receipt(receipt, old_root, ts.public_key)
    # A wrong "old root" (e.g. a rewritten history) must not validate.
    assert not scitt.verify_consistency_receipt(receipt, b"\x11" * 32, ts.public_key)
    # Wrong service key fails too.
    assert not scitt.verify_consistency_receipt(receipt, old_root, generate_keypair().public_key)


# --- AuditChain as the Transparency Service -------------------------------- #


def _chain(n):
    import uuid
    from datetime import datetime, timezone

    from agentauth.receipts.audit import AuditChain
    from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof

    chain = AuditChain.in_memory(signing_key=generate_keypair())
    for i in range(n):
        chain.append(
            ExecutionProof(
                proof_id=uuid.uuid4(),
                agent_id=uuid.uuid4(),
                certificate_ref="c",
                policy_commitment="pc",
                context_hash="ch",
                output_hash=f"oh{i}",
                attestation_path=AttestationPath.SHADOW,
                policy_satisfied=True,
                decision_outcome=DecisionOutcome.ALLOW,
                authority_version=1,
                session_id=None,
                created_at=datetime.now(timezone.utc),
            ),
            action=f"a{i}",
        )
    return chain


def test_audit_chain_issues_verifiable_scitt_receipt():
    chain = _chain(5)
    record = chain.iter_records()[2]
    receipt = chain.scitt_receipt(record.record_hash, service_id="agent-receipts.local/log")
    entry = bytes.fromhex(record.record_hash)
    assert scitt.verify_receipt(entry, receipt, chain.signing_key.public_key)
    # A different record's entry is not proven by this receipt.
    other = bytes.fromhex(chain.iter_records()[4].record_hash)
    assert not scitt.verify_receipt(other, receipt, chain.signing_key.public_key)


def test_audit_chain_consistency_receipt():
    import agentauth.receipts.c2sp as c2sp

    chain = _chain(7)
    # The size-3 root the verifier already trusts (from an earlier checkpoint).
    entries = [bytes.fromhex(r.record_hash) for r in chain.iter_records()]
    old3 = c2sp.rfc6962_root(entries[:3])

    receipt = chain.scitt_consistency_receipt(3, service_id="agent-receipts.local/log")
    assert scitt.verify_consistency_receipt(receipt, old3, chain.signing_key.public_key)
    # A forged earlier root (rewritten history) must not validate.
    assert not scitt.verify_consistency_receipt(receipt, b"\x22" * 32, chain.signing_key.public_key)
