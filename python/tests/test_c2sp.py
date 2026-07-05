"""C2SP checkpoint format: RFC 6962 Merkle root + signed-note serialization."""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone

from agentauth.receipts import c2sp
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.proof import AttestationPath, DecisionOutcome, ExecutionProof
from agentauth.core.signing import generate_keypair


def _entries(n: int) -> list[bytes]:
    return [hashlib.sha256(f"e{i}".encode()).digest() for i in range(n)]


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


# --- RFC 6962 Merkle hashing (known-answer + structure) -------------------- #


def test_rfc6962_root_known_answers():
    # Empty tree is SHA-256 of the empty string (RFC 6962 §2.1).
    assert c2sp.rfc6962_root([]) == hashlib.sha256(b"").digest()
    # Single leaf is the leaf hash: SHA-256(0x00 || entry).
    assert c2sp.rfc6962_root([b""]) == hashlib.sha256(b"\x00").digest()
    # Two leaves: SHA-256(0x01 || leaf(a) || leaf(b)).
    a, b = b"a", b"b"
    expected = hashlib.sha256(
        b"\x01" + c2sp.rfc6962_leaf_hash(a) + c2sp.rfc6962_leaf_hash(b)
    ).digest()
    assert c2sp.rfc6962_root([a, b]) == expected


def test_rfc6962_inclusion_accepts_every_leaf():
    for n in range(1, 18):
        entries = _entries(n)
        root = c2sp.rfc6962_root(entries)
        for i in range(n):
            path = c2sp.rfc6962_inclusion_path(i, entries)
            leaf = c2sp.rfc6962_leaf_hash(entries[i])
            assert c2sp.rfc6962_verify_inclusion(leaf, i, n, path, root)


def test_rfc6962_inclusion_rejects_tamper():
    entries = _entries(11)
    root = c2sp.rfc6962_root(entries)
    path = c2sp.rfc6962_inclusion_path(4, entries)
    leaf = c2sp.rfc6962_leaf_hash(entries[4])
    assert c2sp.rfc6962_verify_inclusion(leaf, 4, 11, path, root)
    # wrong leaf
    assert not c2sp.rfc6962_verify_inclusion(
        c2sp.rfc6962_leaf_hash(b"evil"), 4, 11, path, root
    )
    # corrupted path node
    bad = list(path)
    bad[0] = hashlib.sha256(b"x").digest()
    assert not c2sp.rfc6962_verify_inclusion(leaf, 4, 11, bad, root)


# --- C2SP signed-note format ----------------------------------------------- #


def test_checkpoint_body_format():
    root = c2sp.rfc6962_root(_entries(3))
    body = c2sp.checkpoint_body("example.com/log42", 3, root)
    lines = body.split("\n")
    assert lines[0] == "example.com/log42"
    assert lines[1] == "3"
    assert lines[2] == base64.standard_b64encode(root).decode()
    assert body.endswith("\n")


def test_note_sign_verify_roundtrip():
    key = generate_keypair()
    body = c2sp.checkpoint_body("origin/x", 5, c2sp.rfc6962_root(_entries(5)))
    note = c2sp.sign_note(body, "origin/x", key.private_key)
    # blank line separates body from the signature line.
    assert "\n\n— origin/x " in note
    assert c2sp.verify_note(note, "origin/x", key.public_key)


def test_note_verify_rejects_tamper_and_wrong_key():
    key = generate_keypair()
    other = generate_keypair()
    body = c2sp.checkpoint_body("origin/x", 5, c2sp.rfc6962_root(_entries(5)))
    note = c2sp.sign_note(body, "origin/x", key.private_key)
    assert not c2sp.verify_note(note, "origin/x", other.public_key)
    # tamper the committed size in the body -> signature no longer covers it
    tampered = note.replace("\n5\n", "\n6\n", 1)
    assert not c2sp.verify_note(tampered, "origin/x", key.public_key)


def test_note_key_id_is_four_bytes():
    key = generate_keypair()
    kid = c2sp.note_key_id("origin/x", key.public_key)
    assert len(kid) == 4


# --- AuditChain integration ------------------------------------------------ #


def test_audit_chain_emits_verifiable_c2sp_checkpoint():
    key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    for i in range(6):
        chain.append(_proof(i), action=f"a{i}")

    note = chain.c2sp_checkpoint("agent-receipts.local/audit")
    assert c2sp.verify_note(note, "agent-receipts.local/audit", key.public_key)

    # The committed root matches a standards-correct RFC 6962 root, and an
    # RFC 6962 inclusion proof verifies against it.
    record = chain.iter_records()[2]
    proof = chain.rfc6962_inclusion_proof(record.record_hash)
    body_root_b64 = note.split("\n")[2]
    assert base64.standard_b64decode(body_root_b64).hex() == proof["root"]
    assert c2sp.rfc6962_verify_inclusion(
        bytes.fromhex(proof["leaf_hash"]),
        proof["leaf_index"],
        proof["tree_size"],
        [bytes.fromhex(p) for p in proof["path"]],
        bytes.fromhex(proof["root"]),
    )


def test_c2sp_checkpoint_requires_signing_key():
    chain = AuditChain.in_memory()
    chain.append(_proof(0), action="a0")
    try:
        chain.c2sp_checkpoint("origin/x")
        raised = False
    except ValueError:
        raised = True
    assert raised
