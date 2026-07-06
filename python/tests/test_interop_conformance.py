"""External interop / conformance: our SCITT receipts, C2SP checkpoints, and
tlog-tiles are accepted by an *independent* implementation that re-derives each spec
from primitives (`cryptography` + `cbor2`) and never calls our own verify code.

This closes the standing "spec-conformant but live interop not asserted" caveat: it
proves an outside party reading RFC 9162 / C2SP signed-note / tlog-tiles /
draft-ietf-scitt COSE_Sign1 accepts the exact bytes we emit. (The next rung is the Go
reference binaries; this is the in-Python, separate-code-path equivalent.)
"""

from __future__ import annotations

import base64
import hashlib
import uuid
from datetime import datetime, timezone

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

cbor2 = pytest.importorskip("cbor2")

from agentauth.receipts.audit import AuditChain  # noqa: E402
from agentauth.receipts.proof import (  # noqa: E402
    AttestationPath,
    DecisionOutcome,
    ExecutionProof,
)
from agentauth.core.signing import generate_keypair  # noqa: E402


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


def _chain(n: int):
    key = generate_keypair()
    chain = AuditChain.in_memory(signing_key=key)
    for i in range(n):
        chain.append(_proof(i), action=f"a{i}")
    return chain, key


# --- independent primitives (RFC 6962), written to spec, not imported -------- #


def _rfc6962_leaf(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def _rfc6962_root(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    # largest power of two strictly less than len
    k = 1
    while k * 2 < len(leaves):
        k *= 2
    return hashlib.sha256(
        b"\x01" + _rfc6962_root(leaves[:k]) + _rfc6962_root(leaves[k:])
    ).digest()


def _independent_note_verify(note: str, public_key: Ed25519PublicKey) -> bool:
    """C2SP signed-note: signature is Ed25519 over the body (incl. its trailing
    newline); the sig line is `— <name> base64(keyid[4] || sig[64])`."""
    idx = note.find("\n\n")
    if idx == -1:
        return False
    body = note[: idx + 1]
    sig_line = note[idx + 2 :].splitlines()[0]
    blob = base64.standard_b64decode(sig_line.split(" ")[-1])
    signature = blob[4:]
    try:
        public_key.verify(signature, body.encode())
        return True
    except InvalidSignature:
        return False


def _independent_cose_sign1_verify(stmt: bytes, public_key: Ed25519PublicKey) -> bool:
    """COSE_Sign1 (RFC 9052): verify Ed25519 over Sig_structure =
    ["Signature1", protected, external_aad, payload]. Accepts the tagged
    (#6.18) form RFC 9942 mandates as well as bare arrays."""
    decoded = cbor2.loads(stmt)
    if isinstance(decoded, cbor2.CBORTag):
        assert decoded.tag == 18
        decoded = decoded.value
    protected, _unprotected, payload, signature = decoded
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    try:
        public_key.verify(signature, sig_structure)
        return True
    except InvalidSignature:
        return False


def _entries_from_tiles(files: dict[str, bytes]) -> list[bytes]:
    """tlog-tiles entry bundles: uint16-big-endian length-prefixed leaf entries."""
    leaves: list[bytes] = []
    for path in sorted(k for k in files if k.startswith("tile/entries/")):
        blob = files[path]
        offset = 0
        while offset < len(blob):
            length = int.from_bytes(blob[offset : offset + 2], "big")
            offset += 2
            leaves.append(blob[offset : offset + length])
            offset += length
    return leaves


# --- conformance tests ------------------------------------------------------ #


def test_c2sp_checkpoint_accepted_by_independent_ed25519_verifier():
    chain, key = _chain(6)
    note = chain.c2sp_checkpoint("agent-receipts.local/audit")
    assert _independent_note_verify(note, key.public_key) is True
    # Independent verifier rejects a body tamper (size bumped 6 -> 7).
    tampered = note.replace("\n6\n", "\n7\n", 1)
    assert _independent_note_verify(tampered, key.public_key) is False


def test_tlog_tiles_root_reconstructed_by_independent_client():
    chain, _key = _chain(300)
    files = chain.static_log_tiles("agent-receipts.local/audit")
    # Independent tile client: read entry tiles, RFC 6962-hash leaves, fold the root.
    entries = _entries_from_tiles(files)
    assert len(entries) == 300
    independent_root = _rfc6962_root([_rfc6962_leaf(e) for e in entries])
    # Checkpoint root parsed straight from the signed note body (line 3 = base64 root).
    note_root_b64 = files["checkpoint"].decode().split("\n")[2]
    assert independent_root == base64.standard_b64decode(note_root_b64)


def test_scitt_signed_statement_accepted_by_independent_cose_verifier():
    from agentauth.receipts import scitt

    key = generate_keypair()
    stmt = scitt.sign_statement(b"benchmark-claim", key, issuer="issuer.example", subject="agent-9")
    assert _independent_cose_sign1_verify(stmt, key.public_key) is True
    # Re-pack a different payload under the same signature -> independent verify fails.
    protected, unprotected, _payload, signature = cbor2.loads(stmt).value
    forged = cbor2.dumps(cbor2.CBORTag(18, [protected, unprotected, b"evil", signature]))
    assert _independent_cose_sign1_verify(forged, key.public_key) is False
