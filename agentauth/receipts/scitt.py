"""SCITT receipts: COSE Signed Statements + COSE Receipts (RFC 9943 / RFC 9942).

Re-expresses our receipts in the IETF SCITT model (RFC 9943): a **Signed
Statement** is a COSE_Sign1 over a claim; a **Transparency Service** registers
it and returns a **Receipt** — a COSE_Sign1 carrying an RFC 9162 Merkle
**inclusion proof** (RFC 9942, ``RFC9162_SHA256`` verifiable data structure).
A statement plus its receipt is a **Transparent Statement**: verifiable by any
SCITT-aware relying party without our JSON verifier.

Built on the standards-correct RFC 6962 Merkle hashing in
:mod:`agentauth.receipts.c2sp`. Wire conformance points (RFC 9942 Figure 1):

- Statements and Receipts are **tagged** COSE_Sign1 (``#6.18``); verification
  also accepts untagged envelopes so pre-0.5 bundles keep verifying.
- Header labels are the final IANA assignments: ``receipts`` (394, an *array*
  of ``bstr``-wrapped Receipts in the statement's unprotected header), ``vds``
  (395, value 1 = RFC9162_SHA256) and ``vdp`` (396, ``-1`` inclusion / ``-2``
  consistency proofs).
- Protected headers carry ``kid`` (label 4) and CWT Claims (label 15,
  RFC 9597) with issuer/subject, as RFC 9943 §4.2 requires.
- Receipts sign over the Merkle root as a *detached* payload (``payload: nil``),
  forcing verifiers to reconstruct the root from the proof.

The HTTP face of this module (publish to / serve as a Transparency Service) is
:mod:`agentauth.receipts.scrapi`.
"""

from __future__ import annotations

from typing import Any

import cbor2
from agentauth.core.signing import SigningKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agentauth.receipts import c2sp

# COSE header labels / values (RFC 9052, RFC 9942, RFC 9597).
_ALG = 1
_CONTENT_TYPE = 3
_KID = 4
_ALG_EDDSA = -8
_TAG_COSE_SIGN1 = 18
# RFC 9942: verifiable data structure + proofs.
_VDS = 395  # protected: "vds"
_VDS_PROOFS = 396  # unprotected: "vdp"
_VDS_RFC9162_SHA256 = 1
_PROOF_TYPE_INCLUSION = -1
_PROOF_TYPE_CONSISTENCY = -2
# RFC 9942: "receipts" header in the statement's unprotected map — an array of
# bstr-wrapped Receipts.
_SCITT_RECEIPTS = 394
# CWT claims (RFC 8392 via RFC 9597) carried in the protected header.
_CWT_CLAIMS = 15
_CWT_ISS = 1
_CWT_SUB = 2


def _decode_sign1(envelope: bytes | Any) -> list:
    """Decode a COSE_Sign1 envelope, accepting tagged (#6.18) and untagged forms."""
    value = cbor2.loads(envelope) if isinstance(envelope, (bytes, bytearray)) else envelope
    if isinstance(value, cbor2.CBORTag):
        if value.tag != _TAG_COSE_SIGN1:
            raise ValueError(f"expected COSE_Sign1 tag 18, got {value.tag}")
        value = value.value
    # cbor2 decodes tagged arrays as tuples (and maps as frozendicts).
    if not isinstance(value, (list, tuple)) or len(value) != 4:
        raise ValueError("COSE_Sign1 must be a 4-element array")
    return list(value)


def _sign_cose(
    protected: dict[int, Any],
    payload: bytes | None,
    private_key: Ed25519PrivateKey,
    *,
    unprotected: dict[int, Any] | None = None,
    detached_payload: bytes | None = None,
) -> bytes:
    """Build a tagged COSE_Sign1 with EdDSA. ``detached_payload`` signs over a
    value not carried in the envelope (used by Receipts to sign the Merkle root)."""
    protected = {_ALG: _ALG_EDDSA, **protected}
    protected_bytes = cbor2.dumps(protected)
    to_sign = payload if detached_payload is None else detached_payload
    sig_structure = ["Signature1", protected_bytes, b"", to_sign]
    signature = private_key.sign(cbor2.dumps(sig_structure))
    return cbor2.dumps(
        cbor2.CBORTag(_TAG_COSE_SIGN1, [protected_bytes, unprotected or {}, payload, signature])
    )


def _verify_cose(
    envelope: bytes,
    public_key: Ed25519PublicKey,
    *,
    detached_payload: bytes | None = None,
) -> tuple[dict, dict, bytes | None] | None:
    """Verify a COSE_Sign1 signature. Returns (protected, unprotected, payload) or None."""
    try:
        protected_bytes, unprotected, payload, signature = _decode_sign1(envelope)
        to_sign = payload if detached_payload is None else detached_payload
        sig_structure = ["Signature1", protected_bytes, b"", to_sign]
        public_key.verify(signature, cbor2.dumps(sig_structure))
    except (InvalidSignature, ValueError, cbor2.CBORError, TypeError):
        return None
    return cbor2.loads(protected_bytes), unprotected, payload


def _kid_bytes(signing_key: SigningKey) -> bytes:
    return signing_key.key_id.encode("ascii")


# --------------------------------------------------------------------------- #
# Signed Statements
# --------------------------------------------------------------------------- #
def sign_statement(
    payload: bytes,
    signing_key: SigningKey,
    *,
    issuer: str,
    subject: str,
    content_type: str = "application/agent-receipt+cbor",
) -> bytes:
    """Wrap a claim as a SCITT Signed Statement (tagged COSE_Sign1, EdDSA)."""
    protected = {
        _CONTENT_TYPE: content_type,
        _KID: _kid_bytes(signing_key),
        _CWT_CLAIMS: {_CWT_ISS: issuer, _CWT_SUB: subject},
    }
    return _sign_cose(protected, payload, signing_key.private_key)


def sign_receipt_bundle(bundle: dict[str, Any], signing_key: SigningKey, **kw: Any) -> bytes:
    """Convenience: canonical-CBOR-encode a receipt bundle and sign it as a statement."""
    payload = cbor2.dumps(bundle, canonical=True)
    return sign_statement(payload, signing_key, **kw)


def verify_statement(
    signed_statement: bytes, public_key: Ed25519PublicKey
) -> bytes | None:
    """Verify a Signed Statement's signature; return its payload, or None."""
    result = _verify_cose(signed_statement, public_key)
    return result[2] if result is not None else None


def statement_claims(signed_statement: bytes) -> dict[str, Any]:
    """Decode (without verifying) a statement's protected-header metadata.

    Returns ``{"issuer", "subject", "kid", "content_type", "alg"}`` with ``None``
    for absent fields. Raises ``ValueError`` on structurally invalid envelopes —
    the syntactic registration check of RFC 9943 §5.2.
    """
    protected_bytes, _unprotected, _payload, _signature = _decode_sign1(signed_statement)
    protected = cbor2.loads(protected_bytes)
    if not isinstance(protected, dict):
        raise ValueError("COSE_Sign1 protected header must be a map")
    cwt = protected.get(_CWT_CLAIMS) or {}
    kid = protected.get(_KID)
    return {
        "issuer": cwt.get(_CWT_ISS) if isinstance(cwt, dict) else None,
        "subject": cwt.get(_CWT_SUB) if isinstance(cwt, dict) else None,
        "kid": kid.decode("ascii", "replace") if isinstance(kid, bytes) else kid,
        "content_type": protected.get(_CONTENT_TYPE),
        "alg": protected.get(_ALG),
    }


# --------------------------------------------------------------------------- #
# Transparency Service + COSE Receipts
# --------------------------------------------------------------------------- #
def _inclusion_proof_cbor(tree_size: int, leaf_index: int, path: list[bytes]) -> bytes:
    """RFC 9162 inclusion proof, CBOR-encoded per RFC 9942 §5.2."""
    return cbor2.dumps([tree_size, leaf_index, path])


def issue_inclusion_receipt(
    entries: list[bytes], index: int, signing_key: SigningKey, *, service_id: str
) -> bytes:
    """Build a COSE Receipt proving ``entries[index]`` is included under the RFC 6962 root.

    ``entries`` are the raw leaf entries of the verifiable data structure (a SCITT Signed
    Statement's bytes, or — when the audit log is the Transparency Service — a record hash).
    The receipt is signed over the Merkle root (detached payload, RFC 9942 §4.4).
    """
    path = c2sp.rfc6962_inclusion_path(index, entries)
    proofs = {_PROOF_TYPE_INCLUSION: [_inclusion_proof_cbor(len(entries), index, path)]}
    protected = {
        _VDS: _VDS_RFC9162_SHA256,
        _KID: _kid_bytes(signing_key),
        _CWT_CLAIMS: {_CWT_ISS: service_id},
    }
    return _sign_cose(
        protected,
        None,
        signing_key.private_key,
        unprotected={_VDS_PROOFS: proofs},
        detached_payload=c2sp.rfc6962_root(entries),
    )


def issue_consistency_receipt(
    entries: list[bytes], old_size: int, signing_key: SigningKey, *, service_id: str
) -> bytes:
    """COSE Receipt proving the log is an append-only extension from ``old_size`` to now.

    Signed over the new RFC 6962 root, carrying an RFC 9162 consistency proof. Verify
    with :func:`verify_consistency_receipt` against the (trusted) earlier root.
    """
    new_size = len(entries)
    path = c2sp.rfc6962_consistency_path(old_size, entries)
    proof_cbor = cbor2.dumps([old_size, new_size, path])
    proofs = {_PROOF_TYPE_CONSISTENCY: [proof_cbor]}
    protected = {
        _VDS: _VDS_RFC9162_SHA256,
        _KID: _kid_bytes(signing_key),
        _CWT_CLAIMS: {_CWT_ISS: service_id},
    }
    return _sign_cose(
        protected,
        None,
        signing_key.private_key,
        unprotected={_VDS_PROOFS: proofs},
        detached_payload=c2sp.rfc6962_root(entries),
    )


def verify_consistency_receipt(
    receipt: bytes, old_root: bytes, service_public_key: Ed25519PublicKey
) -> bool:
    """Verify a consistency receipt is append-only from a trusted ``old_root``.

    Reconstructs the new root from the proof + ``old_root`` and checks the service's
    COSE_Sign1 signature over it. Rejects any history rewrite (the old root won't
    reconstruct).
    """
    try:
        _protected, unprotected, _payload, _sig = _decode_sign1(receipt)
        proofs = unprotected[_VDS_PROOFS][_PROOF_TYPE_CONSISTENCY]
        old_size, new_size, path = cbor2.loads(proofs[0])
    except (ValueError, KeyError, IndexError, cbor2.CBORError, TypeError):
        return False
    roots = c2sp.rfc6962_consistency_roots(old_size, new_size, path, old_root)
    if roots is None or roots[0] != old_root:
        return False
    return _verify_cose(receipt, service_public_key, detached_payload=roots[1]) is not None


class TransparencyService:
    """A minimal SCITT Transparency Service over an RFC 6962 Merkle log.

    Registers Signed Statements (their bytes are the log leaves) and issues COSE
    Receipts proving inclusion under the service's signed Merkle root.
    """

    def __init__(self, signing_key: SigningKey, *, service_id: str) -> None:
        self.signing_key = signing_key
        self.service_id = service_id
        self._entries: list[bytes] = []

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.signing_key.public_key

    @property
    def tree_size(self) -> int:
        return len(self._entries)

    def root(self) -> bytes:
        return c2sp.rfc6962_root(self._entries)

    def register(self, signed_statement: bytes) -> bytes:
        """Append a statement and return its COSE Receipt (a Transparent-Statement proof)."""
        index = len(self._entries)
        self._entries.append(signed_statement)
        return self.receipt_for(index)

    def receipt_for(self, index: int) -> bytes:
        """A fresh COSE Receipt for ``entries[index]`` under the *current* signed root."""
        if not 0 <= index < len(self._entries):
            raise IndexError(f"no entry at index {index}")
        return issue_inclusion_receipt(
            self._entries, index, self.signing_key, service_id=self.service_id
        )

    def consistency_receipt(self, old_size: int) -> bytes:
        """COSE Receipt proving append-only growth from ``old_size`` to the current size."""
        return issue_consistency_receipt(
            self._entries, old_size, self.signing_key, service_id=self.service_id
        )


def transparent_statement(signed_statement: bytes, receipt: bytes) -> bytes:
    """Append a receipt to a statement's ``receipts`` (394) header → a Transparent Statement.

    Per RFC 9942 the header value is an array of ``bstr``-wrapped Receipts;
    calling this again with another receipt appends to the array.
    """
    protected_bytes, unprotected, payload, signature = _decode_sign1(signed_statement)
    unprotected = dict(unprotected)
    existing = unprotected.get(_SCITT_RECEIPTS)
    receipts = list(existing) if isinstance(existing, (list, tuple)) else []
    receipts.append(receipt)
    unprotected[_SCITT_RECEIPTS] = receipts
    return cbor2.dumps(
        cbor2.CBORTag(_TAG_COSE_SIGN1, [protected_bytes, unprotected, payload, signature])
    )


def receipts_from_transparent_statement(statement: bytes) -> list[bytes]:
    """Extract the embedded COSE Receipts from a Transparent Statement.

    Tolerates the pre-0.5 layout where label 394 held a single raw receipt
    instead of the RFC 9942 array.
    """
    _protected, unprotected, _payload, _signature = _decode_sign1(statement)
    value = unprotected.get(_SCITT_RECEIPTS)
    if value is None:
        return []
    if isinstance(value, (bytes, bytearray)):
        return [bytes(value)]
    if isinstance(value, (list, tuple)):
        return [bytes(item) for item in value]
    raise ValueError("receipts header (394) must be an array of bstr")


def verify_receipt(
    signed_statement: bytes, receipt: bytes, service_public_key: Ed25519PublicKey
) -> bool:
    """Verify a COSE Receipt: the statement is included under a root the service signed.

    Reconstructs the RFC 6962 root from the receipt's inclusion proof and the
    statement's leaf hash, then checks the service's COSE_Sign1 signature over it.
    """
    try:
        _protected, unprotected, _payload, _sig = _decode_sign1(receipt)
        proofs = unprotected[_VDS_PROOFS][_PROOF_TYPE_INCLUSION]
        tree_size, leaf_index, path = cbor2.loads(proofs[0])
    except (ValueError, KeyError, IndexError, cbor2.CBORError, TypeError):
        return False

    leaf = c2sp.rfc6962_leaf_hash(signed_statement)
    root = c2sp.rfc6962_root_from_path(leaf, leaf_index, tree_size, path)
    if root is None:
        return False
    return _verify_cose(receipt, service_public_key, detached_payload=root) is not None


def verify_transparent_statement(
    statement: bytes, service_public_key: Ed25519PublicKey
) -> bool:
    """Verify at least one embedded receipt proves this statement's inclusion.

    The leaf the service committed to is the statement *without* its unprotected
    ``receipts`` header (receipts are attached after registration).
    """
    try:
        protected_bytes, unprotected, payload, signature = _decode_sign1(statement)
    except (ValueError, cbor2.CBORError):
        return False
    unprotected = dict(unprotected)
    unprotected.pop(_SCITT_RECEIPTS, None)
    bare = cbor2.dumps(
        cbor2.CBORTag(_TAG_COSE_SIGN1, [protected_bytes, unprotected, payload, signature])
    )
    receipts = receipts_from_transparent_statement(statement)
    return any(verify_receipt(bare, receipt, service_public_key) for receipt in receipts)
