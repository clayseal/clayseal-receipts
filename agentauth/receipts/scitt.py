"""SCITT-aligned receipts: COSE Signed Statements + COSE Receipts (SOTA-11).

Re-expresses our receipts in the IETF SCITT model
(`draft-ietf-scitt-architecture`): a **Signed Statement** is a COSE_Sign1 over a
claim; a **Transparency Service** registers it and returns a **Receipt** — a
COSE_Sign1 carrying an RFC 9162 Merkle **inclusion proof**
(`draft-ietf-cose-merkle-tree-proofs`). A statement plus its receipt is a
**Transparent Statement**: verifiable by any SCITT-aware relying party without our
JSON verifier.

Built on the standards-correct RFC 6962 Merkle hashing in :mod:`agentauth.receipts.c2sp`.
COSE_Sign1 framing matches :mod:`agentauth.receipts.tee_nitro` (untagged 4-element array,
``Sig_structure = ["Signature1", protected, external_aad, payload]``).

Header label values track the current drafts and are named constants below; pin
them to the final IANA assignments when the drafts publish. Internal round-trip
(register → verify) is tested; live interop with a third-party SCITT verifier is
not yet asserted.
"""

from __future__ import annotations

from typing import Any

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from agentauth.receipts import c2sp
from agentauth.core.signing import SigningKey

# COSE header labels / values (RFC 9052 + the two drafts).
_ALG = 1
_CONTENT_TYPE = 3
_ALG_EDDSA = -8
# draft-ietf-cose-merkle-tree-proofs: verifiable data structure + proofs.
_VDS = 395  # protected: verifiable-data-structure
_VDS_PROOFS = 396  # unprotected: verifiable-data-structure-proofs
_VDS_RFC9162_SHA256 = 1
_PROOF_TYPE_INCLUSION = -1
_PROOF_TYPE_CONSISTENCY = -2
# draft-ietf-scitt-architecture: receipt header in the statement's unprotected map.
_SCITT_RECEIPT = 394
# CWT claims (RFC 8392) carried in the statement's protected header (issuer/subject).
_CWT_CLAIMS = 15
_CWT_ISS = 1
_CWT_SUB = 2


def _sign_cose(
    protected: dict[int, Any],
    payload: bytes | None,
    private_key: Ed25519PrivateKey,
    *,
    unprotected: dict[int, Any] | None = None,
    detached_payload: bytes | None = None,
) -> bytes:
    """Build an (untagged) COSE_Sign1 with EdDSA. ``detached_payload`` signs over a
    value not carried in the envelope (used by Receipts to sign the Merkle root)."""
    protected = {_ALG: _ALG_EDDSA, **protected}
    protected_bytes = cbor2.dumps(protected)
    to_sign = payload if detached_payload is None else detached_payload
    sig_structure = ["Signature1", protected_bytes, b"", to_sign]
    signature = private_key.sign(cbor2.dumps(sig_structure))
    return cbor2.dumps([protected_bytes, unprotected or {}, payload, signature])


def _verify_cose(
    envelope: bytes,
    public_key: Ed25519PublicKey,
    *,
    detached_payload: bytes | None = None,
) -> tuple[dict, dict, bytes | None] | None:
    """Verify a COSE_Sign1 signature. Returns (protected, unprotected, payload) or None."""
    try:
        cose = cbor2.loads(envelope)
        protected_bytes, unprotected, payload, signature = cose
        to_sign = payload if detached_payload is None else detached_payload
        sig_structure = ["Signature1", protected_bytes, b"", to_sign]
        public_key.verify(signature, cbor2.dumps(sig_structure))
    except (InvalidSignature, ValueError, cbor2.CBORError, TypeError):
        return None
    return cbor2.loads(protected_bytes), unprotected, payload


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
    """Wrap a claim as a SCITT Signed Statement (COSE_Sign1, EdDSA)."""
    protected = {
        _CONTENT_TYPE: content_type,
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


# --------------------------------------------------------------------------- #
# Transparency Service + COSE Receipts
# --------------------------------------------------------------------------- #
def _inclusion_proof_cbor(tree_size: int, leaf_index: int, path: list[bytes]) -> bytes:
    """RFC 9162 inclusion proof, CBOR-encoded per draft-ietf-cose-merkle-tree-proofs."""
    return cbor2.dumps([tree_size, leaf_index, path])


def issue_inclusion_receipt(
    entries: list[bytes], index: int, signing_key: SigningKey, *, service_id: str
) -> bytes:
    """Build a COSE Receipt proving ``entries[index]`` is included under the RFC 6962 root.

    ``entries`` are the raw leaf entries of the verifiable data structure (a SCITT Signed
    Statement's bytes, or — when the audit log is the Transparency Service — a record hash).
    The receipt is signed over the Merkle root (detached payload).
    """
    path = c2sp.rfc6962_inclusion_path(index, entries)
    proofs = {_PROOF_TYPE_INCLUSION: [_inclusion_proof_cbor(len(entries), index, path)]}
    protected = {_VDS: _VDS_RFC9162_SHA256, _CWT_CLAIMS: {_CWT_ISS: service_id}}
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
    protected = {_VDS: _VDS_RFC9162_SHA256, _CWT_CLAIMS: {_CWT_ISS: service_id}}
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
        _protected, unprotected, _payload, _sig = cbor2.loads(receipt)
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
        return issue_inclusion_receipt(
            self._entries, index, self.signing_key, service_id=self.service_id
        )

    def consistency_receipt(self, old_size: int) -> bytes:
        """COSE Receipt proving append-only growth from ``old_size`` to the current size."""
        return issue_consistency_receipt(
            self._entries, old_size, self.signing_key, service_id=self.service_id
        )


def transparent_statement(signed_statement: bytes, receipt: bytes) -> bytes:
    """Embed a receipt into a statement's unprotected header → a Transparent Statement."""
    protected_bytes, unprotected, payload, signature = cbor2.loads(signed_statement)
    unprotected = dict(unprotected)
    unprotected[_SCITT_RECEIPT] = receipt
    return cbor2.dumps([protected_bytes, unprotected, payload, signature])


def verify_receipt(
    signed_statement: bytes, receipt: bytes, service_public_key: Ed25519PublicKey
) -> bool:
    """Verify a COSE Receipt: the statement is included under a root the service signed.

    Reconstructs the RFC 6962 root from the receipt's inclusion proof and the
    statement's leaf hash, then checks the service's COSE_Sign1 signature over it.
    """
    try:
        _protected, unprotected, _payload, _sig = cbor2.loads(receipt)
        proofs = unprotected[_VDS_PROOFS][_PROOF_TYPE_INCLUSION]
        tree_size, leaf_index, path = cbor2.loads(proofs[0])
    except (ValueError, KeyError, IndexError, cbor2.CBORError, TypeError):
        return False

    leaf = c2sp.rfc6962_leaf_hash(signed_statement)
    root = c2sp.rfc6962_root_from_path(leaf, leaf_index, tree_size, path)
    if root is None:
        return False
    return _verify_cose(receipt, service_public_key, detached_payload=root) is not None
