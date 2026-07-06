"""Receipt bundles as DSSE-signed in-toto attestations.

Wraps a receipt bundle in an in-toto **Statement** (v1) with the published
predicate type ``https://agentauth.dev/receipt/v1`` and signs it in a **DSSE**
envelope (v1, PAE encoding, Ed25519). The subject digest is the SHA-256 of the
bundle's canonical JSON (``agentauth.core.hash_util`` — THE byte convention),
so any relying party can re-derive it from the raw bundle.

Because predicate types are self-defined by design, stock supply-chain tooling
verifies these attestations without AgentAuth code:

- ``cosign attest-blob --predicate receipt.json --key ed25519.key
  --type https://agentauth.dev/receipt/v1 bundle.json``
- ``cosign verify-blob-attestation --key ed25519.pub --signature receipt.att
  --type https://agentauth.dev/receipt/v1 bundle.json``
- ``gh attestation verify --predicate-type https://agentauth.dev/receipt/v1 …``

and Rekor anchoring rides the same tooling (``cosign attest-blob`` with
``--rekor-url``, or ``rekor-cli upload``) — we deliberately do not hand-roll a
Rekor client. See ``docs/audit_interop.md``.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from agentauth.core.hash_util import canonical_json_bytes
from agentauth.core.signing import SigningKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://agentauth.dev/receipt/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def bundle_subject_digest(bundle: dict[str, Any]) -> str:
    """SHA-256 hex of the bundle's canonical JSON — the attestation subject."""
    return hashlib.sha256(canonical_json_bytes(bundle)).hexdigest()


def receipt_statement(
    bundle: dict[str, Any],
    *,
    subject_name: str | None = None,
    predicate_type: str = PREDICATE_TYPE,
) -> dict[str, Any]:
    """The receipt as an in-toto Statement: subject = bundle digest, predicate = bundle."""
    name = subject_name or str(
        (bundle.get("execution_proof") or {}).get("proof_id") or "agent-receipt"
    )
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": bundle_subject_digest(bundle)}}],
        "predicateType": predicate_type,
        "predicate": bundle,
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding: ``PAE(type, body)`` per DSSE v1."""
    return b" ".join(
        [
            b"DSSEv1",
            str(len(payload_type)).encode("ascii"),
            payload_type.encode("utf-8"),
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


def sign_statement(statement: dict[str, Any], signing_key: SigningKey) -> dict[str, Any]:
    """Sign an in-toto Statement into a DSSE envelope (Ed25519 over the PAE)."""
    payload = json.dumps(statement, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = signing_key.private_key.sign(pae(PAYLOAD_TYPE, payload))
    return {
        "payload": base64.standard_b64encode(payload).decode("ascii"),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [
            {
                "keyid": signing_key.key_id,
                "sig": base64.standard_b64encode(signature).decode("ascii"),
            }
        ],
    }


def attest_receipt_bundle(
    bundle: dict[str, Any],
    signing_key: SigningKey,
    *,
    subject_name: str | None = None,
) -> dict[str, Any]:
    """Convenience: Statement + DSSE in one call."""
    return sign_statement(receipt_statement(bundle, subject_name=subject_name), signing_key)


def verify_envelope(
    envelope: dict[str, Any],
    public_key: Ed25519PublicKey,
) -> dict[str, Any] | None:
    """Verify a DSSE envelope signature; return the decoded Statement, or None.

    Accepts any DSSE-over-in-toto envelope signed with the given Ed25519 key —
    including OpenSSF Model Signing-style statements — so callers can use it to
    check external attestations as evidence, not just our receipts.
    """
    try:
        payload = base64.standard_b64decode(envelope["payload"])
        payload_type = envelope["payloadType"]
        message = pae(payload_type, payload)
        for entry in envelope.get("signatures", []):
            signature = base64.standard_b64decode(entry["sig"])
            try:
                public_key.verify(signature, message)
            except InvalidSignature:
                continue
            return json.loads(payload)
    except (KeyError, TypeError, ValueError):
        return None
    return None


def verify_receipt_attestation(
    envelope: dict[str, Any],
    public_key: Ed25519PublicKey,
    *,
    bundle: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Verify a receipt attestation end to end; return the Statement, or None.

    Checks the DSSE signature, the Statement/predicate types, and — when the
    raw ``bundle`` is supplied — that the subject digest matches its canonical
    JSON (the ``--check-claims`` equivalent).
    """
    statement = verify_envelope(envelope, public_key)
    if statement is None:
        return None
    if statement.get("_type") != STATEMENT_TYPE:
        return None
    if statement.get("predicateType") != PREDICATE_TYPE:
        return None
    if bundle is not None:
        subjects = statement.get("subject") or []
        expected = bundle_subject_digest(bundle)
        if not any(
            (subject.get("digest") or {}).get("sha256") == expected for subject in subjects
        ):
            return None
    return statement
