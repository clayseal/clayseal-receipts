"""WIMSE WIT/WPT + Transaction-Tokens-for-Agents envelopes (SOTA-15).

Re-expresses our signed mandate / key-bound authority as IETF WIMSE Workload Identity
Tokens (WIT) and Workload Proof Tokens (WPT), plus an OAuth transaction-token-style
``act`` chain for delegation lineage.

See ``docs/wimse_mapping.md`` and the WIMSE / txn-token-for-agents drafts.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.mandate import Mandate, verify_mandate_envelope
from agentauth.core.signing import SigningKey

WIT_TYP = "application/wimse-workload-identity-token"
WPT_TYP = "application/wimse-workload-proof-token"
TXN_TOKEN_TYP = "application/oauth-txn-token"


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def owner_hpke_pk_b64url(public_key_raw: bytes) -> str:
    """Encode an X25519 public key for mandate / WIT ``owner_hpke_pk`` claims."""
    return b64url_encode(public_key_raw)


def mandate_to_wit_claims(
    mandate: Mandate,
    *,
    jti: str | None = None,
    cnf_jkt: str | None = None,
) -> dict[str, Any]:
    """Map a :class:`Mandate` to WIT-shaped JWT claims."""
    subject = mandate.delegate or mandate.grant_id
    claims: dict[str, Any] = {
        "iss": mandate.issuer,
        "sub": subject,
        "iat": int(mandate.issued_at.timestamp()),
        "exp": int(mandate.expires_at.timestamp()),
        "jti": jti or mandate.grant_id,
        "agent_receipts": {
            "grant_id": mandate.grant_id,
            "commitment": mandate.commitment(),
        },
    }
    if mandate.delegate:
        claims["agent_receipts"]["delegate"] = mandate.delegate
    if mandate.owner_hpke_pk:
        claims["owner_hpke_pk"] = mandate.owner_hpke_pk
    if mandate.allowed_actions:
        claims["scope"] = " ".join(mandate.allowed_actions)
    if cnf_jkt:
        claims["cnf"] = {"jkt": cnf_jkt}
    return claims


def issue_wit_from_mandate(
    envelope: dict[str, Any],
    key: SigningKey,
    *,
    jti: str | None = None,
    cnf_jkt: str | None = None,
) -> dict[str, Any]:
    """Issue a WIT JWT from a verified signed mandate envelope."""
    violations = verify_mandate_envelope(envelope)
    if violations:
        raise ValueError(f"mandate invalid: {violations[0]}")
    mandate = Mandate.from_dict(envelope["document"])
    claims = mandate_to_wit_claims(mandate, jti=jti, cnf_jkt=cnf_jkt)
    token = jwt.encode(
        claims,
        key.private_key,
        algorithm="EdDSA",
        headers={"typ": WIT_TYP},
    )
    return {"token": token, "claims": claims, "typ": WIT_TYP}


def verify_wit(
    token: str,
    issuer_public_key: Ed25519PublicKey | bytes,
    *,
    audience: str | None = None,
) -> dict[str, Any]:
    """Verify a WIT and return decoded claims."""
    if isinstance(issuer_public_key, bytes):
        issuer_public_key = Ed25519PublicKey.from_public_bytes(issuer_public_key)
    options = {"require": ["exp", "iat", "sub", "iss"]}
    return jwt.decode(
        token,
        issuer_public_key,
        algorithms=["EdDSA"],
        audience=audience,
        options=options,
    )


def build_wpt(
    *,
    wit_token: str,
    aud: str,
    htm: str,
    htu: str,
    key: SigningKey,
    jti: str | None = None,
    cnf_jkt: str | None = None,
) -> dict[str, Any]:
    """Build a request-bound Workload Proof Token (WPT) JWT."""
    now = int(datetime.now(timezone.utc).timestamp())
    claims: dict[str, Any] = {
        "iss": key.public_key_hex,
        "sub": key.public_key_hex,
        "aud": aud,
        "iat": now,
        "exp": now + 300,
        "jti": jti or str(uuid4()),
        "htm": htm.upper(),
        "htu": htu,
        "wit": wit_token,
    }
    if cnf_jkt:
        claims["cnf"] = {"jkt": cnf_jkt}
    token = jwt.encode(
        claims,
        key.private_key,
        algorithm="EdDSA",
        headers={"typ": WPT_TYP},
    )
    return {"token": token, "claims": claims, "typ": WPT_TYP}


def verify_wpt(
    token: str,
    workload_public_key: Ed25519PublicKey | bytes,
    *,
    aud: str | None = None,
) -> dict[str, Any]:
    if isinstance(workload_public_key, bytes):
        workload_public_key = Ed25519PublicKey.from_public_bytes(workload_public_key)
    return jwt.decode(
        token,
        workload_public_key,
        algorithms=["EdDSA"],
        audience=aud,
        options={"require": ["exp", "iat", "sub", "htm", "htu"]},
    )


def transaction_token_act_chain(
    mandate: Mandate,
    *,
    parent_act: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """OAuth transaction-token-style ``act`` chain for delegation lineage."""
    actor: dict[str, Any] = {
        "sub": mandate.delegate or mandate.grant_id,
        "grant_id": mandate.grant_id,
    }
    if mandate.allowed_actions:
        actor["roles"] = list(mandate.allowed_actions)
    act = list(parent_act or [])
    act.append(actor)
    return {
        "typ": TXN_TOKEN_TYP,
        "grant_id": mandate.grant_id,
        "act": act,
        "commitment": mandate.commitment(),
    }


def mandate_ref_from_envelope(envelope: dict[str, Any]) -> str:
    """SHA-256 commitment used as ``mandate_ref`` / ``token_ref`` log index (SOTA-16d)."""
    document = envelope.get("document")
    if not isinstance(document, dict):
        raise ValueError("mandate envelope missing document")
    return hash_canonical_json(document)
