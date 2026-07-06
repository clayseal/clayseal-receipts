"""Identity authenticity for receipts (L1/L2 ↔ L4 seam).

The receipt's `authority` block carries the agent's attested identity facts (SPIFFE
id, issuer, `cnf` key thumbprint, delegation). EV-RT-2 already makes those facts
*tamper-evident* (they are bound into `context_hash`). This module adds the missing
*authenticity*: it embeds the signed JWT-SVID the issuer actually minted, plus the
issuer JWKS, so a verifier can check the issuer's signature and bind the SVID's
`sub`/`iss`/`cnf.jkt` claims to the authority block. With this, swapping the SVID for
another agent's, forging identity facts, or mutating a bound authority field fails
verification.

Trust note: the issuer JWKS is embedded so the receipt verifies offline. That makes
signature verification *self-contained*; establishing *trust* still requires pinning
the issuer key to a trust anchor — the same model as bundle signatures and audit-log
keys (`AGENT_RECEIPTS_TRUSTED_IDENTITY_ISSUER_KEYS`, optional, checked when set).
"""

from __future__ import annotations

import os
from typing import Any

import jwt

from agentauth.receipts.verification import VerificationIssue, VerifyErrorCode

TRUSTED_IDENTITY_ISSUER_KEYS_ENV = "AGENT_RECEIPTS_TRUSTED_IDENTITY_ISSUER_KEYS"


def build_identity_section(
    credential: dict[str, Any], issuer_jwks: dict[str, Any]
) -> dict[str, Any]:
    """Assemble the embedded identity-evidence block from an issued credential and
    the issuer's JWKS. `credential` is `Credential.to_binding_dict()`-shaped plus the
    raw `token`."""
    return {
        "jwt_svid": credential.get("token"),
        "spiffe_id": credential.get("spiffe_id"),
        "cnf_jkt": credential.get("bound_keyhash"),
        "expires_at": credential.get("expires_at"),
        "biscuit": credential.get("biscuit"),
        "biscuit_root_public_key": credential.get("biscuit_root_public_key"),
        "issuer_jwks": issuer_jwks,
    }


def _select_jwk(token: str, jwks: dict[str, Any]) -> dict[str, Any] | None:
    keys = jwks.get("keys") or []
    if not keys:
        return None
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except Exception:
        kid = None
    if kid is not None:
        for jwk in keys:
            if jwk.get("kid") == kid:
                return jwk
    return keys[0]


# Identity issues RS256 as of v0.5 (the federation-compatible algorithm);
# EdDSA remains accepted so historical receipt bundles keep verifying.
_SVID_ALGORITHMS = ("RS256", "ES256", "EdDSA")


def _decode_svid(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    jwk = _select_jwk(token, jwks)
    if jwk is None:
        raise ValueError("no issuer key in JWKS")
    key = jwt.PyJWK.from_dict(jwk).key
    # Signature is the property under test; exp/aud are bound/handled separately so a
    # historical receipt is still checkable.
    return jwt.decode(
        token,
        key=key,
        algorithms=list(_SVID_ALGORITHMS),
        options={"verify_aud": False, "verify_exp": False},
    )


def _trusted_issuer_jwks() -> list[str]:
    raw = os.getenv(TRUSTED_IDENTITY_ISSUER_KEYS_ENV, "").strip()
    return [item.strip() for item in raw.split(",") if item.strip()]


def identity_issues(bundle: dict[str, Any]) -> list[VerificationIssue]:
    """Verify the embedded JWT-SVID and bind its claims to the receipt's authority
    block. No-op when the bundle carries no `identity` section."""
    identity = bundle.get("identity")
    if not isinstance(identity, dict):
        return []
    issues: list[VerificationIssue] = []
    token = identity.get("jwt_svid")
    jwks = identity.get("issuer_jwks")
    if not token or not isinstance(jwks, dict):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.SIGNATURE_INVALID,
                "identity section is missing jwt_svid or issuer_jwks",
            )
        )
        return issues

    try:
        claims = _decode_svid(token, jwks)
    except Exception as exc:  # signature, key, or structural failure
        issues.append(
            VerificationIssue(
                VerifyErrorCode.SIGNATURE_INVALID,
                f"jwt_svid signature/decoding failed: {type(exc).__name__}",
            )
        )
        return issues

    authority = bundle.get("authority") or {}
    sub = claims.get("sub")
    iss = claims.get("iss")
    cnf_jkt = (claims.get("cnf") or {}).get("jkt")

    # Bind the signed SVID claims to the (tamper-evident) authority projection. A
    # swapped SVID changes sub/cnf; a mutated authority field stops matching the SVID.
    if sub is not None and authority.get("workload_principal") not in (None, sub):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUTHORITY_MISMATCH,
                "authority.workload_principal does not match the signed JWT-SVID sub",
            )
        )
    if sub is not None and authority.get("subject_id") not in (None, sub):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUTHORITY_MISMATCH,
                "authority.subject_id does not match the signed JWT-SVID sub",
            )
        )
    if sub is not None and identity.get("spiffe_id") not in (None, sub):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUTHORITY_MISMATCH,
                "identity.spiffe_id does not match the signed JWT-SVID sub",
            )
        )
    if iss is not None and authority.get("issuer") not in (None, iss):
        issues.append(
            VerificationIssue(
                VerifyErrorCode.AUTHORITY_MISMATCH,
                "authority.issuer does not match the signed JWT-SVID iss",
            )
        )
    if cnf_jkt is not None:
        if authority.get("presenter_key_hash") not in (None, cnf_jkt):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_MISMATCH,
                    "authority.presenter_key_hash does not match the JWT-SVID cnf.jkt",
                )
            )
        if identity.get("cnf_jkt") not in (None, cnf_jkt):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_MISMATCH,
                    "identity.cnf_jkt does not match the JWT-SVID cnf.jkt",
                )
            )

    # EV-101b: bind the embedded credential's stated expiry to the signed SVID `exp`.
    exp = claims.get("exp")
    stated_exp = identity.get("expires_at")
    if exp is not None and stated_exp:
        try:
            from datetime import datetime, timezone

            dt = datetime.fromisoformat(str(stated_exp).replace("Z", "+00:00"))
            if dt.tzinfo is None:  # credential expiry is a UTC instant, written naive
                dt = dt.replace(tzinfo=timezone.utc)
            parsed = dt.timestamp()
        except ValueError:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.AUTHORITY_MISMATCH,
                    "identity.expires_at is malformed",
                )
            )
        else:
            if abs(parsed - float(exp)) > 2:
                issues.append(
                    VerificationIssue(
                        VerifyErrorCode.AUTHORITY_MISMATCH,
                        "identity.expires_at does not match the JWT-SVID exp",
                    )
                )

    # EV-101b: when a Biscuit capability token is embedded, it must cryptographically
    # verify against the embedded root key. (None when the workload is JWT-only.)
    biscuit = identity.get("biscuit")
    if biscuit:
        root = identity.get("biscuit_root_public_key")
        ok = False
        if root:
            try:
                from biscuit_auth import Algorithm, Biscuit, PublicKey

                pk = PublicKey.from_bytes(bytes.fromhex(str(root)), Algorithm.Ed25519)
                Biscuit.from_base64(str(biscuit), pk)
                ok = True
            except Exception:
                ok = False
        if not ok:
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.SIGNATURE_INVALID,
                    "embedded Biscuit does not verify against its root public key",
                )
            )

    # Optional trust anchor: when a pinned issuer-key allowlist is configured, the
    # embedded JWKS thumbprints must be in it (otherwise verification is structural).
    trusted = _trusted_issuer_jwks()
    if trusted:
        thumbprints = {
            jwt.PyJWK.from_dict(jwk).key_id or jwk.get("x", "")
            for jwk in (jwks.get("keys") or [])
        }
        if not (thumbprints & set(trusted)):
            issues.append(
                VerificationIssue(
                    VerifyErrorCode.SIGNATURE_INVALID,
                    "identity issuer key is not in the trusted issuer allowlist",
                )
            )
    return issues
