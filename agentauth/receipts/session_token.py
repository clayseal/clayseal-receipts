"""Session-scoped credentials with optional DPoP binding (F8 replay mitigation)."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt

from agentauth.core.hash_util import hash_canonical_json, sha256_hex

DEFAULT_TTL_SECONDS = 300


@dataclass
class SessionTokenPolicy:
    enabled: bool = False
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    require_dpop: bool = False
    bind_to_session_id: bool = True

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> SessionTokenPolicy:
        if not isinstance(raw, dict):
            return cls()
        return cls(
            enabled=bool(raw.get("enabled", False)),
            ttl_seconds=int(raw.get("ttl_seconds", DEFAULT_TTL_SECONDS)),
            require_dpop=bool(raw.get("require_dpop", False)),
            bind_to_session_id=bool(raw.get("bind_to_session_id", True)),
        )


@dataclass
class SessionBoundCredential:
    token_id: str
    session_id: str
    issued_at: int
    expires_at: int
    scopes: list[str] = field(default_factory=list)
    dpop_jkt: str | None = None

    def to_claims(self) -> dict[str, Any]:
        return {
            "sub": self.session_id,
            "jti": self.token_id,
            "iat": self.issued_at,
            "exp": self.expires_at,
            "scopes": list(self.scopes),
            "dpop_jkt": self.dpop_jkt,
            "typ": "agentauth-session+credential",
        }


def mint_session_credential(
    session_id: str,
    *,
    secret: bytes | str,
    scopes: list[str] | None = None,
    policy: SessionTokenPolicy | None = None,
    dpop_jkt: str | None = None,
) -> tuple[str, SessionBoundCredential]:
    """Issue a short-lived HS256 session token (gateway mints; MCP verifies)."""
    cfg = policy or SessionTokenPolicy()
    now = int(time.time())
    cred = SessionBoundCredential(
        token_id=f"st_{uuid.uuid4().hex}",
        session_id=session_id,
        issued_at=now,
        expires_at=now + cfg.ttl_seconds,
        scopes=list(scopes or []),
        dpop_jkt=dpop_jkt if cfg.require_dpop else dpop_jkt,
    )
    token = jwt.encode(cred.to_claims(), secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token, cred


def verify_session_credential(
    token: str,
    *,
    secret: bytes | str,
    session_id: str | None = None,
    policy: SessionTokenPolicy | None = None,
    dpop_proof_thumbprint: str | None = None,
) -> dict[str, Any]:
    """Verify session token; optionally require DPoP JKT match."""
    cfg = policy or SessionTokenPolicy()
    issues: list[str] = []
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "sub", "jti"]},
        )
    except Exception as exc:
        return {"valid": False, "issues": [f"session token invalid: {exc}"], "claims": {}}

    if cfg.bind_to_session_id and session_id and claims.get("sub") != session_id:
        issues.append("session token subject does not match active session_id")
    if cfg.require_dpop:
        expected = claims.get("dpop_jkt")
        if not expected:
            issues.append("session token missing dpop_jkt but policy requires DPoP")
        elif dpop_proof_thumbprint and expected != dpop_proof_thumbprint:
            issues.append("DPoP proof thumbprint does not match session token binding")

    return {
        "valid": not issues,
        "issues": issues,
        "claims": claims,
        "commitment": sha256_hex(hash_canonical_json(claims).encode("utf-8")),
    }


def dpop_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638-style thumbprint for DPoP public key binding (stub)."""
    return sha256_hex(hash_canonical_json(jwk).encode("utf-8"))
