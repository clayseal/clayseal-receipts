"""OIDC actor verification for gate / CI binding (SM-15 / F7)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

import jwt

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ACTIONS_JWKS_URL = "https://token.actions.githubusercontent.com/.well-known/jwks"


@dataclass
class VerifiedActorIdentity:
    oidc_subject: str
    oidc_issuer: str
    github_actor: str | None = None
    repository: str | None = None
    workflow_ref: str | None = None
    claims: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "oidc_subject": self.oidc_subject,
            "oidc_issuer": self.oidc_issuer,
            "github_actor": self.github_actor,
            "repository": self.repository,
            "workflow_ref": self.workflow_ref,
        }


def fetch_jwks(jwks_url: str, *, timeout: float = 10.0) -> dict[str, Any]:
    request = urllib.request.Request(jwks_url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not isinstance(payload, dict) or not payload.get("keys"):
        raise ValueError(f"JWKS at {jwks_url!r} did not contain keys")
    return payload


def _select_jwk(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    keys = jwks.get("keys") or []
    if not keys:
        raise ValueError("JWKS contains no keys")
    try:
        kid = jwt.get_unverified_header(token).get("kid")
    except Exception as exc:
        raise ValueError("malformed OIDC token header") from exc
    if kid is not None:
        for jwk in keys:
            if jwk.get("kid") == kid:
                return jwk
        raise ValueError(f"no JWKS key matches kid {kid!r}")
    # No kid: only unambiguous against a single-key JWKS.
    if len(keys) == 1:
        return keys[0]
    raise ValueError("token has no 'kid' and the JWKS has multiple keys")


def verify_oidc_token(
    token: str,
    *,
    jwks: dict[str, Any],
    issuer: str,
    audience: str | None = None,
) -> dict[str, Any]:
    """Verify JWT signature + issuer; optionally audience."""
    jwk = _select_jwk(token, jwks)
    key = jwt.PyJWK.from_dict(jwk).key
    # OIDC ID tokens MUST carry exp and iss (OpenID Connect Core §2); require them so a
    # token without an expiry can never verify.
    options = {"verify_aud": audience is not None, "require": ["exp", "iss"]}
    decode_kwargs: dict[str, Any] = {
        "algorithms": ["RS256", "EdDSA", "ES256"],
        "issuer": issuer,
        "options": options,
    }
    if audience is not None:
        decode_kwargs["audience"] = audience
    return jwt.decode(token, key=key, **decode_kwargs)


def resolve_verified_actor(
    token: str,
    *,
    jwks_url: str | None = None,
    jwks: dict[str, Any] | None = None,
    issuer: str | None = None,
    audience: str | None = None,
) -> VerifiedActorIdentity:
    """Verify an OIDC token and extract actor-facing claims."""
    resolved_jwks = jwks or fetch_jwks(jwks_url or GITHUB_ACTIONS_JWKS_URL)
    resolved_issuer = issuer or GITHUB_ACTIONS_ISSUER
    claims = verify_oidc_token(
        token,
        jwks=resolved_jwks,
        issuer=resolved_issuer,
        audience=audience,
    )
    subject = str(claims.get("sub") or "")
    if not subject:
        raise ValueError("OIDC token missing sub claim")
    actor = claims.get("actor")
    github_actor = str(actor) if actor else None
    repository = claims.get("repository")
    workflow_ref = claims.get("workflow_ref") or claims.get("ref")
    return VerifiedActorIdentity(
        oidc_subject=subject,
        oidc_issuer=str(claims.get("iss") or resolved_issuer),
        github_actor=github_actor,
        repository=str(repository) if repository else None,
        workflow_ref=str(workflow_ref) if workflow_ref else None,
        claims=claims,
    )


def github_actor_from_oidc(token: str, *, audience: str | None = None) -> VerifiedActorIdentity:
    """Convenience wrapper for GitHub Actions OIDC tokens."""
    return resolve_verified_actor(
        token,
        jwks_url=GITHUB_ACTIONS_JWKS_URL,
        issuer=GITHUB_ACTIONS_ISSUER,
        audience=audience,
    )
