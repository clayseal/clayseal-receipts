"""Shared production guardrails for Clay Seal runtimes."""

from __future__ import annotations

import os

from agentauth.core.signing import (
    TRUSTED_SIGNER_KEY_IDS_ENV,
    TRUSTED_SIGNER_PUBLIC_KEYS_ENV,
    trusted_signer_policy_from_env,
)

_PRODUCTION_VALUES = frozenset({"production", "prod"})

# Truthy in production => refuse startup.
_IDENTITY_PRODUCTION_DENY = (
    "AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR",
    "AGENTAUTH_DEV_ATTESTOR",
)

_RECEIPTS_PRODUCTION_DENY = _IDENTITY_PRODUCTION_DENY + (
    "AGENT_RECEIPTS_ALLOW_STUB",
    "AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE",
    "AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT",
)

_ATTESTATION_JWKS_ENV = "AGENTAUTH_ATTESTATION_JWKS_URL"
_ATTESTATION_ISSUER_ENV = "AGENTAUTH_ATTESTATION_ISSUER"
_ATTESTATION_AUDIENCE_ENV = "AGENTAUTH_ATTESTATION_AUDIENCE"
_HTTP_ALLOWED_HOSTS_ENV = "AGENTAUTH_HTTP_ALLOWED_HOSTS"


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


def deployment_env() -> str:
    return (
        os.environ.get("AGENT_RECEIPTS_ENV", "").strip().lower()
        or os.environ.get("AGENTAUTH_ENV", "").strip().lower()
    )


def is_production() -> bool:
    return deployment_env() in _PRODUCTION_VALUES


def production_violations(*, layer: str = "all") -> list[str]:
    """Return human-readable production policy violations for ``layer``.

    ``layer`` is one of ``identity``, ``receipts``, or ``all``.
    """
    if not is_production():
        return []

    violations: list[str] = []

    if layer in {"identity", "all"}:
        for name in _IDENTITY_PRODUCTION_DENY:
            if _env_truthy(name):
                violations.append(f"{name}={os.environ.get(name)}")
        if not os.environ.get("AGENTAUTH_ADMIN_API_KEY", "").strip():
            violations.append("AGENTAUTH_ADMIN_API_KEY is unset")
        cors = os.environ.get("AGENTAUTH_CORS_ORIGINS", "").strip()
        if not cors:
            violations.append("AGENTAUTH_CORS_ORIGINS must be set in production")
        elif "*" in cors.split(","):
            violations.append("AGENTAUTH_CORS_ORIGINS must not include '*' in production")

    if layer in {"receipts", "all"}:
        for name in _RECEIPTS_PRODUCTION_DENY:
            if _env_truthy(name):
                violations.append(f"{name}={os.environ.get(name)}")
        if not os.environ.get("AGENT_RECEIPTS_VERIFIER_API_KEY", "").strip():
            violations.append("AGENT_RECEIPTS_VERIFIER_API_KEY is unset")
        if not _env_truthy("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES"):
            violations.append(
                "AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES must be set to 1 in production"
            )
        policy = trusted_signer_policy_from_env()
        if not policy.get("public_keys") and not policy.get("key_ids"):
            violations.append(
                f"configure {TRUSTED_SIGNER_PUBLIC_KEYS_ENV} or {TRUSTED_SIGNER_KEY_IDS_ENV} "
                "so receipt verification pins trusted signers"
            )

    if layer in {"identity", "receipts", "all"}:
        if not os.environ.get(_HTTP_ALLOWED_HOSTS_ENV, "").strip():
            violations.append(
                f"{_HTTP_ALLOWED_HOSTS_ENV} must be set in production for outbound HTTP fetches"
            )
        commit_store = os.environ.get("AGENTAUTH_COMMIT_TOKEN_STORE", "").strip().lower()
        if commit_store in {"redis", "rediss"} and not os.environ.get(
            "AGENTAUTH_COMMIT_TOKEN_REDIS_URL", ""
        ).strip():
            violations.append(
                "AGENTAUTH_COMMIT_TOKEN_REDIS_URL is required when AGENTAUTH_COMMIT_TOKEN_STORE=redis"
            )
        jwks_url = os.environ.get(_ATTESTATION_JWKS_ENV, "").strip()
        if jwks_url:
            if not os.environ.get(_ATTESTATION_ISSUER_ENV, "").strip():
                violations.append(
                    f"{_ATTESTATION_ISSUER_ENV} is required when {_ATTESTATION_JWKS_ENV} is set"
                )
            if not os.environ.get(_ATTESTATION_AUDIENCE_ENV, "").strip():
                violations.append(
                    f"{_ATTESTATION_AUDIENCE_ENV} is required when {_ATTESTATION_JWKS_ENV} is set"
                )

    return violations


def enforce_production_policy(*, layer: str = "all") -> None:
    violations = production_violations(layer=layer)
    if violations:
        raise RuntimeError(
            "production deployment refused to start: " + "; ".join(sorted(violations))
        )


def refuse_dev_attestation_client(*, dev_attestation_enabled: bool) -> None:
    """SDK entrypoints call this when dev attestation is requested."""
    if is_production() and dev_attestation_enabled:
        raise RuntimeError(
            "dev_attestation is not permitted when AGENTAUTH_ENV=production; "
            "use a real attestation path or a non-production environment"
        )
    if is_production() and _env_truthy("AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR"):
        raise RuntimeError(
            "AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR must be unset in production"
        )
