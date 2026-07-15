"""Registry for receipt-local identity providers."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agentauth.core.plugins import get_plugin, list_plugins, register_plugin

if TYPE_CHECKING:
    from agentauth.core.identity_protocol import (
        CapabilityAuthorizer,
        IdentityProvider,
        IdentitySession,
    )

_GROUP = "identity_providers"
_BUILTINS_LOADED = False


def register_identity_provider(provider: IdentityProvider) -> None:
    register_plugin(_GROUP, provider.name, provider)


def get_identity_provider(name: str) -> IdentityProvider:
    _ensure_loaded()
    try:
        return get_plugin(_GROUP, name)
    except KeyError:
        known = ", ".join(list_identity_providers()) or "(none)"
        raise KeyError(f"unknown identity provider {name!r}; known: {known}") from None


def list_identity_providers() -> list[str]:
    _ensure_loaded()
    return list_plugins(_GROUP)


def build_identity_session(
    provider: str,
    claims: dict[str, Any],
    *,
    capability_authorizer: CapabilityAuthorizer | None = None,
    evidence_verified: bool = False,
) -> IdentitySession:
    return get_identity_provider(provider).build_session(
        claims,
        capability_authorizer=capability_authorizer,
        evidence_verified=evidence_verified,
    )


def _ensure_loaded() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return

    from agentauth.receipts.identity_providers import agentauth as _agentauth
    from agentauth.receipts.identity_providers import auth0 as _auth0
    from agentauth.receipts.identity_providers import aws_sts as _aws
    from agentauth.receipts.identity_providers import azure_ad as _azure
    from agentauth.receipts.identity_providers import gcp as _gcp
    from agentauth.receipts.identity_providers import oidc as _oidc
    from agentauth.receipts.identity_providers import spiffe_jwt as _spiffe

    for module in (_agentauth, _auth0, _aws, _azure, _gcp, _oidc, _spiffe):
        register_identity_provider(module.provider)
    _BUILTINS_LOADED = True
