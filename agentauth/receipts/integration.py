"""Receipt runtime integration with pluggable identity + capability layers.

This module is the L3 side of the identity seam: it consumes core contracts
(``IdentitySession``, ``AuthorityBinding``) and duck-typed native sessions.
receipts never imports the identity layer itself. The umbrella package's
``agentauth.wrap()`` delegates here.
"""

from __future__ import annotations

from typing import Any

from agentauth.core.identity_protocol import (
    CapabilityAuthorizer,
    CapabilityLayer,
    CapabilityProvider,
    IdentitySession,
)


def resolve_capability_provider(
    provider: str | CapabilityProvider | None,
) -> CapabilityProvider | None:
    """Resolve a capability provider from a registry name or provider object."""
    if provider is None or not isinstance(provider, str):
        return provider
    from agentauth.receipts.capability_providers import get_capability_provider

    return get_capability_provider(provider)


def authorizer_from_provider(
    provider: CapabilityProvider,
    *,
    context: dict[str, Any] | None = None,
) -> CapabilityAuthorizer:
    """Adapt a provider to the callable shape enforced by ``AgentWrapper``."""

    def _authorize(resource: str, action: str) -> dict[str, Any]:
        decision = provider.authorize(action=action, resource=resource, context=context)
        metadata = {
            k: v
            for k, v in decision.metadata.items()
            if k not in {"allowed", "reason", "obligations"}
        }
        return {
            "allowed": decision.allowed,
            "reason": decision.reason,
            "obligations": decision.obligations,
            **metadata,
        }

    return _authorize


def wrap_with_identity_session(
    model: Any,
    policy: Any,
    session: IdentitySession,
    *,
    capability_layer: CapabilityLayer | None = None,
    capability_provider: str | CapabilityProvider | None = None,
    capability_context: dict[str, Any] | None = None,
    task_mandate: Any = None,
    **kwargs: Any,
) -> Any:
    """Wrap a model using a provider-neutral identity session."""
    from agentauth.receipts import AgentWrapper

    capability_authorizer = session.capability_authorizer
    resolved = resolve_capability_provider(capability_provider)
    if resolved is not None:
        capability_authorizer = authorizer_from_provider(resolved, context=capability_context)

    if task_mandate is not None:
        kwargs["task_mandate"] = task_mandate
    if capability_layer is not None:
        metadata = dict(getattr(session, "metadata", {}) or {})
        metadata["capability_layer"] = getattr(capability_layer, "name", "custom")
        session.metadata = metadata
    return AgentWrapper(
        model,
        policy,
        default_authority_binding=session.binding,
        capability_authorizer=capability_authorizer,
        **kwargs,
    )


def wrap_agentauth_session(
    session: Any,
    model: Any,
    *,
    policy: Any,
    task_mandate: Any = None,
    **kwargs: Any,
) -> Any:
    """Wrap a model bound to a native Clay Seal ``AgentSession``.

    Duck-typed on purpose: ``session`` only needs ``.credential`` (with
    ``to_binding_dict()`` and ``biscuit``) and ``.authorize``, so this module
    stays free of any import of the identity layer. This is the inverted home
    of what used to be ``AgentSession.wrap()``.
    """
    from agentauth.core.authority_binding import AuthorityBinding
    from agentauth.receipts import AgentWrapper

    binding = AuthorityBinding.from_agentauth_credential(session.credential.to_binding_dict())
    capability_authorizer = session.authorize if session.credential.biscuit else None
    if task_mandate is not None:
        kwargs["task_mandate"] = task_mandate
    workload_pem = getattr(session, "_workload_private_pem", None)
    if workload_pem:
        kwargs.setdefault("workload_private_pem", workload_pem)
    kwargs.setdefault("agentauth_credential_token", session.token)
    return AgentWrapper(
        model,
        policy,
        default_authority_binding=binding,
        capability_authorizer=capability_authorizer,
        **kwargs,
    )


def wrap_with_provider_claims(
    model: Any,
    policy: Any,
    provider: str,
    claims: dict[str, Any],
    *,
    evidence_verified: bool = False,
    **kwargs: Any,
) -> Any:
    """Wrap a model from provider claims without requiring Clay Seal Identity (L1).

    Requires only receipts-local provider normalization. L3 still runs without
    L1 or L2 if the caller supplies verified OIDC/SPIFFE/Auth0/AWS/Azure/GCP
    claims.
    """
    from agentauth.receipts.identity_providers import get_identity_provider

    session = get_identity_provider(provider).build_session(
        claims, evidence_verified=evidence_verified
    )
    return wrap_with_identity_session(model, policy, session, **kwargs)


wrap_clayseal_session = wrap_agentauth_session
