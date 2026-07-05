"""Receipt runtime integration with pluggable identity + capability layers."""
from __future__ import annotations

from typing import Any

from agentauth.core.identity_protocol import CapabilityLayer, IdentitySession


def wrap_with_identity_session(
    model: Any,
    policy: Any,
    session: IdentitySession,
    *,
    capability_layer: CapabilityLayer | None = None,
    task_mandate: Any = None,
    **kwargs: Any,
) -> Any:
    """Wrap a model using a provider-neutral identity session."""
    from agentauth.receipts import AgentWrapper

    if task_mandate is not None:
        kwargs["task_mandate"] = task_mandate
    return AgentWrapper(
        model,
        policy,
        default_authority_binding=session.binding,
        capability_authorizer=session.capability_authorizer,
        **kwargs,
    )
