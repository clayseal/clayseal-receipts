"""User-supplied capability provider.

For teams whose authorization does not fit a bundled engine: wrap any callable in a
provider and register it. The callable receives ``(action, resource, context)`` and
returns either a bool or a mapping ``{"allowed": bool, "reason"?, "obligations"?}``.

    from agentauth.receipts.capability_providers import from_callable, register_capability_provider

    def my_authz(action, resource, context):
        return {"allowed": action == "read", "reason": "read-only tenant"}

    register_capability_provider(from_callable(my_authz, name="acme"))
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision

AuthorizeFn = Callable[[str, str, dict], "bool | dict[str, Any] | CapabilityDecision"]


def _coerce(result: bool | dict[str, Any] | CapabilityDecision) -> CapabilityDecision:
    if isinstance(result, CapabilityDecision):
        return result
    if isinstance(result, bool):
        return CapabilityDecision(allowed=result, reason=None if result else "denied")
    return CapabilityDecision(
        allowed=bool(result.get("allowed")),
        reason=result.get("reason"),
        obligations=list(result.get("obligations", [])),
        metadata=dict(result.get("metadata", {})),
    )


class _CallableCapabilityProvider:
    def __init__(self, fn: AuthorizeFn, *, name: str) -> None:
        self.name = name
        self._fn = fn

    def authorize(
        self,
        *,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return _coerce(self._fn(action, resource, context or {}))

    def check_path(
        self,
        path: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self.authorize(action="read", resource=path, context=context)


def from_callable(fn: AuthorizeFn, *, name: str = "user") -> _CallableCapabilityProvider:
    """Build a CapabilityProvider from an ``(action, resource, context)`` callable."""
    return _CallableCapabilityProvider(fn, name=name)
