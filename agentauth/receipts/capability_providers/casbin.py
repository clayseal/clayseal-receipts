"""Casbin capability provider.

Evaluates authorization with a Casbin enforcer (the ``casbin`` package). Install with
``pip install 'agentauth-receipts[casbin]'``. Configuration via ``context``:

    casbin_enforcer   a ready ``casbin.Enforcer`` (preferred), or
    casbin_model      path to a Casbin model .conf, and
    casbin_policy     path to a policy .csv
    casbin_subject    request subject (else context['principal'], else '*')

The request maps to Casbin's ``enforce(sub, obj, act)`` as
``enforce(subject, resource, action)``.
"""
from __future__ import annotations

from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision


class CasbinCapabilityProvider:
    name = "casbin"

    def _enforcer(self, ctx: dict[str, Any]):
        enforcer = ctx.get("casbin_enforcer")
        if enforcer is not None:
            return enforcer
        model = ctx.get("casbin_model")
        policy = ctx.get("casbin_policy")
        if not model:
            raise ValueError(
                "Casbin provider needs context['casbin_enforcer'] or "
                "context['casbin_model'] (+ optional 'casbin_policy')."
            )
        try:
            import casbin
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "The Casbin capability provider requires the 'casbin' extra: "
                "pip install 'agentauth-receipts[casbin]'"
            ) from exc
        return casbin.Enforcer(model, policy) if policy else casbin.Enforcer(model)

    def _decision(self, *, action: str, resource: str, ctx: dict[str, Any]) -> CapabilityDecision:
        enforcer = self._enforcer(ctx)
        subject = ctx.get("casbin_subject") or ctx.get("principal") or "*"
        allowed = bool(enforcer.enforce(subject, resource, action))
        return CapabilityDecision(
            allowed=allowed,
            reason=None if allowed else f"{subject!r} not permitted to {action!r} {resource!r}",
            metadata={"engine": "casbin"},
        )

    def authorize(
        self,
        *,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self._decision(action=action, resource=resource, ctx=context or {})

    def check_path(
        self,
        path: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self._decision(action="read", resource=path, ctx=context or {})


provider = CasbinCapabilityProvider()
