"""AWS Cedar capability provider.

Evaluates the request in-process with the Cedar engine (the ``cedarpy`` binding).
Install with ``pip install 'agentauth-receipts[cedar]'``. Configuration via ``context``:

    cedar_policies    Cedar policy text (or list of policy strings)
    cedar_entities    list of entity dicts (Cedar entity JSON)
    cedar_principal   principal uid, e.g. 'Agent::"researcher"'
    cedar_schema      optional schema JSON

The action/resource passed to ``authorize`` map to the Cedar action/resource uids
(``Action::"<action>"`` and ``Resource::"<resource>"`` unless already namespaced).
"""
from __future__ import annotations

from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision


def _uid(value: str, default_type: str) -> str:
    return value if "::" in value else f'{default_type}::"{value}"'


class CedarCapabilityProvider:
    name = "cedar"

    def _evaluate(
        self, *, action: str, resource: str, ctx: dict[str, Any]
    ) -> CapabilityDecision:
        try:
            import cedarpy
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "The Cedar capability provider requires the 'cedar' extra: "
                "pip install 'agentauth-receipts[cedar]'"
            ) from exc

        policies = ctx.get("cedar_policies")
        if policies is None:
            raise ValueError("Cedar provider needs context['cedar_policies'].")
        if isinstance(policies, (list, tuple)):
            policies = "\n".join(policies)

        request = {
            "principal": ctx.get("cedar_principal", 'Agent::"anonymous"'),
            "action": _uid(action, "Action"),
            "resource": _uid(resource, "Resource"),
            "context": ctx.get("cedar_context", {}),
        }
        result = cedarpy.is_authorized(
            request,
            policies,
            ctx.get("cedar_entities", []),
            schema=ctx.get("cedar_schema"),
        )
        allowed = getattr(result, "decision", None) == getattr(
            cedarpy.Decision, "Allow", "Allow"
        )
        return CapabilityDecision(
            allowed=allowed,
            reason=None if allowed else "denied by Cedar policy",
            metadata={"engine": "cedar", "reasons": list(getattr(result, "reasons", []) or [])},
        )

    def authorize(
        self,
        *,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self._evaluate(action=action, resource=resource, ctx=context or {})

    def check_path(
        self,
        path: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self._evaluate(action="read", resource=path, ctx=context or {})


provider = CedarCapabilityProvider()
