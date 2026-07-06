"""Native AgentAuth capability provider — wraps the Biscuit L2 layer.

Importing this module requires ``agentauth-capabilities`` (and its Biscuit backend);
the registry registers this provider only when that import succeeds, so receipts can
run on an external engine with no L2 installed.
"""
from __future__ import annotations

from typing import Any

from agentauth.capabilities.integration import default_biscuit_backend
from agentauth.core.identity_protocol import CapabilityDecision

_FILE_RESOURCE = "file"


def _decision_from_dict(result: dict[str, Any]) -> CapabilityDecision:
    return CapabilityDecision(
        allowed=bool(result.get("allowed")),
        reason=result.get("reason"),
        obligations=list(result.get("obligations", [])),
        metadata={k: v for k, v in result.items() if k not in ("allowed", "reason", "obligations")},
    )


class AgentAuthCapabilityProvider:
    """Authorization via the native Biscuit capability layer.

    Resolves a decision from, in order of preference:
      1. a ``capability_authorizer`` callable in ``context`` (an offline
         ``AgentSession.authorize`` bound to an attested identity), or
      2. a raw Biscuit ``token``/``root_public_hex`` pair in ``context``.
    """

    name = "agentauth"

    def authorize(
        self,
        *,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        ctx = context or {}
        authorizer = ctx.get("capability_authorizer")
        if callable(authorizer):
            return _decision_from_dict(authorizer(resource, action))

        token = ctx.get("token") or ctx.get("token_b64")
        root = ctx.get("root_public_hex")
        if token and root:
            result = default_biscuit_backend().authorize(
                token,
                root_public_hex=root,
                resource=resource,
                action=action,
                file_path=ctx.get("file_path"),
            )
            return _decision_from_dict(result)

        return CapabilityDecision(
            allowed=False,
            reason="no capability_authorizer or biscuit token in context",
        )

    def check_path(
        self,
        path: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        ctx = dict(context or {})
        ctx["file_path"] = path
        return self.authorize(action="read", resource=_FILE_RESOURCE, context=ctx)


provider = AgentAuthCapabilityProvider()
