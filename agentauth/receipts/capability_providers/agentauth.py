"""Native Clay Seal capability provider for Biscuit-backed L2 authorization.

This provider works with a supplied ``capability_authorizer`` without importing
the private-preview capabilities layer. Raw Biscuit token checks import that
layer lazily only when the token path is used.
"""
from __future__ import annotations

from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision

_FILE_RESOURCE = "file"


def _decision_from_dict(result: dict[str, Any]) -> CapabilityDecision:
    return CapabilityDecision(
        allowed=bool(result.get("allowed")),
        reason=result.get("reason"),
        obligations=list(result.get("obligations", [])),
        metadata={k: v for k, v in result.items() if k not in ("allowed", "reason", "obligations")},
    )


class ClaySealCapabilityProvider:
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
            try:
                from agentauth.capabilities.integration import default_biscuit_backend
            except ImportError as exc:
                raise ImportError(
                    "Raw Biscuit token authorization requires the private-preview "
                    "Clay Seal capabilities layer. Pass a capability_authorizer "
                    "callable in context, or use an external provider such as OPA, "
                    "Cedar, OpenFGA, or Casbin."
                ) from exc
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


provider = ClaySealCapabilityProvider()
