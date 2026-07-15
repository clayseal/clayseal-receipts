"""Open Policy Agent (Rego) capability provider.

Sends the authorization query to an OPA server's Data API and normalizes the result.
Configuration comes from ``context`` (per call) or environment (process default):

    opa_url            base URL of the OPA server   (env AGENTAUTH_OPA_URL,
                       default http://localhost:8181)
    opa_decision_path  package path of the boolean/object decision rule,
                       e.g. "agentauth/authz/allow"  (env AGENTAUTH_OPA_DECISION_PATH)

The rule receives ``input = {"action", "resource", "path"?, ...context}`` and should
return either a bool or an object like ``{"allow": bool, "reason": str,
"obligations": [...]}``.
"""
from __future__ import annotations

import os
from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision

_DEFAULT_URL = "http://localhost:8181"


class OPACapabilityProvider:
    name = "opa"

    def _config(self, ctx: dict[str, Any]) -> tuple[str, str]:
        url = ctx.get("opa_url") or os.environ.get("AGENTAUTH_OPA_URL", _DEFAULT_URL)
        path = ctx.get("opa_decision_path") or os.environ.get("AGENTAUTH_OPA_DECISION_PATH")
        if not path:
            raise ValueError(
                "OPA provider needs a decision path: set context['opa_decision_path'] "
                "or AGENTAUTH_OPA_DECISION_PATH (e.g. 'agentauth/authz/allow')."
            )
        return url.rstrip("/"), path.strip("/")

    def _query(self, url: str, path: str, doc: dict[str, Any]) -> CapabilityDecision:
        import httpx  # a receipts dependency; imported lazily to keep import side-effect-free

        resp = httpx.post(f"{url}/v1/data/{path}", json={"input": doc}, timeout=10.0)
        resp.raise_for_status()
        result = resp.json().get("result")
        if isinstance(result, bool) or result is None:
            return CapabilityDecision(
                allowed=bool(result),
                reason=None if result else "denied by OPA policy",
                metadata={"engine": "opa", "decision_path": path},
            )
        return CapabilityDecision(
            allowed=bool(result.get("allow", result.get("allowed"))),
            reason=result.get("reason"),
            obligations=list(result.get("obligations", [])),
            metadata={"engine": "opa", "decision_path": path, **result.get("metadata", {})},
        )

    def authorize(
        self,
        *,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        ctx = context or {}
        url, path = self._config(ctx)
        doc = {k: v for k, v in ctx.items() if not k.startswith("opa_")}
        doc.update(action=action, resource=resource)
        return self._query(url, path, doc)

    def check_path(
        self,
        path: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        ctx = dict(context or {})
        ctx["path"] = path
        return self.authorize(action="read", resource="file", context=ctx)


provider = OPACapabilityProvider()
