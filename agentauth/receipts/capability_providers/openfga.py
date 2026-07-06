"""OpenFGA / SpiceDB (Zanzibar-style relationship) capability provider.

Answers ``authorize`` as a relationship check: does the principal have relation
``action`` on object ``resource``? Install with ``pip install
'agentauth-receipts[openfga]'``. Configuration via ``context`` or environment:

    openfga_url    API URL   (env AGENTAUTH_OPENFGA_URL, default http://localhost:8080)
    openfga_store  store id  (env AGENTAUTH_OPENFGA_STORE_ID)
    openfga_user   principal, e.g. 'agent:researcher' (else context['principal'])

``resource`` is the object (``type:id``); ``action`` is the relation to check.
"""
from __future__ import annotations

import os
from typing import Any

from agentauth.core.identity_protocol import CapabilityDecision

_DEFAULT_URL = "http://localhost:8080"


class OpenFGACapabilityProvider:
    name = "openfga"

    def _check(
        self, *, action: str, resource: str, ctx: dict[str, Any]
    ) -> CapabilityDecision:
        try:
            from openfga_sdk import ClientConfiguration, OpenFgaClient
            from openfga_sdk.client.models import ClientCheckRequest
        except ImportError as exc:  # pragma: no cover - exercised only without the extra
            raise ImportError(
                "The OpenFGA capability provider requires the 'openfga' extra: "
                "pip install 'agentauth-receipts[openfga]'"
            ) from exc

        url = ctx.get("openfga_url") or os.environ.get("AGENTAUTH_OPENFGA_URL", _DEFAULT_URL)
        store = ctx.get("openfga_store") or os.environ.get("AGENTAUTH_OPENFGA_STORE_ID")
        if not store:
            raise ValueError(
                "OpenFGA provider needs a store id: context['openfga_store'] or "
                "AGENTAUTH_OPENFGA_STORE_ID."
            )
        user = ctx.get("openfga_user") or ctx.get("principal")
        if not user:
            raise ValueError("OpenFGA provider needs context['openfga_user'] (or 'principal').")

        config = ClientConfiguration(api_url=url, store_id=store)
        with OpenFgaClient(config) as client:
            body = ClientCheckRequest(user=user, relation=action, object=resource)
            resp = client.check(body)
        allowed = bool(getattr(resp, "allowed", False))
        return CapabilityDecision(
            allowed=allowed,
            reason=None if allowed else f"{user} lacks relation {action!r} on {resource!r}",
            metadata={"engine": "openfga", "store": store},
        )

    def authorize(
        self,
        *,
        action: str,
        resource: str,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self._check(action=action, resource=resource, ctx=context or {})

    def check_path(
        self,
        path: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> CapabilityDecision:
        return self._check(action="read", resource=f"file:{path}", ctx=context or {})


provider = OpenFGACapabilityProvider()
