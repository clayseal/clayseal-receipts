"""Vanta exporter: receipt verification results as continuous control evidence.

Pushes :func:`agentauth.receipts.exporters.evidence.receipt_evidence_record`
records to a Vanta **Custom Connector** resource sync URL (PUT = full-state
sync of the resources you send). Auth is OAuth client-credentials against the
Vanta Connectors API.

Configuration (constructor args override env):

- ``AGENTAUTH_VANTA_RESOURCES_URL`` — the custom-resource sync URL from your
  Vanta custom connector (required to deliver)
- ``AGENTAUTH_VANTA_CLIENT_ID`` / ``AGENTAUTH_VANTA_CLIENT_SECRET``
- ``AGENTAUTH_VANTA_TOKEN_URL`` — default ``https://api.vanta.com/oauth/token``
- ``AGENTAUTH_VANTA_SCOPE`` — default ``connectors.self:write-resource``

Pair the pushed records with a dashboard-authored Custom Test (e.g. "every
agent receipt verifies and satisfied policy") to turn them into pass/fail
control evidence.
"""

from __future__ import annotations

import os
from typing import Any

from agentauth.receipts.exporters._http import post_json, put_json
from agentauth.receipts.exporters.evidence import receipt_evidence_record

RESOURCES_URL_ENV = "AGENTAUTH_VANTA_RESOURCES_URL"
CLIENT_ID_ENV = "AGENTAUTH_VANTA_CLIENT_ID"
CLIENT_SECRET_ENV = "AGENTAUTH_VANTA_CLIENT_SECRET"
TOKEN_URL_ENV = "AGENTAUTH_VANTA_TOKEN_URL"
SCOPE_ENV = "AGENTAUTH_VANTA_SCOPE"

DEFAULT_TOKEN_URL = "https://api.vanta.com/oauth/token"
DEFAULT_SCOPE = "connectors.self:write-resource"
DEFAULT_RESOURCE_TYPE = "AgentReceipt"


class VantaExporter:
    """``ReceiptExporter`` pushing receipt evidence to Vanta Custom Resources."""

    name = "vanta"

    def __init__(
        self,
        *,
        resources_url: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        token_url: str | None = None,
        scope: str | None = None,
        resource_type: str = DEFAULT_RESOURCE_TYPE,
        timeout: float = 10.0,
        client: Any | None = None,
    ) -> None:
        self.resources_url = resources_url or os.getenv(RESOURCES_URL_ENV, "")
        self.client_id = client_id or os.getenv(CLIENT_ID_ENV, "")
        self.client_secret = client_secret or os.getenv(CLIENT_SECRET_ENV, "")
        self.token_url = token_url or os.getenv(TOKEN_URL_ENV, "") or DEFAULT_TOKEN_URL
        self.scope = scope or os.getenv(SCOPE_ENV, "") or DEFAULT_SCOPE
        self.resource_type = resource_type
        self.timeout = timeout
        self.client = client

    def _access_token(self, client: Any | None) -> str:
        response = post_json(
            self.token_url,
            {
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": self.scope,
            },
            timeout=self.timeout,
            client=client,
        )
        token = response.json().get("access_token", "")
        if not token:
            raise RuntimeError("Vanta token endpoint returned no access_token")
        return token

    def export(self, bundle: dict[str, Any], **options: Any) -> dict[str, Any]:
        if not self.resources_url:
            raise RuntimeError(
                "vanta exporter is unconfigured: set the custom-connector resource "
                f"sync URL via {RESOURCES_URL_ENV} or resources_url="
            )
        if not self.client_id or not self.client_secret:
            raise RuntimeError(
                f"vanta exporter needs OAuth credentials ({CLIENT_ID_ENV} / {CLIENT_SECRET_ENV})"
            )
        client = options.get("client", self.client)
        record = receipt_evidence_record(bundle, verify=options.get("verify", True))
        resource_id = str(record.get("proof_id") or "agent-receipt")
        payload = {
            "resourceType": options.get("resource_type", self.resource_type),
            "resources": [
                {
                    "resourceId": resource_id,
                    "displayName": f"Agent receipt {resource_id}",
                    **record,
                }
            ],
        }
        token = self._access_token(client)
        response = put_json(
            options.get("resources_url", self.resources_url),
            payload,
            headers={"Authorization": f"Bearer {token}"},
            timeout=options.get("timeout", self.timeout),
            client=client,
        )
        return {
            "exporter": self.name,
            "delivered": True,
            "resource_id": resource_id,
            "status_code": response.status_code,
        }
