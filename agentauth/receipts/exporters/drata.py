"""Drata exporter: receipt verification results into a Custom Connection.

POSTs :func:`agentauth.receipts.exporters.evidence.receipt_evidence_record`
records to Drata's public API
(``/public/custom-connections/{connection_id}/resources/{resource_id}/records``,
Bearer auth), where they feed Drata's monitoring/evidence workflows.

Configuration (constructor args override env):

- ``AGENTAUTH_DRATA_API_KEY`` — Drata public API key (required to deliver)
- ``AGENTAUTH_DRATA_CONNECTION_ID`` / ``AGENTAUTH_DRATA_RESOURCE_ID``
- ``AGENTAUTH_DRATA_BASE_URL`` — default ``https://public-api.drata.com``
"""

from __future__ import annotations

import os
from typing import Any

from agentauth.receipts.exporters._http import post_json
from agentauth.receipts.exporters.evidence import receipt_evidence_record

API_KEY_ENV = "AGENTAUTH_DRATA_API_KEY"
CONNECTION_ID_ENV = "AGENTAUTH_DRATA_CONNECTION_ID"
RESOURCE_ID_ENV = "AGENTAUTH_DRATA_RESOURCE_ID"
BASE_URL_ENV = "AGENTAUTH_DRATA_BASE_URL"

DEFAULT_BASE_URL = "https://public-api.drata.com"


class DrataExporter:
    """``ReceiptExporter`` pushing receipt evidence to a Drata Custom Connection."""

    name = "drata"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        connection_id: str | None = None,
        resource_id: str | None = None,
        base_url: str | None = None,
        timeout: float = 10.0,
        client: Any | None = None,
    ) -> None:
        self.api_key = api_key or os.getenv(API_KEY_ENV, "")
        self.connection_id = connection_id or os.getenv(CONNECTION_ID_ENV, "")
        self.resource_id = resource_id or os.getenv(RESOURCE_ID_ENV, "")
        self.base_url = (base_url or os.getenv(BASE_URL_ENV, "") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.client = client

    def export(self, bundle: dict[str, Any], **options: Any) -> dict[str, Any]:
        if not self.api_key:
            raise RuntimeError(f"drata exporter is unconfigured: set {API_KEY_ENV} or api_key=")
        connection_id = options.get("connection_id", self.connection_id)
        resource_id = options.get("resource_id", self.resource_id)
        if not connection_id or not resource_id:
            raise RuntimeError(
                "drata exporter needs a custom connection target "
                f"({CONNECTION_ID_ENV} / {RESOURCE_ID_ENV})"
            )
        record = receipt_evidence_record(bundle, verify=options.get("verify", True))
        url = (
            f"{self.base_url}/public/custom-connections/"
            f"{connection_id}/resources/{resource_id}/records"
        )
        response = post_json(
            url,
            {"data": record},
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=options.get("timeout", self.timeout),
            client=options.get("client", self.client),
        )
        return {
            "exporter": self.name,
            "delivered": True,
            "proof_id": record.get("proof_id"),
            "status_code": response.status_code,
        }
