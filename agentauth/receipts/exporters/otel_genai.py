"""OTel ``gen_ai.*`` receipt exporter (OTLP/HTTP JSON logs).

One exporter, many backends: Datadog, New Relic, Langfuse, LangSmith,
Braintrust and Splunk all ingest OTel GenAI semantic conventions natively —
point ``endpoint`` at the backend's OTLP logs URL (usually ``…/v1/logs``) with
whatever auth header it wants.

The emitted payload pins :data:`agentauth.receipts.otel.GEN_AI_SEMCONV_VERSION`
via the OTLP ``schemaUrl`` fields — gen_ai semconv is still "Development"
status, so consumers need to know which release the mapping tracked.
"""

from __future__ import annotations

import os
from typing import Any

from agentauth.receipts.exporters._http import post_json
from agentauth.receipts.otel import (
    GEN_AI_SEMCONV_VERSION,
    OTEL_SCHEMA_URL,
    bundle_to_otlp_resource_logs,
)

ENDPOINT_ENV = "AGENTAUTH_OTLP_LOGS_ENDPOINT"
# The standard OTel SDK variable, honored as a fallback.
OTEL_ENDPOINT_ENV = "OTEL_EXPORTER_OTLP_LOGS_ENDPOINT"


class OtelGenAiExporter:
    """``ReceiptExporter`` mapping receipt bundles onto gen_ai.* log records."""

    name = "otel_genai"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        service_name: str = "agent-receipts",
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        client: Any | None = None,
    ) -> None:
        self.endpoint = (
            endpoint
            if endpoint is not None
            else os.getenv(ENDPOINT_ENV, "") or os.getenv(OTEL_ENDPOINT_ENV, "")
        )
        self.service_name = service_name
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.client = client

    def export(self, bundle: dict[str, Any], **options: Any) -> dict[str, Any]:
        """Shape the bundle as OTLP resource logs; POST when an endpoint is set.

        Without an endpoint the shaped payload is still returned, so callers can
        hand it to their own OTel pipeline (collector, SDK LoggerProvider, file).
        """
        endpoint = options.get("endpoint", self.endpoint)
        payload = bundle_to_otlp_resource_logs(
            bundle, service_name=options.get("service_name", self.service_name)
        )
        result: dict[str, Any] = {
            "exporter": self.name,
            "semconv_version": GEN_AI_SEMCONV_VERSION,
            "schema_url": OTEL_SCHEMA_URL,
            "payload": payload,
            "delivered": False,
        }
        if endpoint:
            response = post_json(
                endpoint,
                payload,
                headers={**self.headers, **options.get("headers", {})},
                timeout=options.get("timeout", self.timeout),
                client=options.get("client", self.client),
            )
            result["delivered"] = True
            result["endpoint"] = endpoint
            result["status_code"] = response.status_code
        return result
