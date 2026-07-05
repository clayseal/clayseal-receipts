"""OpenTelemetry GenAI semantic-convention mapping for receipts (SOTA-13).

Maps a receipt bundle's evidence onto OpenTelemetry **GenAI** semantic-convention
attributes (`gen_ai.*`) so a receipt drops into existing agent-observability / SIEM
pipelines without translation. Fields with no GenAI equivalent — our authority,
decision, assurance and integrity evidence — are emitted under an `agent_receipts.*`
namespace rather than forced into a `gen_ai.*` slot (the honest crosswalk gap).

See [docs/otel_genai_mapping.md](../docs/otel_genai_mapping.md) and
<https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/>.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# GenAI system identifier for our receipts.
GEN_AI_SYSTEM = "agent_receipts"


def _put(attrs: dict[str, Any], key: str, value: Any) -> None:
    if value is not None and value != "":
        attrs[key] = value


def receipt_to_otel_attributes(bundle: dict[str, Any]) -> dict[str, Any]:
    """Flatten a receipt bundle into OTel attributes (GenAI semconv + namespaced extras).

    Robust to missing sections; returns the subset that's present.
    """
    action = bundle.get("action") or {}
    authority = bundle.get("authority") or {}
    decision = bundle.get("decision") or {}
    certificate = bundle.get("certificate") or {}
    assurance = bundle.get("assurance") or {}
    execution_context = bundle.get("execution_context") or {}

    attrs: dict[str, Any] = {"gen_ai.system": GEN_AI_SYSTEM}

    # --- GenAI semantic conventions (gen_ai.*) ---
    # Agent action receipts are tool-execution operations.
    _put(attrs, "gen_ai.operation.name", "execute_tool")
    _put(attrs, "gen_ai.tool.name", action.get("action_name"))
    _put(attrs, "gen_ai.tool.type", action.get("action_category"))
    _put(
        attrs,
        "gen_ai.agent.id",
        certificate.get("agent_id") or authority.get("authority_id"),
    )
    _put(attrs, "gen_ai.agent.name", certificate.get("display_name") or authority.get("agent_type"))
    _put(
        attrs,
        "gen_ai.conversation.id",
        decision.get("session_id") or authority.get("session_id"),
    )

    # Tool call arguments / results when present on execution_context.
    tool_input = execution_context.get("tool_input") or execution_context.get("input")
    tool_output = execution_context.get("tool_output") or execution_context.get("output")
    if tool_input is not None:
        _put(attrs, "gen_ai.tool.call.arguments", tool_input)
    if tool_output is not None:
        _put(attrs, "gen_ai.tool.call.result", tool_output)

    # --- Receipt-specific evidence (no GenAI equivalent) ---
    _put(attrs, "agent_receipts.action.resource_type", action.get("resource_type"))
    _put(attrs, "agent_receipts.action.resource_ref", action.get("resource_ref"))
    _put(attrs, "agent_receipts.action.side_effect_level", action.get("side_effect_level"))
    _put(attrs, "agent_receipts.authority.version", authority.get("authority_version"))
    _put(
        attrs,
        "agent_receipts.authority.owner",
        authority.get("owner") or authority.get("owner_ref"),
    )
    _put(
        attrs,
        "agent_receipts.authority.proof_of_possession",
        authority.get("proof_of_possession"),
    )
    _put(attrs, "agent_receipts.decision.outcome", decision.get("outcome"))
    _put(
        attrs,
        "agent_receipts.decision.policy_satisfied",
        decision.get("policy_satisfied"),
    )
    _put(attrs, "agent_receipts.assurance.tier", assurance.get("tier") or assurance.get("level"))
    _put(attrs, "agent_receipts.receipt.schema", bundle.get("schema"))
    _put(
        attrs,
        "agent_receipts.receipt.proof_id",
        (bundle.get("execution_proof") or {}).get("proof_id"),
    )
    _put(attrs, "agent_receipts.policy.commitment", (bundle.get("policy") or {}).get("commitment"))
    mandate = bundle.get("mandate")
    if isinstance(mandate, dict) and mandate.get("grant_id"):
        _put(attrs, "agent_receipts.mandate.grant_id", mandate.get("grant_id"))
    return attrs


def receipt_to_otel_events(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Emit OTel GenAI tool-use events for tool I/O on a receipt bundle."""
    action = bundle.get("action") or {}
    execution_context = bundle.get("execution_context") or {}
    attrs = receipt_to_otel_attributes(bundle)
    events: list[dict[str, Any]] = []

    tool_name = action.get("action_name")
    if tool_name:
        events.append(
            {
                "name": "gen_ai.tool.call",
                "attributes": {
                    "gen_ai.tool.name": tool_name,
                    "gen_ai.tool.type": action.get("action_category"),
                    "gen_ai.operation.name": "execute_tool",
                },
            }
        )

    tool_input = execution_context.get("tool_input") or execution_context.get("input")
    if tool_input is not None:
        events.append(
            {
                "name": "gen_ai.tool.input",
                "attributes": {
                    "gen_ai.tool.name": tool_name,
                    "gen_ai.tool.call.arguments": tool_input,
                },
            }
        )

    tool_output = execution_context.get("tool_output") or execution_context.get("output")
    if tool_output is not None:
        events.append(
            {
                "name": "gen_ai.tool.output",
                "attributes": {
                    "gen_ai.tool.name": tool_name,
                    "gen_ai.tool.call.result": tool_output,
                },
            }
        )

    if not events and attrs.get("gen_ai.tool.name"):
        events.append({"name": "gen_ai.tool.call", "attributes": attrs})

    return events


def receipt_to_otel_log_record(bundle: dict[str, Any]) -> dict[str, Any]:
    """Shape a receipt as an OTel log record (body + attributes) for SIEM/OTel ingest."""
    return {
        "body": "agent.receipt",
        "attributes": receipt_to_otel_attributes(bundle),
        "events": receipt_to_otel_events(bundle),
    }


def _nanos_timestamp(iso_timestamp: str | None = None) -> str:
    if iso_timestamp:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    else:
        dt = datetime.now(timezone.utc)
    return str(int(dt.timestamp() * 1_000_000_000))


def bundle_to_otlp_resource_logs(
    bundle: dict[str, Any],
    *,
    service_name: str = "agent-receipts",
) -> dict[str, Any]:
    """Shape a receipt as OTLP/HTTP JSON ``resourceLogs`` (no exporter dependency)."""
    base = bundle.get("exported_at")
    log_record = receipt_to_otel_log_record(bundle)
    attrs = log_record["attributes"]
    otlp_attrs = [
        {"key": key, "value": _otlp_any_value(value)}
        for key, value in sorted(attrs.items())
    ]
    events = [
        {
            "timeUnixNano": _nanos_timestamp(base),
            "name": event["name"],
            "attributes": [
                {"key": key, "value": _otlp_any_value(value)}
                for key, value in sorted(event.get("attributes", {}).items())
            ],
        }
        for event in log_record.get("events", [])
    ]
    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": service_name}},
                        {
                            "key": "gen_ai.system",
                            "value": {"stringValue": GEN_AI_SYSTEM},
                        },
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "agentauth.receipts.otel"},
                        "logRecords": [
                            {
                                "timeUnixNano": _nanos_timestamp(base),
                                "severityText": "INFO",
                                "body": {"stringValue": str(log_record["body"])},
                                "attributes": otlp_attrs,
                                "events": events,
                            }
                        ],
                    }
                ],
            }
        ]
    }


def _otlp_any_value(value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, (list, dict)):
        return {"stringValue": str(value)}
    return {"stringValue": str(value)}


def send_otlp_logs(
    endpoint: str,
    bundle: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> None:
    """POST OTLP/HTTP JSON logs to ``endpoint`` (requires ``httpx``)."""
    import httpx

    payload = bundle_to_otlp_resource_logs(bundle)
    response = httpx.post(
        endpoint,
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )
    response.raise_for_status()
