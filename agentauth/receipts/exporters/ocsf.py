"""OCSF export: receipts as ``ai_operation``-profiled API Activity events.

Maps a receipt bundle onto OCSF v1.8 (the release that shipped the
``ai_operation`` profile):

- every receipt → **API Activity** (class_uid 6003, category 6) carrying the
  ``ai_operation`` profile, with the tool call in ``api``, the agent in
  ``actor`` and model identity in ``ai_model`` when present;
- deny / step-up / approval-pending decisions → an additional **Detection
  Finding** (class_uid 2004, category 2), the shape OCSF v1.9-dev PR #1681
  uses for agent-threat detections.

Receipt evidence with no OCSF slot (authority, assurance, policy commitment)
rides in ``unmapped.agent_receipts``, with field names aligned to the OWASP
Agentic Top-10 decision-log recommendations (action classification,
authorization outcome, policy version, approval id, session tagging).
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

from agentauth.receipts._version import __version__
from agentauth.receipts.exporters._http import post_json

ENDPOINT_ENV = "AGENTAUTH_OCSF_ENDPOINT"

OCSF_SCHEMA_VERSION = "1.8.0"
CATEGORY_APPLICATION_ACTIVITY = 6
CLASS_API_ACTIVITY = 6003
CATEGORY_FINDINGS = 2
CLASS_DETECTION_FINDING = 2004

_ACTIVITY_CREATE = 1
_ACTIVITY_READ = 2
_ACTIVITY_UPDATE = 3
_ACTIVITY_DELETE = 4
_ACTIVITY_OTHER = 99

_SEVERITY_INFORMATIONAL = 1
_SEVERITY_MEDIUM = 3

_STATUS_SUCCESS = 1
_STATUS_FAILURE = 2

# Decision outcomes that mean the action did NOT proceed as requested.
_BLOCKING_OUTCOMES = {
    "deny",
    "pending_approval",
    "pending_step_up",
    "budget_reservation_required",
}

_SIDE_EFFECT_ACTIVITY = {
    "read_only": _ACTIVITY_READ,
    "bounded_write": _ACTIVITY_UPDATE,
    "external_side_effect": _ACTIVITY_UPDATE,
    "privileged_mutation": _ACTIVITY_DELETE,
}


def _epoch_ms(iso_timestamp: str | None) -> int:
    if iso_timestamp:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    else:
        dt = datetime.now(timezone.utc)
    return int(dt.timestamp() * 1000)


def _metadata(bundle: dict[str, Any], profiles: list[str]) -> dict[str, Any]:
    proof = bundle.get("execution_proof") or {}
    decision = bundle.get("decision") or {}
    authority = bundle.get("authority") or {}
    metadata: dict[str, Any] = {
        "version": OCSF_SCHEMA_VERSION,
        "profiles": profiles,
        "product": {
            "name": "Clay Seal Receipts",
            "vendor_name": "Clay Seal",
            "version": bundle.get("sdk_version") or __version__,
        },
    }
    if proof.get("proof_id"):
        metadata["uid"] = str(proof["proof_id"])
    session_id = decision.get("session_id") or authority.get("session_id")
    if session_id:
        metadata["correlation_uid"] = str(session_id)
    return metadata


def _unmapped(bundle: dict[str, Any]) -> dict[str, Any]:
    """Receipt evidence without an OCSF slot, named per OWASP Agentic Top-10."""
    action = bundle.get("action") or {}
    decision = bundle.get("decision") or {}
    authority = bundle.get("authority") or {}
    policy = bundle.get("policy") or {}
    assurance = bundle.get("assurance") or {}
    fields = {
        "action_classification": action.get("side_effect_level"),
        "authorization_outcome": decision.get("outcome"),
        "policy_satisfied": decision.get("policy_satisfied"),
        "policy_name": policy.get("name"),
        "policy_version": policy.get("version"),
        "policy_commitment": policy.get("commitment"),
        "approval_id": decision.get("approval_id"),
        "risk_score": decision.get("risk_score"),
        "session_id": decision.get("session_id") or authority.get("session_id"),
        "authority_version": authority.get("authority_version"),
        "assurance_tier": assurance.get("tier") or assurance.get("level"),
        "receipt_schema": bundle.get("schema"),
        "proof_id": (bundle.get("execution_proof") or {}).get("proof_id"),
        "model_provenance_hash": (bundle.get("certificate") or {}).get(
            "model_provenance_hash"
        ),
    }
    return {"agent_receipts": {k: v for k, v in fields.items() if v is not None}}


def _actor(bundle: dict[str, Any]) -> dict[str, Any]:
    certificate = bundle.get("certificate") or {}
    authority = bundle.get("authority") or {}
    app_name = (
        certificate.get("display_name")
        or authority.get("agent_type")
        or "agent"
    )
    actor: dict[str, Any] = {"app_name": str(app_name)}
    agent_uid = certificate.get("agent_id") or authority.get("authority_id")
    if agent_uid:
        actor["app_uid"] = str(agent_uid)
    return actor


def _ai_model(bundle: dict[str, Any]) -> dict[str, Any] | None:
    """OCSF ``ai_model`` requires name + ai_provider, so it is only emitted when
    the receipt actually knows the model's identity; the provenance *hash* is
    always available in ``unmapped.agent_receipts.model_provenance_hash``."""
    certificate = bundle.get("certificate") or {}
    name = certificate.get("model_id") or certificate.get("model_name")
    if not name:
        return None
    model: dict[str, Any] = {
        "name": str(name),
        "ai_provider": str(certificate.get("model_provider") or "unknown"),
    }
    uid = certificate.get("model_provenance_hash")
    if uid:
        model["uid"] = str(uid)
    return model


def bundle_to_api_activity(bundle: dict[str, Any]) -> dict[str, Any]:
    """The receipt as an OCSF API Activity (6003) event with the ai_operation profile."""
    action = bundle.get("action") or {}
    decision = bundle.get("decision") or {}
    outcome = decision.get("outcome")

    activity_id = _SIDE_EFFECT_ACTIVITY.get(
        str(action.get("side_effect_level") or ""), _ACTIVITY_OTHER
    )
    actor = _actor(bundle)
    event: dict[str, Any] = {
        "activity_id": activity_id,
        "category_uid": CATEGORY_APPLICATION_ACTIVITY,
        "class_uid": CLASS_API_ACTIVITY,
        "type_uid": CLASS_API_ACTIVITY * 100 + activity_id,
        "time": _epoch_ms(bundle.get("exported_at")),
        "severity_id": _SEVERITY_INFORMATIONAL,
        "status_id": _STATUS_FAILURE if outcome in _BLOCKING_OUTCOMES else _STATUS_SUCCESS,
        "metadata": _metadata(bundle, ["ai_operation"]),
        "actor": actor,
        # The agent runtime is where the API call originated.
        "src_endpoint": {
            key: value
            for key, value in (("name", actor.get("app_name")), ("uid", actor.get("app_uid")))
            if value
        },
        "api": {
            "operation": str(action.get("action_name") or "execute_tool"),
        },
        "unmapped": _unmapped(bundle),
    }
    if action.get("resource_type") or action.get("resource_ref"):
        event["resources"] = [
            {
                key: str(value)
                for key, value in (
                    ("type", action.get("resource_type")),
                    ("uid", action.get("resource_ref")),
                )
                if value
            }
        ]
    if action.get("action_category"):
        event["api"]["service"] = {"name": str(action["action_category"])}
    if outcome in _BLOCKING_OUTCOMES:
        reasons = decision.get("reasons") or bundle.get("policy_violations") or []
        event["api"]["response"] = {
            "error": str(outcome),
            "error_message": "; ".join(str(reason) for reason in reasons) or None,
        }
        event["api"]["response"] = {
            k: v for k, v in event["api"]["response"].items() if v is not None
        }
    model = _ai_model(bundle)
    if model is not None:
        event["ai_model"] = model
    return event


def bundle_to_detection_finding(bundle: dict[str, Any]) -> dict[str, Any] | None:
    """A Detection Finding (2004) for blocked/step-up decisions; None for allows."""
    decision = bundle.get("decision") or {}
    outcome = decision.get("outcome")
    if outcome not in _BLOCKING_OUTCOMES:
        return None
    action = bundle.get("action") or {}
    proof = bundle.get("execution_proof") or {}
    reasons = decision.get("reasons") or bundle.get("policy_violations") or []
    finding: dict[str, Any] = {
        "activity_id": _ACTIVITY_CREATE,
        "category_uid": CATEGORY_FINDINGS,
        "class_uid": CLASS_DETECTION_FINDING,
        "type_uid": CLASS_DETECTION_FINDING * 100 + _ACTIVITY_CREATE,
        "time": _epoch_ms(bundle.get("exported_at")),
        "severity_id": _SEVERITY_MEDIUM,
        "metadata": _metadata(bundle, ["ai_operation"]),
        "finding_info": {
            "title": f"Agent action {outcome}: {action.get('action_name') or 'unknown action'}",
            "uid": str(proof.get("proof_id") or ""),
            "types": ["Policy Violation"],
            "desc": "; ".join(str(reason) for reason in reasons)
            or f"decision outcome {outcome}",
        },
        "unmapped": _unmapped(bundle),
    }
    return finding


def bundle_to_ocsf_events(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """All OCSF events for a receipt: API Activity always, Detection Finding on blocks."""
    events = [bundle_to_api_activity(bundle)]
    finding = bundle_to_detection_finding(bundle)
    if finding is not None:
        events.append(finding)
    return events


class OcsfExporter:
    """``ReceiptExporter`` delivering OCSF events to an HTTP collector."""

    name = "ocsf_ai_operation"

    def __init__(
        self,
        *,
        endpoint: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        client: Any | None = None,
    ) -> None:
        self.endpoint = endpoint if endpoint is not None else os.getenv(ENDPOINT_ENV, "")
        self.headers = dict(headers or {})
        self.timeout = timeout
        self.client = client

    def export(self, bundle: dict[str, Any], **options: Any) -> dict[str, Any]:
        """Build the OCSF events; POST them (as a JSON array) when an endpoint is set."""
        endpoint = options.get("endpoint", self.endpoint)
        events = bundle_to_ocsf_events(bundle)
        result: dict[str, Any] = {
            "exporter": self.name,
            "ocsf_version": OCSF_SCHEMA_VERSION,
            "events": events,
            "delivered": False,
        }
        if endpoint:
            response = post_json(
                endpoint,
                events,
                headers={**self.headers, **options.get("headers", {})},
                timeout=options.get("timeout", self.timeout),
                client=options.get("client", self.client),
            )
            result["delivered"] = True
            result["endpoint"] = endpoint
            result["status_code"] = response.status_code
        return result
