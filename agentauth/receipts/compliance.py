"""Compliance profile mapping and SIEM export (SOTA-4)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml

from agentauth.receipts.assurance import enrich_assurance_dict
from agentauth.receipts.audit import count_valid_witness_cosignatures
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.receipt_schema import stored_assurance_dict

ComplianceProfile = Literal["eu-ai-act", "soc2", "iso27001"]
SiemFormat = Literal["ecs", "otel", "cef"]

SUPPORTED_PROFILES: tuple[ComplianceProfile, ...] = ("eu-ai-act", "soc2", "iso27001")
SUPPORTED_SIEM_FORMATS: tuple[SiemFormat, ...] = ("ecs", "otel", "cef")


def _repo_compliance_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "compliance"


def _normalize_profile(profile: str) -> ComplianceProfile:
    normalized = profile.strip().lower().replace("_", "-")
    if normalized not in SUPPORTED_PROFILES:
        supported = ", ".join(SUPPORTED_PROFILES)
        raise ValueError(f"unsupported compliance profile {profile!r}; choose: {supported}")
    return normalized  # type: ignore[return-value]


def load_compliance_profile(profile: str) -> dict[str, Any]:
    """Load a compliance crosswalk YAML from ``compliance/<profile>.yaml``."""
    name = _normalize_profile(profile)
    path = _repo_compliance_dir() / f"{name}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"compliance profile not found: {path}")
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"invalid compliance profile document: {path}")
    return data


def _bundle_view(bundle: dict[str, Any]) -> dict[str, Any]:
    """Flatten v2 assurance and other nested fields for dot-path lookup."""
    view = dict(bundle)
    assurance = stored_assurance_dict(bundle)
    if assurance is not None:
        view["assurance"] = enrich_assurance_dict(assurance)
    evidence = bundle.get("evidence")
    if isinstance(evidence, dict) and "assurance" in evidence and "assurance" not in view:
        view["assurance"] = enrich_assurance_dict(evidence["assurance"])
    return view


def _dig(obj: dict[str, Any], path: str) -> Any:
    current: Any = obj
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, dict, tuple, set)):
        return len(value) > 0
    return True


def _resolve_field(view: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    sources = [str(item) for item in spec.get("sources", [])]
    rule = str(spec.get("rule", "required"))
    values = {source: _dig(view, source) for source in sources}

    if rule == "any_present":
        present = any(_is_present(value) for value in values.values())
    elif rule == "all_present":
        present = bool(sources) and all(_is_present(value) for value in values.values())
    elif rule == "required":
        present = bool(sources) and _is_present(values.get(sources[0]))
    else:
        raise ValueError(f"unknown compliance field rule: {rule!r}")

    primary = next((value for value in values.values() if _is_present(value)), None)
    return {
        "label": spec.get("label"),
        "present": present,
        "values": values,
        "value": primary,
    }


def validate_profile_completeness(
    mapped_fields: dict[str, dict[str, Any]],
    profile_doc: dict[str, Any],
) -> dict[str, Any]:
    missing = [
        key
        for key, payload in mapped_fields.items()
        if not payload.get("present")
    ]
    return {
        "complete": len(missing) == 0,
        "missing_fields": missing,
        "present_fields": [key for key in mapped_fields if key not in missing],
        "required_count": len(profile_doc.get("required_fields", [])),
    }


def export_compliance_mapped(
    bundle: dict[str, Any],
    profile: str,
) -> dict[str, Any]:
    """Map a receipt bundle onto a compliance profile crosswalk."""
    from agentauth.receipts.export import verify_receipt_bundle

    profile_doc = load_compliance_profile(profile)
    view = _bundle_view(bundle)
    proof = ExecutionProof.from_dict(bundle["execution_proof"])
    live_verification = verify_receipt_bundle(bundle)

    mapped_fields: dict[str, dict[str, Any]] = {}
    for spec in profile_doc.get("required_fields", []):
        key = str(spec["key"])
        mapped_fields[key] = _resolve_field(view, spec)

    completeness = validate_profile_completeness(mapped_fields, profile_doc)
    completeness["cryptographically_verified"] = live_verification["valid"]
    completeness["verification_issue_count"] = len(live_verification.get("issues", []))

    controls: dict[str, dict[str, Any]] = {}
    for control_id, mapping in profile_doc.get("controls", {}).items():
        controls[control_id] = {
            field_key: mapped_fields[field_key]
            for field_key in mapping.values()
            if field_key in mapped_fields
        }

    return {
        "profile": profile_doc.get("profile", _normalize_profile(profile)),
        "profile_title": profile_doc.get("title"),
        "profile_version": profile_doc.get("version", 1),
        "framework_refs": list(profile_doc.get("framework_refs", [])),
        "mapped_at": datetime.now(timezone.utc).isoformat(),
        "proof_id": str(proof.proof_id),
        "schema": bundle.get("schema"),
        "fields": mapped_fields,
        "controls": controls,
        "completeness": completeness,
        "verification": {
            "valid": live_verification["valid"],
            "issue_count": len(live_verification.get("issues", [])),
        },
    }


def _base_event_fields(bundle: dict[str, Any]) -> dict[str, Any]:
    from agentauth.receipts.export import verify_receipt_bundle

    proof = ExecutionProof.from_dict(bundle["execution_proof"])
    view = _bundle_view(bundle)
    policy = bundle.get("policy", {})
    decision = bundle.get("decision", {})
    authority = bundle.get("authority", {})
    action = bundle.get("action", {})
    assurance = view.get("assurance", {})
    live_verification = verify_receipt_bundle(bundle)
    verified_extensions = _verified_extension_fields(
        bundle,
        proof=proof,
        live_verification=live_verification,
    )
    return {
        "proof_id": str(proof.proof_id),
        "exported_at": bundle.get("exported_at"),
        "sdk_version": bundle.get("sdk_version"),
        "schema": bundle.get("schema"),
        "agent_id": _dig(view, "certificate.agent_id"),
        "model_provenance_hash": _dig(view, "certificate.model_provenance_hash"),
        "policy_name": policy.get("name"),
        "policy_version": policy.get("version"),
        "policy_commitment": proof.policy_commitment,
        "context_hash": proof.context_hash,
        "output_hash": proof.output_hash,
        "decision_outcome": decision.get("outcome", proof.decision_outcome.value),
        "policy_satisfied": decision.get("policy_satisfied", proof.policy_satisfied),
        "recommended_action": decision.get("recommended_action"),
        "approval_state": decision.get("approval_state"),
        "authority_id": authority.get("authority_id"),
        "session_id": authority.get("session_id", proof.session_id),
        "action_name": action.get("action_name"),
        "assurance_level": assurance.get("level"),
        "assurance_tier": assurance.get("tier"),
        "assurance_tier_ordinal": assurance.get("tier_ordinal"),
        "verification_valid": live_verification["valid"],
        "verification_issue_count": len(live_verification.get("issues", [])),
        "stored_verification_valid": bundle.get("verification", {}).get("valid"),
        "signature_count": len(bundle.get("signatures", [])),
        "verified_extensions": verified_extensions,
    }


def _verified_extension_fields(
    bundle: dict[str, Any],
    *,
    proof: ExecutionProof,
    live_verification: dict[str, Any],
) -> dict[str, Any]:
    """Optional SOTA extension fields, only surfaced after live verification passes."""
    if not live_verification.get("valid"):
        return {}

    extensions: dict[str, Any] = {}
    mandate = bundle.get("mandate")
    if isinstance(mandate, dict):
        if mandate.get("grant_id"):
            extensions["mandate_grant_id"] = mandate["grant_id"]
        if mandate.get("commitment"):
            extensions["mandate_commitment"] = mandate["commitment"]

    audit_inclusion = bundle.get("audit_inclusion")
    if isinstance(audit_inclusion, dict):
        checkpoint = audit_inclusion.get("checkpoint")
        extensions["audit_inclusion_present"] = True
        if isinstance(checkpoint, dict):
            extensions["audit_checkpoint_signed"] = bool(checkpoint.get("signature"))
            extensions["audit_witness_cosignature_count"] = count_valid_witness_cosignatures(
                checkpoint
            )

    session_proof = bundle.get("session_proof")
    if isinstance(session_proof, dict):
        extensions["session_proof_present"] = True
        if session_proof.get("mode") is not None:
            extensions["session_proof_mode"] = session_proof.get("mode")

    if proof.bundle.composed_proof:
        extensions["recursive_composition_present"] = True
    if proof.bundle.verification_key_id:
        extensions["recursive_verification_key_id"] = proof.bundle.verification_key_id

    tee_quote = proof.bundle.tee_quote
    if isinstance(tee_quote, dict) and tee_quote:
        extensions["tee_quote_present"] = True
        if tee_quote.get("kind") is not None:
            extensions["tee_quote_kind"] = tee_quote.get("kind")
        elif tee_quote.get("format") is not None:
            extensions["tee_quote_kind"] = tee_quote.get("format")
        claims = sorted(str(key) for key in tee_quote.keys())
        if claims:
            extensions["tee_claim_keys"] = claims

    return extensions


def export_siem_ecs(bundle: dict[str, Any]) -> dict[str, Any]:
    """Elastic Common Schema (ECS) shaped log record."""
    base = _base_event_fields(bundle)
    timestamp = base["exported_at"] or datetime.now(timezone.utc).isoformat()
    outcome = base["decision_outcome"] or "unknown"
    agent_receipts = {
        "proof_id": base["proof_id"],
        "schema": base["schema"],
        "context_hash": base["context_hash"],
        "output_hash": base["output_hash"],
        "policy_commitment": base["policy_commitment"],
        "model_provenance_hash": base["model_provenance_hash"],
        "assurance_level": base["assurance_level"],
        "assurance_tier": base["assurance_tier"],
        "assurance_tier_ordinal": base["assurance_tier_ordinal"],
        "verification_valid": base["verification_valid"],
        "verification_issue_count": base["verification_issue_count"],
        "stored_verification_valid": base["stored_verification_valid"],
        "signature_count": base["signature_count"],
        "approval_state": base["approval_state"],
        "recommended_action": base["recommended_action"],
    }
    if base["verified_extensions"]:
        agent_receipts["verified_extensions"] = base["verified_extensions"]

    return {
        "@timestamp": timestamp,
        "event.kind": "event",
        "event.category": ["process"],
        "event.type": ["info"],
        "event.action": base["action_name"] or "agent.action",
        "event.outcome": outcome,
        "agent.id": base["agent_id"],
        "agent.version": base["sdk_version"],
        "rule.name": base["policy_name"],
        "rule.uuid": base["policy_commitment"],
        "session.id": base["session_id"],
        "user.id": base["authority_id"],
        "hash.sha256": base["output_hash"],
        "agent_receipts": agent_receipts,
    }


def export_siem_otel(bundle: dict[str, Any]) -> dict[str, Any]:
    """OpenTelemetry log record JSON representation (GenAI semconv + legacy agent.receipt.*)."""
    from agentauth.receipts.otel import receipt_to_otel_attributes, receipt_to_otel_events

    base = _base_event_fields(bundle)
    timestamp = base["exported_at"] or datetime.now(timezone.utc).isoformat()
    gen_ai = receipt_to_otel_attributes(bundle)
    attributes = {
        "agent.receipt.proof_id": base["proof_id"],
        "agent.receipt.schema": base["schema"],
        "agent.receipt.action": base["action_name"],
        "agent.receipt.decision_outcome": base["decision_outcome"],
        "agent.receipt.policy_commitment": base["policy_commitment"],
        "agent.receipt.context_hash": base["context_hash"],
        "agent.receipt.output_hash": base["output_hash"],
        "agent.receipt.assurance_tier": base["assurance_tier"],
        "agent.receipt.verification_valid": base["verification_valid"],
        "agent.receipt.approval_state": base["approval_state"],
    }
    attributes.update(gen_ai)
    for key, value in base["verified_extensions"].items():
        attributes[f"agent.receipt.extension.{key}"] = value

    return {
        "timestamp": timestamp,
        "severity_text": "INFO",
        "body": f"agent receipt {base['proof_id']}",
        "resource": {
            "service.name": "agent-receipts",
            "service.version": base["sdk_version"],
            "agent.id": base["agent_id"],
        },
        "attributes": attributes,
        "events": receipt_to_otel_events(bundle),
    }


def export_siem_cef(bundle: dict[str, Any]) -> str:
    """ArcSight CEF single-line event."""
    base = _base_event_fields(bundle)

    def esc(value: Any) -> str:
        text = str(value if value is not None else "")
        return (
            text.replace("\\", "\\\\")
            .replace("|", "\\|")
            .replace("=", "\\=")
        )

    extensions = " ".join(
        f"{key}={esc(value)}"
        for key, value in {
            "proofId": base["proof_id"],
            "outcome": base["decision_outcome"],
            "policyCommitment": base["policy_commitment"],
            "contextHash": base["context_hash"],
            "outputHash": base["output_hash"],
            "assuranceTier": base["assurance_tier"],
            "verificationValid": base["verification_valid"],
            "sessionId": base["session_id"],
            "agentId": base["agent_id"],
            **{
                "".join(
                    word.capitalize() if i else word
                    for i, word in enumerate(extension_key.split("_"))
                ): extension_value
                for extension_key, extension_value in base["verified_extensions"].items()
            },
        }.items()
        if value is not None
    )
    outcome = base["decision_outcome"] or "unknown"
    severity = 3 if outcome == "allow" else 6
    return (
        f"CEF:0|Agent Receipts|Receipt|{esc(base['sdk_version'])}|agent_action|"
        f"Agent action receipt|{severity}|{extensions}"
    )


def export_siem_record(
    bundle: dict[str, Any],
    *,
    format: SiemFormat | str = "ecs",
) -> dict[str, Any] | str:
    normalized = str(format).lower()
    if normalized == "ecs":
        return export_siem_ecs(bundle)
    if normalized == "otel":
        return export_siem_otel(bundle)
    if normalized == "cef":
        return export_siem_cef(bundle)
    supported = ", ".join(SUPPORTED_SIEM_FORMATS)
    raise ValueError(f"unsupported SIEM format {format!r}; choose: {supported}")
