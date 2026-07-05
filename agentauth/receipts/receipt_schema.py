"""Receipt bundle schema v1/v2 helpers (L4-1)."""

from __future__ import annotations

from typing import Any, Literal

from agentauth.receipts.assurance import assurance_from_proof
from agentauth.receipts.evidence import evidence_block_from_run
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.wrapper import RunResult

RECEIPT_BUNDLE_SCHEMA_V1 = "agent-receipts.receipt-bundle.v1"
RECEIPT_BUNDLE_SCHEMA_V2 = "agent-receipts.receipt-bundle.v2"

# Backward-compatible alias used by existing imports.
RECEIPT_BUNDLE_SCHEMA = RECEIPT_BUNDLE_SCHEMA_V1

SUPPORTED_RECEIPT_BUNDLE_SCHEMAS = (
    RECEIPT_BUNDLE_SCHEMA_V1,
    RECEIPT_BUNDLE_SCHEMA_V2,
)

SchemaVersion = Literal["v1", "v2"]


def schema_id(version: SchemaVersion) -> str:
    return RECEIPT_BUNDLE_SCHEMA_V2 if version == "v2" else RECEIPT_BUNDLE_SCHEMA_V1


def is_supported_schema(schema: str | None) -> bool:
    return schema in SUPPORTED_RECEIPT_BUNDLE_SCHEMAS


def policy_violations_from_bundle(bundle: dict[str, Any]) -> list[str]:
    decision = bundle.get("decision", {})
    if decision.get("violations") is not None:
        return list(decision["violations"])
    return list(bundle.get("policy_violations", []))


def stored_assurance_dict(bundle: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(bundle.get("assurance"), dict):
        return bundle["assurance"]
    evidence = bundle.get("evidence", {})
    if isinstance(evidence, dict) and isinstance(evidence.get("assurance"), dict):
        return evidence["assurance"]
    if "execution_proof" in bundle:
        proof = ExecutionProof.from_dict(bundle["execution_proof"])
        return assurance_from_proof(proof).to_dict()
    return None


def build_v2_sections(
    result: RunResult,
    *,
    assurance: dict[str, Any],
    authority: dict[str, Any],
    action: dict[str, Any],
    execution_context: dict[str, Any],
    budgets: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble required v2 sections from a run result."""
    decision = result.decision.to_dict()
    evidence = evidence_block_from_run(result)
    evidence["assurance"] = assurance

    sections: dict[str, Any] = {
        "decision": decision,
        "authority": authority,
        "action": action,
        "evidence": evidence,
    }

    session_id = result.session_id
    if session_id is not None:
        sections["session"] = {
            "session_id": session_id,
            "authority_version": result.authority_version,
        }

    approval = result.decision.approval_state.value
    metadata = result.decision.approval_metadata
    if approval != "not_required" or metadata is not None:
        sections["approval"] = {
            "state": approval,
            "metadata": metadata.to_dict() if metadata else None,
        }

    effects = [item.to_dict() for item in result.decision.budget_effects]
    budget_section = result.decision.budget_section()
    if budgets or budget_section:
        section: dict[str, Any] = {"items": list(budgets or [])}
        if budget_section:
            section["effects"] = budget_section["effects"]
            section["summary"] = result.decision.budget_summary_dict()
        elif effects:
            section["effects"] = effects
        sections["budget"] = section

    # Retained for replay helpers; not a required v2 section.
    sections["execution_context"] = execution_context
    return sections


def migrate_v1_to_v2(bundle: dict[str, Any]) -> dict[str, Any]:
    """Upgrade a v1 bundle to the v2 layout without re-running the agent."""
    if bundle.get("schema") == RECEIPT_BUNDLE_SCHEMA_V2:
        return dict(bundle)

    migrated = {key: value for key, value in bundle.items()}
    decision = dict(migrated.get("decision", {}))
    if "violations" not in decision:
        decision["violations"] = list(migrated.get("policy_violations", []))
    if migrated.get("recommended_action") and not decision.get("recommended_action"):
        decision["recommended_action"] = migrated["recommended_action"]
    migrated["decision"] = decision

    evidence = dict(migrated.get("evidence", {}))
    if migrated.get("assurance"):
        evidence["assurance"] = migrated["assurance"]
    if not evidence.get("decision_record") and decision:
        evidence["decision_record"] = {
            "outcome": decision.get("outcome"),
            "policy_satisfied": decision.get("policy_satisfied"),
            "violations": list(decision.get("violations", [])),
            "obligations": list(decision.get("obligations", [])),
            "recommended_action": decision.get("recommended_action"),
            "approval_state": decision.get("approval_state"),
            "approval_metadata": decision.get("approval_metadata"),
            "authority": {
                "authority_id": migrated.get("authority", {}).get("authority_id"),
                "authority_version": decision.get("authority_version"),
                "session_id": decision.get("session_id"),
            },
        }
    if not evidence.get("summary") and "execution_proof" in migrated:
        proof = ExecutionProof.from_dict(migrated["execution_proof"])
        from agentauth.receipts.evidence import EvidenceSummary

        evidence["summary"] = EvidenceSummary.from_proof(proof).to_dict()
    migrated["evidence"] = evidence

    session_id = decision.get("session_id")
    if session_id and "session" not in migrated:
        migrated["session"] = {
            "session_id": session_id,
            "authority_version": decision.get("authority_version", 1),
        }

    approval_state = decision.get("approval_state")
    if approval_state and approval_state != "not_required" and "approval" not in migrated:
        migrated["approval"] = {
            "state": approval_state,
            "metadata": decision.get("approval_metadata"),
        }

    effects = decision.get("budget_effects", [])
    if (migrated.get("budgets") or effects) and "budget" not in migrated:
        from agentauth.core.decision import DecisionResult

        dr = DecisionResult.from_dict(decision) if decision.get("outcome") else None
        budget_block: dict[str, Any] = {
            "items": list(migrated.get("budgets", [])),
            "effects": list(effects),
        }
        if dr is not None:
            section = dr.budget_section()
            if section and section.get("summary"):
                budget_block["summary"] = section["summary"]
        migrated["budget"] = budget_block

    for key in ("policy_violations", "recommended_action", "assurance", "budgets"):
        migrated.pop(key, None)

    migrated["schema"] = RECEIPT_BUNDLE_SCHEMA_V2
    return migrated


def required_sections_present(bundle: dict[str, Any]) -> list[str]:
    """Return names of missing required sections for v2 bundles."""
    if bundle.get("schema") != RECEIPT_BUNDLE_SCHEMA_V2:
        return []
    missing: list[str] = []
    for section in ("execution_proof", "decision", "authority", "action", "evidence"):
        if section not in bundle:
            missing.append(section)
    evidence = bundle.get("evidence", {})
    if not isinstance(evidence, dict) or "summary" not in evidence:
        missing.append("evidence.summary")
    return missing
