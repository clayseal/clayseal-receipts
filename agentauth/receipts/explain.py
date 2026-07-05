"""Postmortem / auditor-friendly receipt explanations (L4-7)."""

from __future__ import annotations

from typing import Any

from agentauth.receipts.assurance import AssuranceLevel, assurance_from_bundle
from agentauth.core.decision import DecisionResult
from agentauth.receipts.export import verify_receipt_bundle
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.receipt_schema import policy_violations_from_bundle


def explain_receipt_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Produce a readable explanation report from a stored receipt bundle.

    Does not re-run the agent model; summarizes evidence and verification state.
    """
    proof = ExecutionProof.from_dict(bundle["execution_proof"])
    verification = verify_receipt_bundle(bundle)
    assurance = assurance_from_bundle(bundle)
    decision_raw = bundle.get("decision", {})
    decision_obj = _decision_from_bundle(bundle, decision_raw, proof)
    authority = bundle.get("authority", {})
    action = bundle.get("action", {})
    policy = bundle.get("policy", {})
    lineage = bundle.get("lineage")
    budget = _budget_from_bundle(bundle)
    evidence_refs = bundle.get("evidence_refs")
    handoff = bundle.get("handoff")

    warnings: list[str] = []
    if not verification["valid"]:
        warnings.extend(verification.get("reasons", []))
    if not proof.policy_satisfied:
        warnings.append("policy was not satisfied at execution time")
    if assurance.level == AssuranceLevel.SHADOW:
        warnings.append("shadow mode: no cryptographic attestation attached")
    if not decision_obj.can_execute():
        warnings.append(
            "execution gate: action would not be executable under stored decision state"
        )

    return {
        "proof_id": str(proof.proof_id),
        "schema": bundle.get("schema"),
        "summary": _build_summary(proof, decision_raw, assurance),
        "decision": {
            "outcome": decision_raw.get("outcome", proof.decision_outcome.value),
            "policy_satisfied": decision_raw.get("policy_satisfied", proof.policy_satisfied),
            "violations": policy_violations_from_bundle(bundle),
            "obligations": decision_raw.get("obligations", proof.obligations),
            "recommended_action": decision_raw.get("recommended_action"),
            "approval_state": decision_raw.get("approval_state"),
            "approval_metadata": decision_raw.get("approval_metadata"),
            "budget_effects": decision_raw.get("budget_effects", []),
            "blocking_obligations": [
                item.to_dict() for item in decision_obj.blocking_obligations()
            ],
            "can_execute": decision_obj.can_execute(),
        },
        "authority": {
            "authority_id": authority.get("authority_id"),
            "authority_version": authority.get("authority_version", proof.authority_version),
            "session_id": authority.get("session_id", proof.session_id),
        },
        "lineage": lineage,
        "budget": budget,
        "evidence_refs": evidence_refs,
        "handoff": handoff,
        "evidence": bundle.get("evidence"),
        "action": action or None,
        "policy": {
            "name": policy.get("name"),
            "version": policy.get("version"),
            "commitment": proof.policy_commitment,
        },
        "assurance": assurance.to_dict(),
        "verification": {
            "valid": verification["valid"],
            "issues": verification.get("issues", []),
        },
        "warnings": warnings,
    }


def _decision_from_bundle(
    bundle: dict[str, Any],
    decision_raw: dict[str, Any],
    proof: ExecutionProof,
) -> DecisionResult:
    if decision_raw.get("outcome"):
        try:
            return DecisionResult.from_dict(decision_raw)
        except (KeyError, TypeError, ValueError):
            pass
    return DecisionResult(
        outcome=proof.decision_outcome,
        policy_satisfied=proof.policy_satisfied,
        violations=policy_violations_from_bundle(bundle),
        authority_version=proof.authority_version,
        session_id=proof.session_id,
    )


def _budget_from_bundle(bundle: dict[str, Any]) -> dict[str, Any] | None:
    if isinstance(bundle.get("budget"), dict):
        return bundle["budget"]
    legacy = bundle.get("budgets")
    if legacy:
        return {
            "items": list(legacy),
            "effects": bundle.get("decision", {}).get("budget_effects", []),
        }
    effects = bundle.get("decision", {}).get("budget_effects")
    if effects:
        return {"effects": list(effects)}
    return None


def _build_summary(
    proof: ExecutionProof,
    decision: dict[str, Any],
    assurance: Any,
) -> str:
    outcome = decision.get("outcome", proof.decision_outcome.value)
    level = assurance.level.value if hasattr(assurance, "level") else assurance.get("level")
    parts = [
        f"Action recorded as {outcome!r}",
        f"assurance level {level!r}",
    ]
    if proof.session_id:
        parts.append(f"session {proof.session_id!r}")
    if proof.authority_version != 1:
        parts.append(f"authority version {proof.authority_version}")
    return "; ".join(parts) + "."
