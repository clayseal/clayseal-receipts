"""Replay-oriented helpers for stored receipts (L3-14)."""

from __future__ import annotations

from typing import Any

from agentauth.core.decision import DecisionResult
from agentauth.receipts.evidence_refs import EvidenceRefs
from agentauth.core.lineage import AuthorityLineage
from agentauth.receipts.policy import Policy
from agentauth.receipts.policy_engine import PolicyEngine, YamlPolicyEngine
from agentauth.receipts.proof import ExecutionProof
from agentauth.receipts.receipt_schema import policy_violations_from_bundle
from agentauth.core.runtime import ExecutionContext


def rebuild_context_from_bundle(bundle: dict[str, Any]) -> dict[str, Any]:
    """Rebuild decision-relevant context from a stored receipt bundle."""
    execution_context = bundle.get("execution_context", {})
    authority = bundle.get("authority", execution_context.get("authority", {}))
    lineage_raw = bundle.get("lineage")
    return {
        "action": bundle.get("action", execution_context.get("action")),
        "authority": authority,
        "lineage": AuthorityLineage.from_dict(lineage_raw).to_dict()
        if lineage_raw
        else None,
        "decision": bundle.get("decision"),
        "policy_violations": policy_violations_from_bundle(bundle),
        "touched_resources": list(execution_context.get("touched_resources", [])),
        "evidence_refs": EvidenceRefs.from_dict(bundle["evidence_refs"]).to_dict()
        if bundle.get("evidence_refs")
        else None,
    }


def compare_stored_decision(bundle: dict[str, Any]) -> dict[str, Any]:
    """
    Compare decision metadata in the bundle against the execution proof.

    Does not re-run policy or the agent model.
    """
    proof = ExecutionProof.from_dict(bundle["execution_proof"])
    decision = bundle.get("decision", {})
    mismatches: list[str] = []

    if decision.get("outcome") != proof.decision_outcome.value:
        mismatches.append("outcome")
    if decision.get("authority_version") != proof.authority_version:
        mismatches.append("authority_version")
    if decision.get("session_id") != proof.session_id:
        mismatches.append("session_id")
    if decision.get("policy_satisfied") != proof.policy_satisfied:
        mismatches.append("policy_satisfied")

    return {
        "match": len(mismatches) == 0,
        "mismatches": mismatches,
        "stored_outcome": decision.get("outcome"),
        "proof_outcome": proof.decision_outcome.value,
    }


def re_evaluate_policy_decision(
    bundle: dict[str, Any],
    policy: Policy,
    *,
    policy_engine: PolicyEngine | None = None,
) -> dict[str, Any]:
    """
    Re-run software policy evaluation against the stored output.

    Compares the fresh ``DecisionResult`` to the stored decision block without
    re-invoking the agent model.
    """
    engine = policy_engine or YamlPolicyEngine(policy)
    output = dict(bundle.get("output", {}))
    execution_context: ExecutionContext | None = None
    if isinstance(bundle.get("execution_context"), dict):
        execution_context = ExecutionContext.from_dict(bundle["execution_context"])

    reevaluated = engine.evaluate(output, execution_context=execution_context)
    stored_raw = bundle.get("decision")
    stored = DecisionResult.from_dict(stored_raw) if stored_raw else None

    mismatches: list[str] = []
    if stored is not None:
        if stored.outcome != reevaluated.outcome:
            mismatches.append("outcome")
        if stored.policy_satisfied != reevaluated.policy_satisfied:
            mismatches.append("policy_satisfied")
        if list(stored.violations) != list(reevaluated.violations):
            mismatches.append("violations")

    return {
        "match": len(mismatches) == 0,
        "mismatches": mismatches,
        "stored": stored.to_dict() if stored else None,
        "reevaluated": reevaluated.to_dict(),
    }


def compare_budget_effects(bundle: dict[str, Any]) -> dict[str, Any]:
    """Compare budget metadata across decision and v2 budget sections."""
    decision_raw = bundle.get("decision", {})
    budget = bundle.get("budget", {})
    mismatches: list[str] = []

    if not decision_raw:
        return {"match": True, "mismatches": [], "stored_effects": [], "budget_effects": []}

    stored_effects = list(decision_raw.get("budget_effects", []))
    budget_effects = list(budget.get("effects", [])) if budget else []
    if budget_effects and budget_effects != stored_effects:
        mismatches.append("effects")

    summary = budget.get("summary") if budget else None
    recomputed: dict[str, Any] | None = None
    if decision_raw.get("outcome"):
        try:
            recomputed = DecisionResult.from_dict(decision_raw).budget_summary_dict()
        except (KeyError, TypeError, ValueError):
            recomputed = None
    if summary is not None and recomputed is not None and summary != recomputed:
        mismatches.append("summary")

    return {
        "match": len(mismatches) == 0,
        "mismatches": mismatches,
        "stored_effects": stored_effects,
        "budget_effects": budget_effects,
        "summary": summary,
        "recomputed_summary": recomputed,
    }
