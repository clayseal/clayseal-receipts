"""Shared Devin PR diff evaluation (P3: gate + product use one evaluator)."""

from __future__ import annotations

from typing import Any

from agentauth.receipts.structural_invariants import (
    PrGateEvidence,
    PrGateEvaluation,
    evaluate_pr_gate,
)


def evaluate_devin_pr_diff(evidence: PrGateEvidence) -> PrGateEvaluation:
    """Single structural evaluation path for demo gate and product engine."""
    return evaluate_pr_gate(evidence)


def merge_evaluation_into_gate(
    evaluation: PrGateEvaluation,
    *,
    reasons: list[dict[str, Any]],
    flags: list[dict[str, Any]],
) -> None:
    """Append product evaluator output into gate reason/flag lists."""
    reasons.extend(evaluation.reasons)
    flags.extend(evaluation.flags)
