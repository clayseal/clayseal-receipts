"""Infer approval state from decision outcome."""

from __future__ import annotations

from agentauth.core.decision import ApprovalState
from agentauth.receipts.proof import DecisionOutcome


def infer_approval_state(
    outcome: DecisionOutcome,
    *,
    explicit: ApprovalState | None = None,
) -> ApprovalState:
    if explicit is not None:
        return explicit
    if outcome == DecisionOutcome.PENDING_APPROVAL:
        return ApprovalState.PENDING
    if outcome == DecisionOutcome.PENDING_STEP_UP:
        return ApprovalState.REQUIRED
    if outcome == DecisionOutcome.DENY:
        return ApprovalState.NOT_REQUIRED
    return ApprovalState.NOT_REQUIRED
