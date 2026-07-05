"""PolicyEngine plugin for Devin PR-gate structural invariants (SM-8)."""

from __future__ import annotations

from typing import Any

from agentauth.core.decision import DecisionResult
from agentauth.receipts.policy import Policy
from agentauth.receipts.policy_engine import PolicyEngine, YamlPolicyEngine
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.runtime import ExecutionContext
from agentauth.receipts.structural_invariants import PrGateEvidence, evaluate_pr_gate


class InvariantPolicyEngine:
    """Compose YAML policy checks with ``pr_gate`` structural invariant evaluation."""

    def __init__(
        self,
        policy: Policy,
        *,
        inner: PolicyEngine | None = None,
    ) -> None:
        self.policy = policy
        self.inner = inner or YamlPolicyEngine(policy)

    def evaluate(
        self,
        output: dict[str, Any],
        *,
        execution_context: ExecutionContext | None = None,
        extra_violations: list[str] | None = None,
    ) -> DecisionResult:
        violations = list(extra_violations or [])
        review_flags: list[dict[str, Any]] = []
        if execution_context is not None:
            authorization = execution_context.authorization
            if isinstance(authorization, dict):
                raw = authorization.get("pr_gate")
                if isinstance(raw, dict):
                    evaluation = evaluate_pr_gate(PrGateEvidence.from_dict(raw))
                    violations.extend(evaluation.violations)
                    review_flags.extend(evaluation.flags)

        base = self.inner.evaluate(
            output,
            execution_context=execution_context,
            extra_violations=violations,
        )
        if not review_flags or not base.policy_satisfied:
            return base

        outcome = base.outcome
        if outcome == DecisionOutcome.ALLOW:
            outcome = DecisionOutcome.ALLOW_WITH_REVIEW
        return DecisionResult(
            outcome=outcome,
            policy_satisfied=base.policy_satisfied,
            violations=list(base.violations),
            obligations=list(base.obligations),
            authority_version=base.authority_version,
            session_id=base.session_id,
            recommended_action=base.recommended_action or "human_review_recommended",
            approval_state=base.approval_state,
            approval_metadata=base.approval_metadata,
            budget_effects=list(base.budget_effects),
        )


def pr_gate_engine(policy: Policy) -> InvariantPolicyEngine:
    return InvariantPolicyEngine(policy)
