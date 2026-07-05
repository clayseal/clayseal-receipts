from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol, runtime_checkable

from agentauth.core.signing import SigningKey
from agentauth.core.decision import Obligation
from agentauth.receipts.permit import SignedToolPermit, issue_tool_permit
from agentauth.receipts.proof import DecisionOutcome

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.core.runtime import AuthorityContext, ExecutionContext, SideEffectLevel


class SandboxEnforcement(str, Enum):
    """Governor enforcement decision (binding)."""

    ALLOW = "allow"
    DENY = "deny"
    STEP_UP = "step_up"


@dataclass(frozen=True)
class SandboxGovernorResult:
    enforcement: SandboxEnforcement = SandboxEnforcement.ALLOW
    extra_violations: list[str] = field(default_factory=list)
    obligations: list[Obligation] = field(default_factory=list)
    authority_patch: dict[str, object] | None = None
    tool_permit: dict[str, object] | None = None
    commit_required: bool = False

    def decision_outcome(self) -> DecisionOutcome:
        if self.enforcement == SandboxEnforcement.DENY:
            return DecisionOutcome.DENY
        if self.enforcement == SandboxEnforcement.STEP_UP:
            return DecisionOutcome.PENDING_STEP_UP
        return DecisionOutcome.ALLOW

    def is_blocking(self) -> bool:
        return self.enforcement in {SandboxEnforcement.DENY, SandboxEnforcement.STEP_UP}


@runtime_checkable
class SandboxGovernor(Protocol):
    """
    Dynamic sandbox governor: binding enforcement decision for a step/tool call.

    This component is allowed to incorporate behavior-monitor signals, but must be safe
    under monitor failure (false negatives/positives).
    """

    def decide(
        self,
        ctx: ExecutionContext,
        *,
        monitor: BehaviorMonitorResult | None = None,
        structural_violations: list[str] | None = None,
    ) -> SandboxGovernorResult: ...


class NullSandboxGovernor:
    """Default governor that never blocks and emits no patches."""

    def decide(
        self,
        ctx: ExecutionContext,
        *,
        monitor: BehaviorMonitorResult | None = None,
        structural_violations: list[str] | None = None,
    ) -> SandboxGovernorResult:
        return SandboxGovernorResult()


class RuleBasedSandboxGovernor:
    """
    Minimal governor for tests and prototypes.

    Supports:
    - tool allow/deny/step-up lists
    - step-up on side-effect levels
    - optional per-call "lease" attachment via authority.expires_at
    """

    def __init__(
        self,
        *,
        deny_tools: set[str] | None = None,
        step_up_tools: set[str] | None = None,
        step_up_side_effect_levels: set[SideEffectLevel] | None = None,
        permit_required_tools: set[str] | None = None,
        permit_required_side_effect_levels: set[SideEffectLevel] | None = None,
        permit_ttl_seconds: int | None = None,
        permit_signing_key: SigningKey | None = None,
        permit_missing_enforcement: SandboxEnforcement = SandboxEnforcement.DENY,
        commit_required_tools: set[str] | None = None,
        commit_required_side_effect_levels: set[SideEffectLevel] | None = None,
        commit_implies_permit_required: bool = True,
        lease_required_tools: set[str] | None = None,
        lease_required_side_effect_levels: set[SideEffectLevel] | None = None,
        lease_ttl_seconds: int | None = None,
        lease_call_budget: int | None = None,
        bump_authority_version_on_lease: bool = True,
        require_active_lease: bool = False,
        lease_missing_enforcement: SandboxEnforcement = SandboxEnforcement.STEP_UP,
        lease_expired_enforcement: SandboxEnforcement = SandboxEnforcement.STEP_UP,
        lease_exhausted_enforcement: SandboxEnforcement = SandboxEnforcement.STEP_UP,
        require_query_bound_lease: bool = False,
        lease_query_mismatch_enforcement: SandboxEnforcement = SandboxEnforcement.STEP_UP,
        require_lease_call_budget: bool = False,
        consume_lease_call_budget: bool = True,
        honor_monitor_recommendations: bool = False,
        suspend_lease_renewal_on_suspicion: bool = True,
    ) -> None:
        self.deny_tools = set(deny_tools or set())
        self.step_up_tools = set(step_up_tools or set())
        self.step_up_levels = set(step_up_side_effect_levels or set())
        self.permit_required_tools = set(permit_required_tools or set())
        self.permit_required_levels = set(permit_required_side_effect_levels or set())
        self.permit_ttl_seconds = permit_ttl_seconds
        self.permit_signing_key = permit_signing_key
        self.permit_missing_enforcement = permit_missing_enforcement
        self.commit_required_tools = set(commit_required_tools or set())
        self.commit_required_levels = set(commit_required_side_effect_levels or set())
        self.commit_implies_permit_required = commit_implies_permit_required
        self.lease_required_tools = set(lease_required_tools or set())
        self.lease_required_levels = set(lease_required_side_effect_levels or set())
        self.lease_ttl_seconds = lease_ttl_seconds
        self.lease_call_budget = lease_call_budget
        self.bump_authority_version_on_lease = bump_authority_version_on_lease
        self.require_active_lease = require_active_lease
        self.lease_missing_enforcement = lease_missing_enforcement
        self.lease_expired_enforcement = lease_expired_enforcement
        self.lease_exhausted_enforcement = lease_exhausted_enforcement
        self.require_query_bound_lease = require_query_bound_lease
        self.lease_query_mismatch_enforcement = lease_query_mismatch_enforcement
        self.require_lease_call_budget = require_lease_call_budget
        self.consume_lease_call_budget = consume_lease_call_budget
        self.honor_monitor_recommendations = honor_monitor_recommendations
        self.suspend_lease_renewal_on_suspicion = suspend_lease_renewal_on_suspicion

    @staticmethod
    def _is_expired(expires_at: str | None) -> bool:
        if not expires_at or not isinstance(expires_at, str):
            return True
        try:
            parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return True
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc) <= datetime.now(timezone.utc)

    def decide(
        self,
        ctx: ExecutionContext,
        *,
        monitor: BehaviorMonitorResult | None = None,
        structural_violations: list[str] | None = None,
    ) -> SandboxGovernorResult:
        tool_name = ctx.action.action_name.rsplit("/", 1)[-1]

        violations: list[str] = []
        enforcement = SandboxEnforcement.ALLOW
        signed_permit: SignedToolPermit | None = None

        permit_required = False
        if tool_name in self.permit_required_tools:
            permit_required = True
        if ctx.action.side_effect_level in self.permit_required_levels:
            permit_required = True

        commit_required = False
        if tool_name in self.commit_required_tools:
            commit_required = True
        if ctx.action.side_effect_level in self.commit_required_levels:
            commit_required = True
        if commit_required and self.commit_implies_permit_required:
            permit_required = True

        lease_required = self.require_active_lease
        if tool_name in self.lease_required_tools:
            lease_required = True
        if ctx.action.side_effect_level in self.lease_required_levels:
            lease_required = True

        if permit_required:
            if not self.permit_signing_key or not self.permit_ttl_seconds:
                enforcement = self.permit_missing_enforcement
                violations.append("sandbox: missing tool permit signer/config")
            elif self.permit_ttl_seconds <= 0:
                enforcement = self.permit_missing_enforcement
                violations.append("sandbox: invalid permit TTL")
            else:
                signed_permit = issue_tool_permit(
                    ctx,
                    key=self.permit_signing_key,
                    ttl_seconds=int(self.permit_ttl_seconds),
                )

        if lease_required:
            expires_at = ctx.authority.expires_at
            remaining_calls = ctx.authority.lease_remaining_calls

            if self.require_query_bound_lease:
                if not ctx.query_id:
                    enforcement = self.lease_query_mismatch_enforcement
                    violations.append("sandbox: missing query_id for query-bound lease")
                elif ctx.query_id != ctx.authority.lease_query_id:
                    enforcement = self.lease_query_mismatch_enforcement
                    violations.append("sandbox: query_id does not match lease_query_id")

            if self.require_lease_call_budget and remaining_calls is None:
                enforcement = self.lease_missing_enforcement
                violations.append("sandbox: missing lease call budget (authority.lease_remaining_calls)")
            if remaining_calls is not None and remaining_calls <= 0:
                enforcement = self.lease_exhausted_enforcement
                violations.append("sandbox: capability lease exhausted (authority.lease_remaining_calls)")

            if expires_at and self._is_expired(expires_at):
                enforcement = self.lease_expired_enforcement
                violations.append("sandbox: capability lease expired (authority.expires_at)")
            elif not expires_at and remaining_calls is None:
                enforcement = self.lease_missing_enforcement
                violations.append("sandbox: missing capability lease (authority.expires_at)")

        if tool_name in self.deny_tools:
            enforcement = SandboxEnforcement.DENY
            violations.append(f"sandbox: tool {tool_name} denied by governor")
        elif tool_name in self.step_up_tools:
            enforcement = SandboxEnforcement.STEP_UP
            violations.append(f"sandbox: tool {tool_name} requires step-up")
        elif ctx.action.side_effect_level in self.step_up_levels:
            enforcement = SandboxEnforcement.STEP_UP
            violations.append(
                f"sandbox: side_effect_level {ctx.action.side_effect_level.value} requires step-up"
            )

        if self.honor_monitor_recommendations and monitor is not None:
            rec = monitor.recommendation.value if monitor.recommendation else None
            if rec == "deny":
                if enforcement != SandboxEnforcement.DENY:
                    enforcement = SandboxEnforcement.DENY
                    violations.append("sandbox: denied by behavior monitor recommendation")
            elif rec == "step_up":
                if enforcement == SandboxEnforcement.ALLOW:
                    enforcement = SandboxEnforcement.STEP_UP
                    violations.append("sandbox: step-up required by behavior monitor recommendation")

        patch: dict[str, object] | None = None
        if enforcement == SandboxEnforcement.ALLOW:
            patch = {}

            issued_ttl = self.lease_ttl_seconds is not None and self.lease_ttl_seconds > 0
            issued_budget = self.lease_call_budget is not None and self.lease_call_budget > 0
            should_issue_renewal = issued_ttl or issued_budget

            if (
                should_issue_renewal
                and self.suspend_lease_renewal_on_suspicion
                and monitor is not None
                and monitor.recommendation is not None
                and monitor.recommendation != BehaviorRecommendation.ALLOW
            ):
                should_issue_renewal = False

            if should_issue_renewal:
                if issued_ttl:
                    expires_at = datetime.now(timezone.utc) + timedelta(
                        seconds=int(self.lease_ttl_seconds or 0)
                    )
                    patch["expires_at"] = expires_at.isoformat()
                if issued_budget:
                    patch["lease_remaining_calls"] = int(self.lease_call_budget or 0)
                if self.require_query_bound_lease and ctx.query_id:
                    patch["lease_query_id"] = ctx.query_id
                if self.bump_authority_version_on_lease:
                    patch["authority_version"] = int(ctx.authority.authority_version) + 1

            if self.consume_lease_call_budget and lease_required:
                starting_budget = patch.get(
                    "lease_remaining_calls", ctx.authority.lease_remaining_calls
                )
                if starting_budget is not None:
                    patch["lease_remaining_calls"] = max(0, int(starting_budget) - 1)

            if not patch:
                patch = None

        return SandboxGovernorResult(
            enforcement=enforcement,
            extra_violations=violations,
            obligations=[],
            authority_patch=patch,
            tool_permit=signed_permit.to_dict() if signed_permit is not None else None,
            commit_required=commit_required,
        )


def apply_authority_patch(authority: AuthorityContext, patch: dict[str, object] | None) -> None:
    if not patch:
        return
    for key, value in patch.items():
        if not hasattr(authority, key):
            continue
        setattr(authority, key, value)  # type: ignore[arg-type]
