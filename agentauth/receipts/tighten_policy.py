"""DP-36 + DP-24: Tighten triggers and tighten-mode policy.

DP-36 — evaluates monitor signals and produces tightening actions:
- stops lease auto-renewal (clears ``expires_at``)
- bumps ``permit_epoch`` (revokes all outstanding permits)
- reduces ``lease_remaining_calls``
- optionally emits STEP_UP for novelty triggers

DP-24 — persistent *tighten mode* that the governor can enter/exit:
- when tightened, all non-read actions require step-up
- exploration budgets are disabled
- auto-expansion is blocked
- mode is sticky until explicitly exited (e.g. by a trusted step-up)
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.receipts.monitor_contract import MonitorInput
from agentauth.core.runtime import ExecutionContext, SideEffectLevel
from agentauth.receipts.sandbox_governor import (
    NullSandboxGovernor,
    SandboxEnforcement,
    SandboxGovernor,
    SandboxGovernorResult,
)


@dataclass
class TightenConfig:
    stop_renewal_on_step_up: bool = True
    bump_epoch_on_deny: bool = True
    reduce_budget_on_step_up: bool = True
    budget_reduction_factor: float = 0.5
    step_up_on_novelty: bool = True
    min_budget_after_reduction: int = 1


@dataclass
class TightenResult:
    triggered: bool = False
    reasons: list[str] = field(default_factory=list)
    authority_patch: dict[str, object] = field(default_factory=dict)
    enforcement_override: SandboxEnforcement | None = None


def evaluate_tighten_triggers(
    monitor_results: list[BehaviorMonitorResult],
    *,
    current_permit_epoch: int = 0,
    current_budget: int | None = None,
    config: TightenConfig | None = None,
) -> TightenResult:
    """Evaluate monitor signals and produce tightening actions (DP-36).

    Returns a ``TightenResult`` with an authority patch and optional
    enforcement override.  The caller (governor) applies the patch.
    """
    cfg = config or TightenConfig()
    result = TightenResult()

    worst = BehaviorRecommendation.ALLOW
    for mr in monitor_results:
        if mr.recommendation is None:
            continue
        if mr.recommendation == BehaviorRecommendation.DENY:
            worst = BehaviorRecommendation.DENY
        elif mr.recommendation == BehaviorRecommendation.STEP_UP:
            if worst != BehaviorRecommendation.DENY:
                worst = BehaviorRecommendation.STEP_UP

    if worst == BehaviorRecommendation.ALLOW:
        return result

    result.triggered = True

    if worst == BehaviorRecommendation.DENY and cfg.bump_epoch_on_deny:
        new_epoch = current_permit_epoch + 1
        result.authority_patch["permit_epoch"] = new_epoch
        result.reasons.append(
            f"tighten: bumped permit_epoch to {new_epoch} (monitor deny)"
        )
        result.enforcement_override = SandboxEnforcement.DENY

    if cfg.stop_renewal_on_step_up:
        result.authority_patch["expires_at"] = None
        result.reasons.append("tighten: stopped lease renewal (monitor non-allow)")

    if cfg.reduce_budget_on_step_up and current_budget is not None:
        reduced = max(
            cfg.min_budget_after_reduction,
            int(current_budget * cfg.budget_reduction_factor),
        )
        if reduced < current_budget:
            result.authority_patch["lease_remaining_calls"] = reduced
            result.reasons.append(
                f"tighten: reduced call budget {current_budget} -> {reduced}"
            )

    if worst == BehaviorRecommendation.STEP_UP and cfg.step_up_on_novelty:
        if result.enforcement_override is None:
            result.enforcement_override = SandboxEnforcement.STEP_UP
        result.reasons.append("tighten: requiring step-up for novelty")

    return result


class TighteningGovernor:
    """Governor that applies tighten triggers on top of an inner governor (DP-36 + DP-24).

    Supports two modes:
    - **Per-action tightening** (DP-36): when a monitor emits non-ALLOW,
      tighten the authority patch for that action.
    - **Persistent tighten mode** (DP-24): once entered, all non-read
      actions require step-up until explicitly exited.  The mode is
      entered automatically when a DENY monitor fires, or manually
      via ``enter_tighten_mode()``.

    Usage::

        monitors = [DriftScorer(...), ScanningScorer(...)]
        governor = TighteningGovernor(
            inner=RuleBasedSandboxGovernor(...),
            monitors=monitors,
            auto_tighten_on_deny=True,
        )
        gw = ReceiptedMcpGateway(agent, sandbox_governor=governor)
    """

    def __init__(
        self,
        inner: SandboxGovernor | None = None,
        *,
        monitors: list[object] | None = None,
        config: TightenConfig | None = None,
        auto_tighten_on_deny: bool = True,
    ) -> None:
        self.inner = inner or NullSandboxGovernor()
        self.monitors = list(monitors or [])
        self.config = config or TightenConfig()
        self.auto_tighten_on_deny = auto_tighten_on_deny
        self._tightened: bool = False
        self._tighten_reason: str | None = None

    @property
    def is_tightened(self) -> bool:
        return self._tightened

    def enter_tighten_mode(self, reason: str = "manual") -> None:
        self._tightened = True
        self._tighten_reason = reason

    def exit_tighten_mode(self) -> None:
        self._tightened = False
        self._tighten_reason = None

    def decide(
        self,
        ctx: ExecutionContext,
        *,
        monitor: BehaviorMonitorResult | None = None,
        structural_violations: list[str] | None = None,
    ) -> SandboxGovernorResult:
        # DP-24: persistent tighten mode
        if self._tightened:
            is_read = ctx.action.side_effect_level == SideEffectLevel.READ_ONLY
            if not is_read:
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.STEP_UP,
                    extra_violations=[
                        f"tighten_mode: non-read action requires step-up "
                        f"(reason: {self._tighten_reason})"
                    ],
                )

        inner_result = self.inner.decide(
            ctx, monitor=monitor, structural_violations=structural_violations
        )

        if inner_result.enforcement == SandboxEnforcement.DENY:
            return inner_result

        monitor_results: list[BehaviorMonitorResult] = []
        if monitor is not None:
            monitor_results.append(monitor)

        tighten = evaluate_tighten_triggers(
            monitor_results,
            current_permit_epoch=ctx.authority.permit_epoch,
            current_budget=ctx.authority.lease_remaining_calls,
            config=self.config,
        )

        if not tighten.triggered:
            return inner_result

        # DP-24: auto-enter tighten mode on DENY
        if (
            self.auto_tighten_on_deny
            and tighten.enforcement_override == SandboxEnforcement.DENY
        ):
            self.enter_tighten_mode("monitor_deny")

        merged_violations = list(inner_result.extra_violations) + tighten.reasons

        merged_patch = dict(inner_result.authority_patch or {})
        merged_patch.update(tighten.authority_patch)

        enforcement = inner_result.enforcement
        if tighten.enforcement_override is not None:
            if tighten.enforcement_override == SandboxEnforcement.DENY:
                enforcement = SandboxEnforcement.DENY
            elif (
                tighten.enforcement_override == SandboxEnforcement.STEP_UP
                and enforcement == SandboxEnforcement.ALLOW
            ):
                enforcement = SandboxEnforcement.STEP_UP

        return SandboxGovernorResult(
            enforcement=enforcement,
            extra_violations=merged_violations,
            obligations=list(inner_result.obligations),
            authority_patch=merged_patch or None,
            tool_permit=inner_result.tool_permit,
            commit_required=inner_result.commit_required,
        )
