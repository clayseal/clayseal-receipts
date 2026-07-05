"""Tests for DP-32, DP-34, DP-35, DP-36."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.receipts.default_deny_governor import DefaultDenySandboxGovernor
from agentauth.receipts.drift_monitor import DriftScorer, DriftScorerConfig
from agentauth.receipts.monitor_contract import MonitorInput, MonitorTraceEvent
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.receipts.sandbox_governor import (
    NullSandboxGovernor,
    SandboxEnforcement,
    SandboxGovernorResult,
)
from agentauth.receipts.scanning_monitor import ScanningScorer, ScanScorerConfig
from agentauth.receipts.tighten_policy import (
    TightenConfig,
    TighteningGovernor,
    evaluate_tighten_triggers,
)


def _trace_event(
    resource_ref: str | None = None,
    action_name: str = "mcp.tools/call/read_file",
) -> MonitorTraceEvent:
    return MonitorTraceEvent(
        action_name=action_name,
        action_category="mcp_tool_call",
        side_effect_level="read_only",
        resource_ref=resource_ref,
        arguments_hash="sha256:deadbeef",
        at=datetime.now(timezone.utc).isoformat(),
    )


def _monitor_input(resource_ref: str | None = None) -> MonitorInput:
    return MonitorInput(
        proposed=_trace_event(resource_ref=resource_ref),
    )


def _ctx(
    *,
    side_effect: SideEffectLevel = SideEffectLevel.BOUNDED_WRITE,
    authority_id: str = "test-auth",
    expires_at: str | None = None,
    resource_scope: list[str] | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            action_category="mcp_tool_call",
            side_effect_level=side_effect,
        ),
        input={},
        authority=AuthorityContext(
            authority_id=authority_id,
            expires_at=expires_at,
            resource_scope=resource_scope or [],
        ),
    )


# ---------------------------------------------------------------------------
# DP-34: Drift scorer
# ---------------------------------------------------------------------------


class TestDriftScorer:
    def test_all_in_scope_returns_allow(self) -> None:
        scorer = DriftScorer(
            {"repo://src/main.py", "repo://src/utils.py"},
            config=DriftScorerConfig(window=5, threshold=0.5),
        )
        for _ in range(5):
            result = scorer.evaluate_contract(_monitor_input("repo://src/main.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.ALLOW
        assert scorer.out_of_scope_ratio == 0.0

    def test_all_out_of_scope_triggers_step_up(self) -> None:
        scorer = DriftScorer(
            {"repo://src/main.py"},
            config=DriftScorerConfig(window=5, threshold=0.5),
        )
        for _ in range(5):
            result = scorer.evaluate_contract(_monitor_input("repo://hack/evil.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.STEP_UP
        assert scorer.out_of_scope_ratio == 1.0

    def test_mixed_below_threshold_returns_allow(self) -> None:
        scorer = DriftScorer(
            {"repo://src/main.py"},
            config=DriftScorerConfig(window=4, threshold=0.5),
        )
        # 3 in-scope, 1 out
        for _ in range(3):
            scorer.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = scorer.evaluate_contract(_monitor_input("repo://other.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.ALLOW

    def test_mixed_above_threshold_triggers(self) -> None:
        scorer = DriftScorer(
            {"repo://src/main.py"},
            config=DriftScorerConfig(window=4, threshold=0.5),
        )
        # 1 in-scope, 3 out → 75% out
        scorer.evaluate_contract(_monitor_input("repo://src/main.py"))
        for _ in range(3):
            result = scorer.evaluate_contract(_monitor_input("repo://other.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.STEP_UP

    def test_rolling_window_evicts_old(self) -> None:
        scorer = DriftScorer(
            {"repo://src/main.py"},
            config=DriftScorerConfig(window=3, threshold=0.5),
        )
        # 3 out-of-scope, then 3 in-scope → window should only see in-scope
        for _ in range(3):
            scorer.evaluate_contract(_monitor_input("repo://hack.py"))
        for _ in range(3):
            result = scorer.evaluate_contract(_monitor_input("repo://src/main.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.ALLOW
        assert scorer.out_of_scope_ratio == 0.0

    def test_trace_commitment_is_stable(self) -> None:
        scorer = DriftScorer({"repo://a.py"})
        # First call returns None (need 2+), so seed with two calls
        scorer.evaluate_contract(_monitor_input("repo://a.py"))
        r1 = scorer.evaluate_contract(_monitor_input("repo://a.py"))
        r2 = scorer.evaluate_contract(_monitor_input("repo://a.py"))
        assert r1 is not None and r2 is not None
        assert r1.trace_commitment.startswith("sha256:")
        assert r2.trace_commitment.startswith("sha256:")

    def test_single_action_returns_none(self) -> None:
        scorer = DriftScorer({"repo://a.py"})
        result = scorer.evaluate_contract(_monitor_input("repo://a.py"))
        assert result is None

    def test_invalid_window_raises(self) -> None:
        with pytest.raises(ValueError):
            DriftScorer(set(), config=DriftScorerConfig(window=0))


# ---------------------------------------------------------------------------
# DP-35: Scanning scorer
# ---------------------------------------------------------------------------


class TestScanningScorer:
    def test_few_files_returns_allow(self) -> None:
        scorer = ScanningScorer(
            config=ScanScorerConfig(window=20, max_unique_dirs=8, max_unique_files=15)
        )
        for i in range(5):
            result = scorer.evaluate_contract(_monitor_input(f"repo://src/file{i}.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.ALLOW

    def test_many_dirs_triggers_step_up(self) -> None:
        scorer = ScanningScorer(
            config=ScanScorerConfig(window=20, max_unique_dirs=3, max_unique_files=100)
        )
        dirs = ["repo://a/f.py", "repo://b/f.py", "repo://c/f.py", "repo://d/f.py"]
        for ref in dirs:
            result = scorer.evaluate_contract(_monitor_input(ref))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.STEP_UP
        assert any("unique dirs" in r for r in result.reasons)

    def test_many_files_triggers_step_up(self) -> None:
        scorer = ScanningScorer(
            config=ScanScorerConfig(window=20, max_unique_dirs=100, max_unique_files=3)
        )
        for i in range(5):
            result = scorer.evaluate_contract(_monitor_input(f"repo://src/f{i}.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.STEP_UP
        assert any("unique files" in r for r in result.reasons)

    def test_entropy_triggers_step_up(self) -> None:
        scorer = ScanningScorer(
            config=ScanScorerConfig(
                window=20,
                max_unique_dirs=100,
                max_unique_files=100,
                entropy_threshold=0.5,
            )
        )
        refs = [
            "repo://a/f.py",
            "repo://b/f.py",
            "repo://c/f.py",
            "repo://d/f.py",
            "repo://e/f.py",
        ]
        for ref in refs:
            result = scorer.evaluate_contract(_monitor_input(ref))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.STEP_UP
        assert any("entropy" in r for r in result.reasons)

    def test_concentrated_access_low_entropy(self) -> None:
        scorer = ScanningScorer(
            config=ScanScorerConfig(
                window=10,
                max_unique_dirs=100,
                max_unique_files=100,
                entropy_threshold=2.5,
            )
        )
        # All in one dir
        for i in range(6):
            result = scorer.evaluate_contract(_monitor_input(f"repo://src/f{i}.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.ALLOW

    def test_null_resource_ref_skipped(self) -> None:
        scorer = ScanningScorer()
        result = scorer.evaluate_contract(_monitor_input(None))
        assert result is None

    def test_properties(self) -> None:
        scorer = ScanningScorer()
        for ref in ["repo://a/f1.py", "repo://b/f2.py", "repo://a/f3.py"]:
            scorer.evaluate_contract(_monitor_input(ref))
        assert scorer.unique_dirs == 2
        assert scorer.unique_files == 3


# ---------------------------------------------------------------------------
# DP-32: Safe default deny
# ---------------------------------------------------------------------------


class TestDefaultDenySandboxGovernor:
    def test_missing_authority_id_denies(self) -> None:
        gov = DefaultDenySandboxGovernor()
        result = gov.decide(_ctx(authority_id=""))
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("missing authority_id" in v for v in result.extra_violations)

    def test_missing_expires_at_denies_write(self) -> None:
        gov = DefaultDenySandboxGovernor()
        result = gov.decide(_ctx(expires_at=None))
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("expired authority lease" in v for v in result.extra_violations)

    def test_expired_lease_denies_write(self) -> None:
        gov = DefaultDenySandboxGovernor()
        expired = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        result = gov.decide(_ctx(expires_at=expired))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_valid_authority_allows_through_inner(self) -> None:
        gov = DefaultDenySandboxGovernor()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        result = gov.decide(_ctx(expires_at=future))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_read_allowed_without_lease_by_default(self) -> None:
        gov = DefaultDenySandboxGovernor()
        result = gov.decide(_ctx(side_effect=SideEffectLevel.READ_ONLY))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_read_denied_without_lease_when_strict(self) -> None:
        gov = DefaultDenySandboxGovernor(allow_read_without_lease=False)
        result = gov.decide(
            _ctx(side_effect=SideEffectLevel.READ_ONLY, expires_at=None)
        )
        assert result.enforcement == SandboxEnforcement.DENY

    def test_require_resource_scope_denies_write_without_scope(self) -> None:
        gov = DefaultDenySandboxGovernor(require_resource_scope=True)
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        result = gov.decide(_ctx(expires_at=future, resource_scope=[]))
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("resource_scope" in v for v in result.extra_violations)

    def test_require_resource_scope_allows_read_without_scope(self) -> None:
        gov = DefaultDenySandboxGovernor(require_resource_scope=True)
        result = gov.decide(
            _ctx(side_effect=SideEffectLevel.READ_ONLY, resource_scope=[])
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_delegates_to_inner_governor(self) -> None:
        class _AlwaysDenyInner:
            def decide(self, ctx, *, monitor=None, structural_violations=None):
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=["inner: denied"],
                )

        gov = DefaultDenySandboxGovernor(inner=_AlwaysDenyInner())
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        result = gov.decide(_ctx(expires_at=future))
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("inner: denied" in v for v in result.extra_violations)


# ---------------------------------------------------------------------------
# DP-36: Tighten triggers
# ---------------------------------------------------------------------------


class TestTightenTriggers:
    def test_no_monitors_no_tighten(self) -> None:
        result = evaluate_tighten_triggers([])
        assert not result.triggered
        assert result.authority_patch == {}

    def test_allow_monitors_no_tighten(self) -> None:
        allow = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.ALLOW,
        )
        result = evaluate_tighten_triggers([allow])
        assert not result.triggered

    def test_step_up_stops_renewal_and_reduces_budget(self) -> None:
        step_up = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.STEP_UP,
        )
        result = evaluate_tighten_triggers(
            [step_up],
            current_budget=10,
        )
        assert result.triggered
        assert result.authority_patch.get("expires_at") is None
        assert result.authority_patch["lease_remaining_calls"] == 5
        assert result.enforcement_override == SandboxEnforcement.STEP_UP

    def test_deny_bumps_epoch(self) -> None:
        deny = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.DENY,
        )
        result = evaluate_tighten_triggers(
            [deny],
            current_permit_epoch=3,
        )
        assert result.triggered
        assert result.authority_patch["permit_epoch"] == 4
        assert result.enforcement_override == SandboxEnforcement.DENY

    def test_deny_takes_precedence_over_step_up(self) -> None:
        monitors = [
            BehaviorMonitorResult(
                monitor_id="a",
                recommendation=BehaviorRecommendation.STEP_UP,
            ),
            BehaviorMonitorResult(
                monitor_id="b",
                recommendation=BehaviorRecommendation.DENY,
            ),
        ]
        result = evaluate_tighten_triggers(monitors, current_permit_epoch=0)
        assert result.enforcement_override == SandboxEnforcement.DENY
        assert result.authority_patch["permit_epoch"] == 1

    def test_budget_reduction_respects_minimum(self) -> None:
        step_up = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.STEP_UP,
        )
        result = evaluate_tighten_triggers(
            [step_up],
            current_budget=1,
            config=TightenConfig(min_budget_after_reduction=1),
        )
        assert result.authority_patch.get("lease_remaining_calls", 1) >= 1

    def test_config_disables_all_actions(self) -> None:
        step_up = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.STEP_UP,
        )
        cfg = TightenConfig(
            stop_renewal_on_step_up=False,
            bump_epoch_on_deny=False,
            reduce_budget_on_step_up=False,
            step_up_on_novelty=False,
        )
        result = evaluate_tighten_triggers([step_up], config=cfg)
        assert result.triggered
        assert result.authority_patch == {}
        assert result.enforcement_override is None


class TestTighteningGovernor:
    def test_passes_through_when_no_monitor(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        result = gov.decide(_ctx(expires_at=future))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_tightens_on_step_up_monitor(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        ctx = _ctx(expires_at=future)
        ctx.authority.lease_remaining_calls = 10
        step_up = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.STEP_UP,
        )
        result = gov.decide(ctx, monitor=step_up)
        assert result.enforcement == SandboxEnforcement.STEP_UP
        assert any("tighten" in v for v in result.extra_violations)

    def test_inner_deny_is_preserved(self) -> None:
        class _AlwaysDeny:
            def decide(self, ctx, *, monitor=None, structural_violations=None):
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=["inner: denied"],
                )

        gov = TighteningGovernor(inner=_AlwaysDeny())
        result = gov.decide(_ctx())
        assert result.enforcement == SandboxEnforcement.DENY
