"""Unit tests for dynamic sandboxing components (monitors, governors, scoping, step-up)."""
from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.receipts.default_deny_governor import DefaultDenySandboxGovernor
from agentauth.receipts.drift_monitor import DriftScorer, DriftScorerConfig
from agentauth.receipts.monitor_contract import MonitorInput, MonitorTraceEvent
from agentauth.receipts.novelty_monitor import NoveltyConfig, NoveltyMonitor
from agentauth.receipts.protected_zone_governor import (
    ProtectedZoneConfig,
    ProtectedZoneGovernor,
)
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
from agentauth.capabilities.step_up import (
    StepUpApproval,
    StepUpRequest,
    apply_step_up,
    build_step_up_request,
)
from agentauth.receipts.tighten_policy import (
    TightenConfig,
    TighteningGovernor,
    evaluate_tighten_triggers,
)
from agentauth.capabilities.scoping.exploration_budget import ExplorationBudget, ExplorationBudgetConfig
from agentauth.capabilities.scoping.index_builder import build_repo_chunk_index
from agentauth.capabilities.scoping.metrics import ScopingMetrics
from agentauth.capabilities.scoping.session_overlay import SessionChunkOverlay


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


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


def _monitor_input(
    resource_ref: str | None = None,
    action_name: str = "mcp.tools/call/read_file",
) -> MonitorInput:
    return MonitorInput(
        proposed=_trace_event(resource_ref=resource_ref, action_name=action_name),
    )


def _ctx(
    *,
    side_effect: SideEffectLevel = SideEffectLevel.BOUNDED_WRITE,
    authority_id: str = "test-auth",
    expires_at: str | None = None,
    resource_scope: list[str] | None = None,
    resource_ref: str | None = None,
    approval_refs: list[str] | None = None,
    auto_future: bool = False,
) -> ExecutionContext:
    action_kwargs: dict = dict(
        action_name="mcp.tools/call/write_file",
        action_category="mcp_tool_call",
        side_effect_level=side_effect,
    )
    if resource_ref is not None:
        action_kwargs["resource_ref"] = resource_ref

    authority_kwargs: dict = dict(
        authority_id=authority_id,
    )
    if expires_at is not None or auto_future:
        authority_kwargs["expires_at"] = expires_at if expires_at is not None else _future()
    if resource_scope is not None:
        authority_kwargs["resource_scope"] = resource_scope
    if approval_refs is not None:
        authority_kwargs["approval_refs"] = approval_refs

    return ExecutionContext(
        action=ActionDescriptor(**action_kwargs),
        input={},
        authority=AuthorityContext(**authority_kwargs),
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
        # 1 in-scope, 3 out -> 75% out
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
        # 3 out-of-scope, then 3 in-scope -> window should only see in-scope
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


# ---------------------------------------------------------------------------
# DP-21: Exploration budgets
# ---------------------------------------------------------------------------


class TestExplorationBudget:
    def test_allows_within_budget(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_files=5))
        ok, reason = budget.try_consume("src/main.py", byte_count=100)
        assert ok
        assert reason == "ok"

    def test_blocks_when_file_budget_exhausted(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_files=2))
        budget.try_consume("a.py")
        budget.try_consume("b.py")
        ok, reason = budget.try_consume("c.py")
        assert not ok
        assert reason == "file_budget_exhausted"

    def test_same_file_does_not_consume_again(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_files=2))
        budget.try_consume("a.py")
        budget.try_consume("b.py")
        ok, _ = budget.try_consume("a.py")
        assert ok

    def test_blocks_when_dir_budget_exhausted(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_dirs=2))
        budget.try_consume("dir1/a.py")
        budget.try_consume("dir2/a.py")
        ok, reason = budget.try_consume("dir3/a.py")
        assert not ok
        assert reason == "dir_budget_exhausted"

    def test_blocks_when_byte_budget_exhausted(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_bytes=1000))
        budget.try_consume("a.py", byte_count=600)
        ok, reason = budget.try_consume("b.py", byte_count=500)
        assert not ok
        assert reason == "byte_budget_exhausted"

    def test_tightened_mode_blocks_all(self) -> None:
        budget = ExplorationBudget()
        budget.enter_tightened_mode()
        ok, reason = budget.try_consume("a.py")
        assert not ok
        assert reason == "exploration_disabled_tightened"

    def test_exit_tightened_mode_re_enables(self) -> None:
        budget = ExplorationBudget()
        budget.enter_tightened_mode()
        budget.exit_tightened_mode()
        ok, _ = budget.try_consume("a.py")
        assert ok

    def test_remaining_properties(self) -> None:
        budget = ExplorationBudget(
            config=ExplorationBudgetConfig(max_files=10, max_dirs=5, max_bytes=5000)
        )
        budget.try_consume("dir1/a.py", byte_count=1000)
        assert budget.remaining_files == 9
        assert budget.remaining_dirs == 4
        assert budget.remaining_bytes == 4000

    def test_to_dict(self) -> None:
        budget = ExplorationBudget()
        budget.try_consume("a.py", byte_count=100)
        d = budget.to_dict()
        assert d["files_read"] == 1
        assert d["bytes_read"] == 100
        assert d["tightened"] is False


# ---------------------------------------------------------------------------
# DP-22: Novelty triggers
# ---------------------------------------------------------------------------


class TestNoveltyMonitor:
    def test_first_subsystem_triggers(self) -> None:
        mon = NoveltyMonitor()
        result = mon.evaluate_contract(_monitor_input("repo://src/main.py"))
        assert result is not None
        assert result.recommendation == BehaviorRecommendation.STEP_UP
        assert any("subsystem" in r for r in result.reasons)

    def test_same_subsystem_no_trigger(self) -> None:
        mon = NoveltyMonitor()
        mon.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = mon.evaluate_contract(_monitor_input("repo://src/utils.py"))
        assert result is None  # same subsystem, same tool class

    def test_new_subsystem_triggers(self) -> None:
        mon = NoveltyMonitor()
        mon.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = mon.evaluate_contract(_monitor_input("repo://tests/test_main.py"))
        assert result is not None
        assert any("subsystem" in r and "tests" in r for r in result.reasons)

    def test_new_tool_class_triggers(self) -> None:
        mon = NoveltyMonitor()
        mon.evaluate_contract(
            _monitor_input("repo://a.py", action_name="mcp.tools/call/read_file")
        )
        result = mon.evaluate_contract(
            _monitor_input("repo://a.py", action_name="shell/exec/bash")
        )
        assert result is not None
        assert any("tool class" in r for r in result.reasons)

    def test_new_net_domain_triggers(self) -> None:
        mon = NoveltyMonitor()
        mon.evaluate_contract(_monitor_input("repo://a.py"))
        result = mon.evaluate_contract(_monitor_input("net://evil.com/exfil"))
        assert result is not None
        assert any("network domain" in r for r in result.reasons)

    def test_protected_zone_triggers(self) -> None:
        mon = NoveltyMonitor()
        mon.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = mon.evaluate_contract(_monitor_input("repo://keys/secret.pem"))
        assert result is not None
        assert any("protected zone" in r for r in result.reasons)

    def test_approved_subsystem_no_trigger(self) -> None:
        mon = NoveltyMonitor()
        mon.approve_subsystem("tests")
        result = mon.evaluate_contract(_monitor_input("repo://tests/test_main.py"))
        # "tests" subsystem is approved, so no subsystem trigger
        # but first tool class still fires
        if result is not None:
            assert not any("subsystem" in r and "tests" in r for r in result.reasons)

    def test_approved_domain_no_trigger(self) -> None:
        mon = NoveltyMonitor()
        mon.approve_domain("api.example.com")
        mon.evaluate_contract(_monitor_input("repo://a.py"))
        result = mon.evaluate_contract(_monitor_input("net://api.example.com/data"))
        # domain approved, no net domain trigger
        if result is not None:
            assert not any("network domain" in r for r in result.reasons)

    def test_approved_protected_no_trigger(self) -> None:
        mon = NoveltyMonitor()
        mon.approve_protected("repo://keys/")
        mon.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = mon.evaluate_contract(_monitor_input("repo://keys/signing.pem"))
        if result is not None:
            assert not any("protected zone" in r and "keys" in r for r in result.reasons)

    def test_seen_properties(self) -> None:
        mon = NoveltyMonitor()
        mon.evaluate_contract(_monitor_input("repo://src/main.py"))
        mon.evaluate_contract(
            _monitor_input("net://api.example.com/x", action_name="http/get")
        )
        assert "src" in mon.seen_subsystems
        assert "api.example.com" in mon.seen_domains

    def test_no_resource_ref_no_subsystem_trigger(self) -> None:
        mon = NoveltyMonitor()
        result = mon.evaluate_contract(_monitor_input(None))
        # No resource ref -> no subsystem/domain/protected triggers
        # But first tool class fires
        assert result is None or not any("subsystem" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# DP-24: Tighten mode (persistent)
# ---------------------------------------------------------------------------


class TestTightenMode:
    def test_manual_tighten_blocks_writes(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test reason")
        assert gov.is_tightened

        result = gov.decide(_ctx(side_effect=SideEffectLevel.BOUNDED_WRITE, auto_future=True))
        assert result.enforcement == SandboxEnforcement.STEP_UP
        assert any("tighten_mode" in v for v in result.extra_violations)

    def test_tighten_allows_reads(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test")

        result = gov.decide(_ctx(side_effect=SideEffectLevel.READ_ONLY, auto_future=True))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_exit_tighten_mode_allows_writes(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test")
        gov.exit_tighten_mode()
        assert not gov.is_tightened

        result = gov.decide(_ctx(side_effect=SideEffectLevel.BOUNDED_WRITE, auto_future=True))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_auto_tighten_on_deny_monitor(self) -> None:
        gov = TighteningGovernor(
            inner=NullSandboxGovernor(),
            auto_tighten_on_deny=True,
        )
        deny = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.DENY,
        )
        gov.decide(_ctx(auto_future=True), monitor=deny)
        assert gov.is_tightened

    def test_auto_tighten_disabled(self) -> None:
        gov = TighteningGovernor(
            inner=NullSandboxGovernor(),
            auto_tighten_on_deny=False,
        )
        deny = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.DENY,
        )
        gov.decide(_ctx(auto_future=True), monitor=deny)
        assert not gov.is_tightened

    def test_step_up_does_not_auto_tighten(self) -> None:
        gov = TighteningGovernor(
            inner=NullSandboxGovernor(),
            auto_tighten_on_deny=True,
        )
        step_up = BehaviorMonitorResult(
            monitor_id="test",
            recommendation=BehaviorRecommendation.STEP_UP,
        )
        gov.decide(_ctx(auto_future=True), monitor=step_up)
        assert not gov.is_tightened

    def test_tighten_persists_across_calls(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test")

        for _ in range(5):
            result = gov.decide(
                _ctx(side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
            )
            assert result.enforcement == SandboxEnforcement.STEP_UP
        assert gov.is_tightened


# ---------------------------------------------------------------------------
# DP-23: Protected-zone governor
# ---------------------------------------------------------------------------


class TestProtectedZoneGovernor:
    def test_normal_resource_passes_through(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="repo://src/main.py", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_protected_write_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="repo://keys/secret.pem", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("protected_zone" in v for v in result.extra_violations)

    def test_protected_read_requires_step_up(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="repo://keys/secret.pem", side_effect=SideEffectLevel.READ_ONLY, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.STEP_UP

    def test_egress_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="net://evil.com/exfil", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("egress" in v for v in result.extra_violations)

    def test_explicit_allow_overrides(self) -> None:
        gov = ProtectedZoneGovernor(explicit_allow={"repo://keys/secret.pem"})
        result = gov.decide(
            _ctx(resource_ref="repo://keys/secret.pem", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_explicit_allow_glob(self) -> None:
        gov = ProtectedZoneGovernor(explicit_allow={"repo://auth/*"})
        result = gov.decide(
            _ctx(resource_ref="repo://auth/verify.py", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_approval_ref_overrides(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(
                resource_ref="repo://keys/secret.pem",
                side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
                approval_refs=["repo://keys/secret.pem"],
                auto_future=True,
            )
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_agents_md_write_denied_without_explicit_allow(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(
                resource_ref="repo_write://AGENTS.md",
                side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
                auto_future=True,
            )
        )
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("AGENTS.md" in v or "write access" in v for v in result.extra_violations)

    def test_agents_md_write_allowed_with_explicit_allow(self) -> None:
        gov = ProtectedZoneGovernor(explicit_allow={"repo_write://AGENTS.md"})
        result = gov.decide(
            _ctx(
                resource_ref="repo_write://AGENTS.md",
                side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
                auto_future=True,
            )
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_agent_memory_write_denied_without_opt_in(self) -> None:
        gov = ProtectedZoneGovernor(
            explicit_allow={"repo_write://.devin/knowledge.md"},
            allow_agent_memory_writes=False,
        )
        result = gov.decide(
            _ctx(
                resource_ref="repo_write://.devin/knowledge.md",
                side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
                auto_future=True,
            )
        )
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("agent memory" in v for v in result.extra_violations)

    def test_agent_memory_write_allowed_with_opt_in_and_explicit_allow(self) -> None:
        gov = ProtectedZoneGovernor(
            explicit_allow={"repo_write://.devin/knowledge.md"},
            allow_agent_memory_writes=True,
        )
        result = gov.decide(
            _ctx(
                resource_ref="repo_write://.devin/knowledge.md",
                side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
                auto_future=True,
            )
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_step_up_approval_recorded(self) -> None:
        gov = ProtectedZoneGovernor()
        result1 = gov.decide(
            _ctx(resource_ref="repo://deploy/prod.yaml", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result1.enforcement != SandboxEnforcement.ALLOW

        gov.approve_resource("repo://deploy/prod.yaml")
        result2 = gov.decide(
            _ctx(resource_ref="repo://deploy/prod.yaml", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result2.enforcement == SandboxEnforcement.ALLOW

    def test_auth_directory_is_protected(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="repo://auth/login.py", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY

    def test_env_file_is_protected(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="repo://.env.production", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY

    def test_github_workflow_is_protected(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="repo://.github/workflows/ci.yml", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY

    def test_secrets_scheme_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx(resource_ref="secrets://aws/prod-key", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY

    def test_delegates_to_inner(self) -> None:
        class _AlwaysDeny:
            def decide(self, ctx, *, monitor=None, structural_violations=None):
                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=["inner: denied"],
                )

        gov = ProtectedZoneGovernor(inner=_AlwaysDeny())
        result = gov.decide(
            _ctx(resource_ref="repo://src/main.py", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY

    def test_custom_patterns(self) -> None:
        config = ProtectedZoneConfig(
            protected_patterns=("repo://custom_secrets/*",),
        )
        gov = ProtectedZoneGovernor(config=config)
        result = gov.decide(
            _ctx(resource_ref="repo://custom_secrets/key.txt", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result.enforcement == SandboxEnforcement.DENY
        result2 = gov.decide(
            _ctx(resource_ref="repo://keys/safe.pem", side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT, auto_future=True)
        )
        assert result2.enforcement == SandboxEnforcement.ALLOW


# ---------------------------------------------------------------------------
# DP-30: Step-up protocol
# ---------------------------------------------------------------------------


class TestStepUpProtocol:
    def test_build_step_up_request(self) -> None:
        req = build_step_up_request(
            request_id="r-1",
            query_id="q-1",
            resource_ref="repo://auth/verify.py",
            operation="write",
            violations=["protected_zone: write denied"],
        )
        assert req.resource_ref == "repo://auth/verify.py"
        assert req.operation == "write"
        d = req.to_dict()
        assert d["schema"] == "agent-receipts.step-up-request.v1"
        assert req.commitment().startswith("sha256:")

    def test_step_up_approval_schema(self) -> None:
        approval = StepUpApproval(
            approval_id="a-1",
            request_commitment="sha256:abc",
            allow_resources=["repo://auth/verify.py"],
            allow_write=True,
        )
        d = approval.to_dict()
        assert d["schema"] == "agent-receipts.step-up-approval.v1"
        assert d["allow_write"] is True

    def test_apply_step_up_adds_resources(self) -> None:
        authority = AuthorityContext(
            authority_id="test",
            authority_version=1,
            resource_scope=["repo://src/main.py"],
            approval_refs=[],
        )
        approval = StepUpApproval(
            approval_id="a-1",
            request_commitment="sha256:abc",
            allow_resources=["repo://auth/verify.py"],
        )
        patch = apply_step_up(authority, approval)
        assert "repo://auth/verify.py" in authority.resource_scope
        assert "repo://auth/verify.py" in authority.approval_refs
        assert authority.authority_version == 2

    def test_apply_step_up_extends_lease(self) -> None:
        authority = AuthorityContext(
            authority_id="test",
            authority_version=1,
            lease_remaining_calls=5,
        )
        approval = StepUpApproval(
            approval_id="a-2",
            request_commitment="sha256:abc",
            allow_resources=["repo://deploy/prod.yaml"],
            extra_budget=10,
            ttl_seconds=300,
        )
        apply_step_up(authority, approval)
        assert authority.lease_remaining_calls == 15
        assert authority.expires_at is not None

    def test_apply_step_up_no_duplicates(self) -> None:
        authority = AuthorityContext(
            authority_id="test",
            resource_scope=["repo://auth/verify.py"],
            approval_refs=["repo://auth/verify.py"],
        )
        approval = StepUpApproval(
            approval_id="a-3",
            request_commitment="sha256:abc",
            allow_resources=["repo://auth/verify.py"],
        )
        apply_step_up(authority, approval)
        assert authority.resource_scope.count("repo://auth/verify.py") == 1
        assert authority.approval_refs.count("repo://auth/verify.py") == 1

    def test_step_up_end_to_end_with_governor(self) -> None:
        """Full flow: governor denies -> build request -> approve -> re-check passes."""
        gov = ProtectedZoneGovernor()

        # 1. First attempt: denied
        ctx1 = _ctx(
            resource_ref="repo://deploy/prod.yaml",
            side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
            auto_future=True,
        )
        result1 = gov.decide(ctx1)
        assert result1.enforcement != SandboxEnforcement.ALLOW

        # 2. Build step-up request
        req = build_step_up_request(
            request_id="r-1",
            query_id="q-1",
            resource_ref="repo://deploy/prod.yaml",
            operation="write",
            violations=result1.extra_violations,
        )

        # 3. Approve
        approval = StepUpApproval(
            approval_id="a-1",
            request_commitment=req.commitment(),
            allow_resources=["repo://deploy/prod.yaml"],
            allow_write=True,
        )

        # 4. Apply approval to governor
        gov.approve_resource("repo://deploy/prod.yaml")

        # 5. Re-check: allowed
        ctx2 = _ctx(
            resource_ref="repo://deploy/prod.yaml",
            side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
            auto_future=True,
        )
        result2 = gov.decide(ctx2)
        assert result2.enforcement == SandboxEnforcement.ALLOW


# ---------------------------------------------------------------------------
# DP-40: Success metrics
# ---------------------------------------------------------------------------


class TestScopingMetrics:
    def test_basic_tracking(self) -> None:
        m = ScopingMetrics(goal_id="g-1")
        m.record_action(blocked=False, overhead_ms=10.0)
        m.record_action(blocked=False, overhead_ms=20.0)
        m.record_action(blocked=True, step_up=True, overhead_ms=15.0)
        assert m.total_actions == 3
        assert m.blocked_actions == 1
        assert m.step_up_prompts == 1

    def test_prompts_per_goal(self) -> None:
        m = ScopingMetrics()
        assert m.prompts_per_goal == 0.0
        m.record_action(step_up=True)
        assert m.prompts_per_goal == 1.0

    def test_false_block_rate(self) -> None:
        m = ScopingMetrics()
        m.record_action(blocked=True)
        m.record_action(blocked=True)
        m.record_false_block()
        assert m.false_block_rate == 0.5

    def test_false_block_rate_zero_when_no_blocks(self) -> None:
        m = ScopingMetrics()
        assert m.false_block_rate == 0.0

    def test_prevented_counts(self) -> None:
        m = ScopingMetrics()
        m.record_prevented(protected_read=True)
        m.record_prevented(protected_write=True)
        m.record_prevented(egress=True)
        s = m.summary()
        assert s["prevented"]["total"] == 3

    def test_monitor_triggers(self) -> None:
        m = ScopingMetrics()
        m.record_monitor_trigger(scan=True)
        m.record_monitor_trigger(drift=True)
        m.record_monitor_trigger(novelty=True)
        s = m.summary()
        assert s["monitor_triggers"]["scan"] == 1
        assert s["monitor_triggers"]["drift"] == 1
        assert s["monitor_triggers"]["novelty"] == 1

    def test_first_edit_and_block_tracking(self) -> None:
        m = ScopingMetrics()
        m.record_action(is_write=False)
        m.record_action(is_write=False)
        m.record_action(is_write=True)
        assert m.first_edit_action == 3
        m.record_action(blocked=True)
        assert m.first_block_action == 4

    def test_overhead_percentiles(self) -> None:
        m = ScopingMetrics()
        for ms in [5, 10, 15, 20, 25, 30, 35, 40, 45, 50]:
            m.record_action(overhead_ms=float(ms))
        assert m.broker_overhead_p50_ms == 27.5
        assert m.broker_overhead_p95_ms >= 45.0

    def test_summary_schema(self) -> None:
        m = ScopingMetrics(goal_id="g-test")
        m.record_action(overhead_ms=5.0)
        s = m.summary()
        assert s["goal_id"] == "g-test"
        assert "prompts_per_goal" in s
        assert "false_block_rate" in s
        assert "prevented" in s
        assert "broker_overhead_p50_ms" in s

    def test_actions_before_first_block(self) -> None:
        m = ScopingMetrics()
        m.record_action()
        m.record_action()
        m.record_action(blocked=True)
        s = m.summary()
        assert s["actions_before_first_block"] == 2


# ---------------------------------------------------------------------------
# DP-8: Session chunk overlay (incremental updates)
# ---------------------------------------------------------------------------


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "swe_triage").mkdir()
    (tmp_path / "swe_triage" / "parser.py").write_text(
        textwrap.dedent(
            '''
            """Parser module."""
            from swe_triage.auth import verify_token

            def parse_ticket(raw: str) -> dict:
                verify_token(raw)
                return {"ok": True}
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "swe_triage" / "auth.py").write_text(
        textwrap.dedent(
            '''
            def verify_token(raw: str) -> bool:
                return bool(raw)
            '''
        ).strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    return tmp_path


def test_overlay_rechunks_changed_file(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    new_text = textwrap.dedent(
        '''
        """Parser module."""
        from swe_triage.auth import verify_token

        def parse_ticket(raw: str) -> dict:
            verify_token(raw)
            return {"ok": True}

        def parse_ticket_v2(raw: str) -> dict:
            return {"v2": True}
        '''
    ).strip() + "\n"

    new_chunks = overlay.update_file("swe_triage/parser.py", new_text)
    assert any(c.qualified_name == "parse_ticket_v2" for c in new_chunks)


def test_overlay_merged_index_contains_new_chunks(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    new_text = textwrap.dedent(
        '''
        def helper() -> None:
            pass
        '''
    ).strip() + "\n"
    overlay.update_file("swe_triage/auth.py", new_text)

    merged = overlay.merged_index()
    assert any(c.qualified_name == "helper" for c in merged.chunks)
    assert not any(
        c.qualified_name == "verify_token"
        and c.file_path == "swe_triage/auth.py"
        for c in merged.chunks
    )


def test_overlay_preserves_untouched_files(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    overlay.update_file("swe_triage/auth.py", "def new_fn(): pass\n")

    merged = overlay.merged_index()
    parser_chunks = [c for c in merged.chunks if c.file_path == "swe_triage/parser.py"]
    assert parser_chunks


def test_overlay_updates_import_edges(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    new_text = "from swe_triage.parser import parse_ticket\ndef call_parser(): pass\n"
    overlay.update_file("swe_triage/auth.py", new_text)

    edges = overlay.merged_import_edges()
    assert ("swe_triage/auth.py", "swe_triage/parser.py") in edges


def test_overlay_changed_files(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    overlay.update_file("swe_triage/auth.py", "x = 1\n")
    assert "swe_triage/auth.py" in overlay.changed_files
    assert "swe_triage/parser.py" not in overlay.changed_files


def test_overlay_reads_from_disk_when_no_text(sample_repo: Path) -> None:
    index = build_repo_chunk_index(sample_repo)
    overlay = SessionChunkOverlay(base=index)

    chunks = overlay.update_file("swe_triage/parser.py")
    assert chunks
    assert any(c.qualified_name == "parse_ticket" for c in chunks)


def test_protected_zone_traversal_cannot_bypass_containment():
    """A resource_ref with `../` or `./` must not evade a protected-zone pattern by
    string-matching outside it while resolving inside it."""
    from agentauth.receipts.protected_zone_governor import ProtectedZoneGovernor

    g = ProtectedZoneGovernor()
    for ref in (
        "repo_write://src/../auth/config",   # resolves into auth/ (protected)
        "repo_write://./auth/config",
        "repo_write://x/../.env.prod",       # resolves into .env* (protected)
        "repo_write://a/b/../../keys/id_rsa",
    ):
        assert g._is_protected(ref) is True, ref
    # legit non-protected files are still not protected
    assert g._is_protected("repo_write://src/app/main.py") is False
    assert g._is_protected("repo_read://docs/readme.md") is False
