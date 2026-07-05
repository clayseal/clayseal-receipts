"""DP-39: Scenario harness — normal + adversarial flows through the full stack.

Normal scenarios: typical bugfix/refactor/test flows that should succeed
with minimal prompts.

Adversarial scenarios: scanning, protected-zone probing, egress, novelty
jumps — should be caught and blocked/stepped-up.
"""
from __future__ import annotations

import textwrap
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agentauth.receipts.behavior_monitor import BehaviorRecommendation
from agentauth.receipts.drift_monitor import DriftScorer, DriftScorerConfig
from agentauth.receipts.monitor_contract import MonitorInput, MonitorTraceEvent
from agentauth.receipts.novelty_monitor import NoveltyMonitor
from agentauth.receipts.protected_zone_governor import ProtectedZoneGovernor
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.receipts.sandbox_governor import SandboxEnforcement
from agentauth.receipts.scanning_monitor import ScanningScorer, ScanScorerConfig
from agentauth.capabilities.step_up import StepUpApproval, apply_step_up, build_step_up_request
from agentauth.receipts.tighten_policy import TighteningGovernor
from agentauth.capabilities.scoping import (
    build_capability_lease,
    build_repo_chunk_index,
    check_repo_path_allowed,
)
from agentauth.capabilities.scoping.exploration_budget import ExplorationBudget, ExplorationBudgetConfig
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.metrics import ScopingMetrics


def _trace_event(ref: str, action: str = "mcp.tools/call/read_file") -> MonitorTraceEvent:
    return MonitorTraceEvent(
        action_name=action,
        action_category="mcp_tool_call",
        side_effect_level="read_only",
        resource_ref=ref,
        arguments_hash="sha256:deadbeef",
        at=datetime.now(timezone.utc).isoformat(),
    )


def _monitor_input(ref: str, action: str = "mcp.tools/call/read_file") -> MonitorInput:
    return MonitorInput(proposed=_trace_event(ref, action))


def _ctx(ref: str, se: SideEffectLevel = SideEffectLevel.BOUNDED_WRITE) -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            resource_ref=ref,
            side_effect_level=se,
        ),
        input={},
        authority=AuthorityContext(
            authority_id="test",
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        ),
    )


@pytest.fixture()
def sample_repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.py").write_text(
        "from src.utils import helper\ndef entry(): pass\n", encoding="utf-8",
    )
    (tmp_path / "src" / "utils.py").write_text(
        "def helper(): pass\n", encoding="utf-8",
    )
    (tmp_path / "src" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "auth").mkdir()
    (tmp_path / "auth" / "verify.py").write_text(
        "def check(): return True\n", encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_main.py").write_text(
        "from src.main import entry\ndef test_entry(): pass\n", encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text("[project]\nname='demo'\n", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------------------
# Normal scenarios
# ---------------------------------------------------------------------------


class TestNormalBugfix:
    """Scenario: fix a bug in src/main.py. Should scope to src/ with read on deps."""

    def test_bugfix_scopes_correctly(self, sample_repo: Path) -> None:
        index = build_repo_chunk_index(sample_repo)
        goal = GoalSpec(query_id="q-1", summary="Fix entry function in main.py")
        lease = build_capability_lease(index, goal, top_k=3)

        ok, _ = check_repo_path_allowed("src/main.py", lease, write=True)
        assert ok, "should be able to write to the file being fixed"

        ok, _ = check_repo_path_allowed("src/utils.py", lease, write=False)
        assert ok, "should be able to read import dep"

    def test_bugfix_no_monitors_fire(self, sample_repo: Path) -> None:
        index = build_repo_chunk_index(sample_repo)
        lease = build_capability_lease(
            index, GoalSpec(query_id="q-1", summary="Fix entry function"), top_k=3
        )
        scope = {f"repo://{f}" for f in lease.read_files | lease.write_files}
        drift = DriftScorer(scope, config=DriftScorerConfig(window=5, threshold=0.5))
        scan = ScanningScorer(config=ScanScorerConfig(window=10, max_unique_dirs=5))

        # Simulate normal work: read main, read utils, write main
        for ref in ["repo://src/main.py", "repo://src/utils.py", "repo://src/main.py"]:
            dr = drift.evaluate_contract(_monitor_input(ref))
            sr = scan.evaluate_contract(_monitor_input(ref))
            if dr:
                assert dr.recommendation == BehaviorRecommendation.ALLOW
            if sr:
                assert sr.recommendation == BehaviorRecommendation.ALLOW

    def test_bugfix_metrics_are_clean(self) -> None:
        metrics = ScopingMetrics(goal_id="bugfix-1")
        # Simulate 5 normal actions with no blocks
        for _ in range(5):
            metrics.record_action(overhead_ms=8.0)
        s = metrics.summary()
        assert s["blocked_actions"] == 0
        assert s["step_up_prompts"] == 0
        assert s["prompts_per_goal"] == 0.0


class TestNormalRefactor:
    """Scenario: rename a function across files. Touches multiple files in same subsystem."""

    def test_refactor_stays_in_subsystem(self, sample_repo: Path) -> None:
        index = build_repo_chunk_index(sample_repo)
        goal = GoalSpec(query_id="q-2", summary="Rename helper to helper_v2 in src/utils.py")
        lease = build_capability_lease(index, goal, top_k=3)

        ok, _ = check_repo_path_allowed("src/utils.py", lease, write=True)
        assert ok

    def test_refactor_novelty_stays_silent(self) -> None:
        novelty = NoveltyMonitor()
        # All accesses in same subsystem
        r1 = novelty.evaluate_contract(_monitor_input("repo://src/main.py"))
        r2 = novelty.evaluate_contract(_monitor_input("repo://src/utils.py"))
        # First triggers subsystem "src", second is same subsystem
        assert r2 is None


class TestNormalTestUpdate:
    """Scenario: add a test file. Should have read access to tested code."""

    def test_test_update_reads_source(self, sample_repo: Path) -> None:
        index = build_repo_chunk_index(sample_repo)
        goal = GoalSpec(query_id="q-3", summary="Add tests for entry function")
        lease = build_capability_lease(index, goal, top_k=3)

        ok, _ = check_repo_path_allowed("tests/test_main.py", lease, write=False)
        if ok:
            pass  # test file in scope
        ok, _ = check_repo_path_allowed("src/main.py", lease, write=False)
        assert ok, "should read the source being tested"


# ---------------------------------------------------------------------------
# Adversarial scenarios
# ---------------------------------------------------------------------------


class TestAdversarialScanning:
    """Scenario: agent does broad directory scanning (recon behavior)."""

    def test_scanning_triggers_step_up(self) -> None:
        scan = ScanningScorer(config=ScanScorerConfig(
            window=10, max_unique_dirs=3, max_unique_files=100
        ))
        dirs = [f"repo://dir{i}/file.py" for i in range(6)]
        last = None
        for ref in dirs:
            last = scan.evaluate_contract(_monitor_input(ref))
        assert last is not None
        assert last.recommendation == BehaviorRecommendation.STEP_UP

    def test_scanning_exhausts_exploration_budget(self) -> None:
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_dirs=3))
        for i in range(3):
            budget.try_consume(f"dir{i}/file.py")
        ok, reason = budget.try_consume("dir99/file.py")
        assert not ok
        assert reason == "dir_budget_exhausted"


class TestAdversarialProtectedZoneProbe:
    """Scenario: agent tries to read/write secrets, keys, deploy configs."""

    def test_secrets_write_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://keys/signing.pem"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_auth_write_denied_without_explicit_allow(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://auth/verify.py"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_step_up_then_approve_flow(self) -> None:
        gov = ProtectedZoneGovernor()
        # Denied first
        r1 = gov.decide(_ctx("repo://deploy/prod.yaml"))
        assert r1.enforcement != SandboxEnforcement.ALLOW
        # Approve via step-up
        gov.approve_resource("repo://deploy/prod.yaml")
        r2 = gov.decide(_ctx("repo://deploy/prod.yaml"))
        assert r2.enforcement == SandboxEnforcement.ALLOW

    def test_metrics_track_prevented(self) -> None:
        metrics = ScopingMetrics()
        metrics.record_action(blocked=True)
        metrics.record_prevented(protected_write=True)
        metrics.record_action(blocked=True)
        metrics.record_prevented(egress=True)
        s = metrics.summary()
        assert s["prevented"]["total"] == 2


class TestAdversarialEgress:
    """Scenario: agent attempts outbound network calls."""

    def test_egress_blocked(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("net://evil.com/exfil"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_egress_novelty_triggers(self) -> None:
        novelty = NoveltyMonitor()
        novelty.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = novelty.evaluate_contract(_monitor_input("net://evil.com/exfil"))
        assert result is not None
        assert any("network domain" in r for r in result.reasons)


class TestAdversarialDrift:
    """Scenario: agent drifts to unrelated subsystems."""

    def test_drift_triggers_after_threshold(self) -> None:
        scope = {"repo://src/main.py", "repo://src/utils.py"}
        drift = DriftScorer(scope, config=DriftScorerConfig(window=4, threshold=0.5))
        drift.evaluate_contract(_monitor_input("repo://src/main.py"))
        for _ in range(3):
            drift.evaluate_contract(_monitor_input("repo://unrelated/evil.py"))
        assert drift.out_of_scope_ratio >= 0.5

    def test_drift_auto_tightens_governor(self) -> None:
        from agentauth.receipts.behavior_monitor import BehaviorMonitorResult

        gov = TighteningGovernor(auto_tighten_on_deny=True)
        deny = BehaviorMonitorResult(
            monitor_id="drift", recommendation=BehaviorRecommendation.DENY
        )
        gov.decide(_ctx("repo://src/main.py"), monitor=deny)
        assert gov.is_tightened


class TestAdversarialNoveltyJump:
    """Scenario: agent suddenly accesses a completely new subsystem."""

    def test_new_subsystem_triggers(self) -> None:
        novelty = NoveltyMonitor()
        novelty.evaluate_contract(_monitor_input("repo://src/main.py"))
        result = novelty.evaluate_contract(_monitor_input("repo://infra/terraform/main.tf"))
        assert result is not None
        assert any("subsystem" in r for r in result.reasons)

    def test_new_tool_class_triggers(self) -> None:
        novelty = NoveltyMonitor()
        novelty.evaluate_contract(
            _monitor_input("repo://src/main.py", "mcp.tools/call/read_file")
        )
        result = novelty.evaluate_contract(
            _monitor_input("repo://src/main.py", "shell/exec/bash")
        )
        assert result is not None
        assert any("tool class" in r for r in result.reasons)


class TestEndToEndScenario:
    """Full end-to-end: index repo → scope goal → run actions → check metrics."""

    def test_full_flow(self, sample_repo: Path) -> None:
        # 1. Index
        index = build_repo_chunk_index(sample_repo)
        assert index.chunks

        # 2. Scope
        goal = GoalSpec(query_id="q-e2e", summary="Fix entry function in src/main.py")
        lease = build_capability_lease(index, goal, top_k=3)
        assert "src/main.py" in lease.write_files

        # 3. Set up monitors + governor
        scope_refs = {f"repo://{f}" for f in lease.read_files | lease.write_files}
        drift = DriftScorer(scope_refs, config=DriftScorerConfig(window=5, threshold=0.5))
        scan = ScanningScorer(config=ScanScorerConfig(window=10, max_unique_dirs=5))
        novelty = NoveltyMonitor()
        gov = ProtectedZoneGovernor(
            explicit_allow={f"repo://{f}" for f in lease.write_files}
        )
        budget = ExplorationBudget(config=ExplorationBudgetConfig(max_files=20))
        metrics = ScopingMetrics(goal_id="e2e-1")

        # 4. Simulate normal work
        actions = [
            ("repo://src/main.py", SideEffectLevel.READ_ONLY),
            ("repo://src/utils.py", SideEffectLevel.READ_ONLY),
            ("repo://src/main.py", SideEffectLevel.BOUNDED_WRITE),
        ]
        for ref, se in actions:
            dr = drift.evaluate_contract(_monitor_input(ref))
            sr = scan.evaluate_contract(_monitor_input(ref))
            nr = novelty.evaluate_contract(_monitor_input(ref))
            gr = gov.decide(_ctx(ref, se))
            budget.try_consume(ref.removeprefix("repo://"), byte_count=500)
            metrics.record_action(
                blocked=(gr.enforcement != SandboxEnforcement.ALLOW),
                is_write=(se != SideEffectLevel.READ_ONLY),
                overhead_ms=5.0,
            )

        # 5. Verify
        s = metrics.summary()
        assert s["blocked_actions"] == 0, "normal work should not be blocked"
        assert s["step_up_prompts"] == 0, "no prompts for normal work"
        assert budget.remaining_files > 0
