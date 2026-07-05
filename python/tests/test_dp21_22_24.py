"""Tests for DP-21 (exploration budgets), DP-22 (novelty triggers),
DP-24 (tighten mode)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.receipts.monitor_contract import MonitorInput, MonitorTraceEvent
from agentauth.receipts.novelty_monitor import NoveltyConfig, NoveltyMonitor
from agentauth.core.runtime import (
    ActionDescriptor,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)
from agentauth.receipts.sandbox_governor import NullSandboxGovernor, SandboxEnforcement
from agentauth.receipts.tighten_policy import TighteningGovernor
from agentauth.capabilities.scoping.exploration_budget import ExplorationBudget, ExplorationBudgetConfig


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
    side_effect: SideEffectLevel = SideEffectLevel.BOUNDED_WRITE,
) -> ExecutionContext:
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            side_effect_level=side_effect,
        ),
        input={},
        authority=AuthorityContext(
            authority_id="test-auth",
            expires_at=future,
        ),
    )


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
        # No resource ref → no subsystem/domain/protected triggers
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

        result = gov.decide(_ctx(side_effect=SideEffectLevel.BOUNDED_WRITE))
        assert result.enforcement == SandboxEnforcement.STEP_UP
        assert any("tighten_mode" in v for v in result.extra_violations)

    def test_tighten_allows_reads(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test")

        result = gov.decide(_ctx(side_effect=SideEffectLevel.READ_ONLY))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_exit_tighten_mode_allows_writes(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test")
        gov.exit_tighten_mode()
        assert not gov.is_tightened

        result = gov.decide(_ctx(side_effect=SideEffectLevel.BOUNDED_WRITE))
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
        gov.decide(_ctx(), monitor=deny)
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
        gov.decide(_ctx(), monitor=deny)
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
        gov.decide(_ctx(), monitor=step_up)
        assert not gov.is_tightened

    def test_tighten_persists_across_calls(self) -> None:
        gov = TighteningGovernor(inner=NullSandboxGovernor())
        gov.enter_tighten_mode("test")

        for _ in range(5):
            result = gov.decide(_ctx(side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT))
            assert result.enforcement == SandboxEnforcement.STEP_UP
        assert gov.is_tightened
