from __future__ import annotations

from pathlib import Path
from typing import Any

from agentauth.receipts.monitor_contract import build_monitor_input
from agentauth.core.runtime import ActionDescriptor, AuthorityContext, ExecutionContext, SideEffectLevel
from agentauth.receipts.behavior_monitor import (
    BehaviorMonitorResult,
    BehaviorMonitorWithContract,
    BehaviorRecommendation,
)
from agentauth.receipts.sandbox_governor import RuleBasedSandboxGovernor
from agentauth.receipts import Policy, ReceiptedMcpGateway
from agentauth.receipts.wrapper import AgentWrapper

ROOT = Path(__file__).resolve().parents[2]


def _ctx_with_secret_args() -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/send_email",
            action_category="mcp_tool_call",
            resource_type="mcp_tool",
            resource_ref="server:send_email",
            side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        ),
        input={"to": "alice@example.com", "body": "SECRET_DO_NOT_LEAK"},
        authority=AuthorityContext(authority_id="a", authority_version=1),
        query_id="q-1",
        authorization=None,
        touched_resources=["mcp://server/send_email"],
    )


def test_monitor_input_contract_excludes_raw_args_by_default() -> None:
    ctx = _ctx_with_secret_args()
    contract = build_monitor_input(ctx)
    payload = contract.to_dict()

    assert payload["schema"] == "agent-receipts.monitor-input.v1"
    assert payload["proposed"]["arguments_hash"].startswith("sha256:")
    assert "SECRET_DO_NOT_LEAK" not in str(payload)


class _AlwaysStepUpMonitor(BehaviorMonitorWithContract):
    def evaluate_contract(self, contract: Any) -> BehaviorMonitorResult | None:
        return BehaviorMonitorResult(
            monitor_id="test_monitor",
            monitor_version="v1",
            detector_family="test",
            feature_set_id="monitor_input_v1",
            risk_score=1.0,
            threshold=0.5,
            recommendation=BehaviorRecommendation.STEP_UP,
            reasons=["suspicious"],
            trace_commitment=None,
        )


class _LegacySecretSniffingMonitor:
    def evaluate(self, ctx: Any) -> BehaviorMonitorResult | None:
        if "SECRET_DO_NOT_LEAK" in str(getattr(ctx, "input", "")):
            return BehaviorMonitorResult(
                monitor_id="legacy_secret_sniffer",
                monitor_version="v1",
                detector_family="test",
                feature_set_id="legacy_ctx_v0",
                risk_score=0.0,
                threshold=0.5,
                recommendation=BehaviorRecommendation.ALLOW,
                reasons=["saw secret; allowing (this is intentionally wrong)"],
                trace_commitment=None,
            )
        return BehaviorMonitorResult(
            monitor_id="legacy_secret_sniffer",
            monitor_version="v1",
            detector_family="test",
            feature_set_id="legacy_ctx_v0",
            risk_score=1.0,
            threshold=0.5,
            recommendation=BehaviorRecommendation.STEP_UP,
            reasons=["did not see secret; stepping up"],
            trace_commitment=None,
        )


def test_gateway_fills_trace_commitment_on_monitor_results() -> None:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")

    agent = AgentWrapper(
        model=lambda _inp: {"ok": True},
        policy=policy,
        mode="shadow",
    )
    gw = ReceiptedMcpGateway(
        agent,
        behavior_monitor=_AlwaysStepUpMonitor(),
    )
    gw.register_tool("noop", lambda _args: {"ok": True})

    result = gw.call_tool("noop", {})
    monitoring = result.execution_context.monitoring
    assert isinstance(monitoring, dict)
    assert monitoring.get("trace_commitment", "").startswith("sha256:")


def test_legacy_monitors_do_not_receive_raw_args() -> None:
    ctx = _ctx_with_secret_args()
    contract = build_monitor_input(ctx)
    monitor = _LegacySecretSniffingMonitor()

    # The legacy monitor is called, but it only sees the sanitized args_hash.
    from agentauth.receipts.behavior_monitor import evaluate_behavior_monitor

    result = evaluate_behavior_monitor(monitor, ctx=ctx, contract=contract)
    assert result is not None
    assert result.recommendation == BehaviorRecommendation.STEP_UP


def test_governor_can_suspend_lease_renewal_on_suspicion() -> None:
    policy = Policy.from_yaml(ROOT / "policies" / "fraud_decision.yaml")
    agent = AgentWrapper(
        model=lambda _inp: {"ok": True},
        policy=policy,
        mode="shadow",
    )
    governor = RuleBasedSandboxGovernor(
        lease_ttl_seconds=60,
        lease_call_budget=3,
        require_active_lease=False,
        suspend_lease_renewal_on_suspicion=True,
        honor_monitor_recommendations=False,
    )
    gw = ReceiptedMcpGateway(
        agent,
        behavior_monitor=_AlwaysStepUpMonitor(),
        sandbox_governor=governor,
    )
    gw.register_tool("noop", lambda _args: {"ok": True})

    result = gw.call_tool("noop", {})
    sandboxing = result.execution_context.sandboxing
    assert isinstance(sandboxing, dict)
    assert sandboxing.get("authority_patch") is None
