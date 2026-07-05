"""Tests for DP-23 (protected-zone governor), DP-30 (step-up protocol),
DP-40 (success metrics)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

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
from agentauth.receipts.sandbox_governor import NullSandboxGovernor, SandboxEnforcement
from agentauth.capabilities.step_up import (
    StepUpApproval,
    StepUpRequest,
    apply_step_up,
    build_step_up_request,
)
from agentauth.capabilities.scoping.metrics import ScopingMetrics


def _future() -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()


def _ctx(
    resource_ref: str = "repo://src/main.py",
    side_effect: SideEffectLevel = SideEffectLevel.EXTERNAL_SIDE_EFFECT,
    approval_refs: list[str] | None = None,
) -> ExecutionContext:
    return ExecutionContext(
        action=ActionDescriptor(
            action_name="mcp.tools/call/write_file",
            action_category="mcp_tool_call",
            resource_ref=resource_ref,
            side_effect_level=side_effect,
        ),
        input={},
        authority=AuthorityContext(
            authority_id="test-auth",
            expires_at=_future(),
            approval_refs=approval_refs or [],
        ),
    )


# ---------------------------------------------------------------------------
# DP-23: Protected-zone governor
# ---------------------------------------------------------------------------


class TestProtectedZoneGovernor:
    def test_normal_resource_passes_through(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://src/main.py"))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_protected_write_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://keys/secret.pem"))
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("protected_zone" in v for v in result.extra_violations)

    def test_protected_read_requires_step_up(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx("repo://keys/secret.pem", side_effect=SideEffectLevel.READ_ONLY)
        )
        assert result.enforcement == SandboxEnforcement.STEP_UP

    def test_egress_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("net://evil.com/exfil"))
        assert result.enforcement == SandboxEnforcement.DENY
        assert any("egress" in v for v in result.extra_violations)

    def test_explicit_allow_overrides(self) -> None:
        gov = ProtectedZoneGovernor(explicit_allow={"repo://keys/secret.pem"})
        result = gov.decide(_ctx("repo://keys/secret.pem"))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_explicit_allow_glob(self) -> None:
        gov = ProtectedZoneGovernor(explicit_allow={"repo://auth/*"})
        result = gov.decide(_ctx("repo://auth/verify.py"))
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_approval_ref_overrides(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(
            _ctx("repo://keys/secret.pem", approval_refs=["repo://keys/secret.pem"])
        )
        assert result.enforcement == SandboxEnforcement.ALLOW

    def test_step_up_approval_recorded(self) -> None:
        gov = ProtectedZoneGovernor()
        result1 = gov.decide(_ctx("repo://deploy/prod.yaml"))
        assert result1.enforcement != SandboxEnforcement.ALLOW

        gov.approve_resource("repo://deploy/prod.yaml")
        result2 = gov.decide(_ctx("repo://deploy/prod.yaml"))
        assert result2.enforcement == SandboxEnforcement.ALLOW

    def test_auth_directory_is_protected(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://auth/login.py"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_env_file_is_protected(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://.env.production"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_github_workflow_is_protected(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("repo://.github/workflows/ci.yml"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_secrets_scheme_denied(self) -> None:
        gov = ProtectedZoneGovernor()
        result = gov.decide(_ctx("secrets://aws/prod-key"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_delegates_to_inner(self) -> None:
        class _AlwaysDeny:
            def decide(self, ctx, *, monitor=None, structural_violations=None):
                from agentauth.receipts.sandbox_governor import SandboxGovernorResult

                return SandboxGovernorResult(
                    enforcement=SandboxEnforcement.DENY,
                    extra_violations=["inner: denied"],
                )

        gov = ProtectedZoneGovernor(inner=_AlwaysDeny())
        result = gov.decide(_ctx("repo://src/main.py"))
        assert result.enforcement == SandboxEnforcement.DENY

    def test_custom_patterns(self) -> None:
        config = ProtectedZoneConfig(
            protected_patterns=("repo://custom_secrets/*",),
        )
        gov = ProtectedZoneGovernor(config=config)
        result = gov.decide(_ctx("repo://custom_secrets/key.txt"))
        assert result.enforcement == SandboxEnforcement.DENY
        result2 = gov.decide(_ctx("repo://keys/safe.pem"))
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
        """Full flow: governor denies → build request → approve → re-check passes."""
        gov = ProtectedZoneGovernor()

        # 1. First attempt: denied
        ctx1 = _ctx("repo://deploy/prod.yaml")
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
        ctx2 = _ctx("repo://deploy/prod.yaml")
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
