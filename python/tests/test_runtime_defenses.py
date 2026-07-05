"""Tests for merge binding, governed runtime, hermetic runner, context fetch, session tokens."""

from __future__ import annotations

import json
from pathlib import Path

from agentauth.receipts.action_monitor import (
    MonitoredAction,
    MonitoringPolicy,
    evaluate_heuristic_suspiciousness,
)
from agentauth.receipts.context_fetch import ContextSourcePolicy, fetch_external_context
from agentauth.receipts.governed_runtime import (
    GovernedRuntimePolicy,
    evaluate_governed_tool_call,
)
from agentauth.receipts.hermetic_runner import (
    HermeticRunnerPolicy,
    evaluate_test_execution_posture,
    hermetic_child_env,
)
from agentauth.receipts.merge_binding import MergeBindingPolicy, evaluate_merge_eligibility
from agentauth.core.runtime import SideEffectLevel
from agentauth.receipts.session_token import (
    SessionTokenPolicy,
    mint_session_credential,
    verify_session_credential,
)

ROOT = Path(__file__).resolve().parents[2]


def test_merge_eligibility_blocks_stale_sha_and_review_flags():
    receipt = {
        "decision": {"outcome": "allow_with_review", "review_required": True},
        "evaluations": [],
        "flags": [{"code": "mandate_anomaly", "message": "test"}],
        "git": {"evaluated_head_sha": "aaa", "head_sha": "aaa"},
    }
    policy = MergeBindingPolicy(block_on_review_flags=True)
    stale = evaluate_merge_eligibility(
        receipt, policy=policy, merge_head_sha="bbb", verify_signature=False
    )
    assert stale.allowed is False
    assert any("merge head" in issue for issue in stale.issues)
    assert any("mandate_anomaly" in issue for issue in stale.issues)


def test_merge_eligibility_allows_clean_allow_receipt():
    receipt = {
        "decision": {"outcome": "allow", "review_required": False},
        "evaluations": [],
        "flags": [],
        "git": {"evaluated_head_sha": "deadbeef", "head_sha": "deadbeef"},
    }
    ok = evaluate_merge_eligibility(
        receipt, merge_head_sha="deadbeef", verify_signature=False
    )
    assert ok.allowed is True


def test_governed_runtime_blocks_ungoverned_tool_calls():
    policy = GovernedRuntimePolicy(require_gateway=True)
    violations = evaluate_governed_tool_call(
        action_name="mcp.default/issue_refund",
        policy=policy,
        gateway_token=None,
    )
    assert violations
    assert (
        evaluate_governed_tool_call(
            action_name="mcp.default/issue_refund",
            policy=policy,
            gateway_token="receipted_mcp_gateway",
        )
        == []
    )


def test_hermetic_env_disables_user_site():
    env = hermetic_child_env(policy=HermeticRunnerPolicy(require_hermetic_python=True))
    assert env.get("PYTHONNOUSERSITE") == "1"
    assert env.get("PYTHONSAFEPATH") == "1"


def test_evaluate_test_execution_posture_fails_closed_without_sandbox(monkeypatch):
    monkeypatch.setattr(
        "agentauth.receipts.hermetic_runner.detect_egress_sandbox",
        lambda: ([], None),
    )
    violations = evaluate_test_execution_posture(
        policy=HermeticRunnerPolicy(require_egress_isolation=True),
        commands=["make test"],
    )
    assert violations
    assert "required_tests_unsandboxed" in violations[0]


def test_context_fetch_records_untrusted_surface():
    _body, surface, violations = fetch_external_context(
        "http://127.0.0.1:9/unreachable",
        source_type="wiki",
        policy=ContextSourcePolicy(allowed_hosts=["example.com"]),
    )
    assert not surface.trusted
    assert violations


def test_session_credential_binds_to_session():
    secret = b"test-session-secret"
    token, _cred = mint_session_credential(
        "sess-1", secret=secret, policy=SessionTokenPolicy()
    )
    verified = verify_session_credential(
        token, secret=secret, session_id="sess-1", policy=SessionTokenPolicy()
    )
    assert verified["valid"] is True
    wrong = verify_session_credential(
        token, secret=secret, session_id="sess-2", policy=SessionTokenPolicy()
    )
    assert wrong["valid"] is False


def test_monitoring_class_thresholds_lower_bar_for_external_side_effects():
    monitoring = MonitoringPolicy(
        enabled=True,
        review_threshold=0.8,
        thresholds_by_side_effect={
            "EXTERNAL_SIDE_EFFECT": {"review": 0.3},
        },
    )
    history = [
        MonitoredAction(
            action_name="read_file",
            action_category="read",
            resource_ref="file:a.txt",
            side_effect_level=SideEffectLevel.READ_ONLY,
        ),
        MonitoredAction(
            action_name="read_file",
            action_category="read",
            resource_ref="file:b.txt",
            side_effect_level=SideEffectLevel.READ_ONLY,
        ),
    ]
    current = MonitoredAction(
        action_name="curl_exfil",
        action_category="network",
        resource_ref="https://evil.example",
        side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        tool_name="curl_post",
    )
    signal = evaluate_heuristic_suspiciousness(
        history, current, monitoring=monitoring, task_summary="normalize tickets"
    )
    assert signal.review_required is True


def test_merge_policy_in_default_gate_json():
    policy = json.loads(
        (
            ROOT
            / "examples/devin-agentauth-demo/gated/.agentauth/policies/devin-pr-gate.policy.json"
        ).read_text()
    )
    assert "merge_policy" in policy
    assert "cross_session_poison_attribution" in policy["merge_policy"]["hard_block_flag_codes"]
