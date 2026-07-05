from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.action_monitor import SessionActionMonitor
from agentauth.receipts.certificate import dev_certificate
from agentauth.receipts.proof import DecisionOutcome


def _monitoring_policy(**overrides) -> Policy:
    raw = {
        "version": 1,
        "name": "monitored-tools",
        "tier": "tool_trace",
        "capability": "operator_attested",
        "allowed_tools": {"tools": ["read_file", "curl_url", "write_file"]},
        "output_schema": {"fields": ["status", "tool"], "required": []},
        "monitoring": {
            "enabled": True,
            "review_threshold": 0.4,
            "block_threshold": 0.85,
            "sensitive_keywords": ["curl"],
        },
        **overrides,
    }
    return Policy.from_dict(raw)


def test_session_monitor_increments_prior_action_count():
    policy = _monitoring_policy()
    cert = dev_certificate(policy.commitment(), scope=["read_file", "curl_url"])
    agent = AgentWrapper(
        model=lambda _inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    gw = ReceiptedMcpGateway(agent, server_name="repo", session_id="sess-a")
    gw.register_tool("read_file", lambda _args: {"ok": True})
    gw.register_tool("curl_url", lambda _args: {"ok": True})

    first = gw.call_tool("read_file", {"path": "AGENTS.md"})
    second = gw.call_tool("read_file", {"path": "src/a.py"})
    third = gw.call_tool("curl_url", {"url": "http://example.invalid"})

    assert first.execution_context.authority.prior_action_count == 0
    assert second.execution_context.authority.prior_action_count == 1
    assert third.execution_context.authority.prior_action_count == 2

    monitoring = third.execution_context.authorization["monitoring"]
    assert monitoring["action_index"] == 2
    assert monitoring["score"] > 0.4
    assert monitoring["review_required"] is True


def test_monitoring_escalates_to_allow_with_review():
    policy = _monitoring_policy()
    cert = dev_certificate(policy.commitment(), scope=["read_file", "curl_url"])
    agent = AgentWrapper(
        model=lambda _inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="shadow",
        audit_db=":memory:",
    )
    gw = ReceiptedMcpGateway(agent, server_name="repo", session_id="sess-review")
    gw.register_tool("read_file", lambda _args: {"ok": True})
    gw.register_tool("curl_url", lambda _args: {"ok": True})

    gw.call_tool("read_file", {"path": "a"})
    gw.call_tool("read_file", {"path": "b"})
    result = gw.call_tool("curl_url", {"url": "http://example.invalid"})

    assert result.decision.outcome == DecisionOutcome.ALLOW_WITH_REVIEW
    assert result.decision.requires_review() is True
    assert result.decision.can_execute() is True


def test_monitoring_block_threshold_denies_in_bounded_auto():
    policy = _monitoring_policy(
        monitoring={
            "enabled": True,
            "review_threshold": 0.4,
            "block_threshold": 0.5,
            "sensitive_keywords": ["curl"],
        }
    )
    cert = dev_certificate(policy.commitment(), scope=["read_file", "curl_url"])
    agent = AgentWrapper(
        model=lambda _inp: {"status": "ok"},
        policy=policy,
        certificate=cert,
        mode="bounded_auto",
        audit_db=":memory:",
    )
    gw = ReceiptedMcpGateway(agent, server_name="repo", session_id="sess-block")
    gw.register_tool("read_file", lambda _args: {"ok": True})
    gw.register_tool("curl_url", lambda _args: {"ok": True})

    monitor = agent.session_monitor
    assert monitor is not None

    for _ in range(3):
        gw.call_tool("read_file", {"path": "x"})

    result = gw.call_tool("curl_url", {"url": "http://example.invalid"})
    assert result.decision.outcome == DecisionOutcome.DENY
    assert result.blocked is True
    assert any("monitoring score" in item for item in result.policy_violations)


def test_monitoring_disabled_by_default():
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "plain",
            "tier": "tool_trace",
            "capability": "operator_attested",
            "allowed_tools": {"tools": ["read_file"]},
        }
    )
    agent = AgentWrapper(
        model=lambda _inp: {"status": "ok"},
        policy=policy,
        mode="shadow",
        audit_db=":memory:",
    )
    assert agent.session_monitor is None
