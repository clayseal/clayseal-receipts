"""Gateway-level integration test: mint_tool_capability_lease wired through
ReceiptedMcpGateway._pre_execution_violations, confirming it's a genuine
blocking check (not just a computed-but-unused value) and that budget
consumption is correctly deferred until a call is confirmed non-blocked."""

from __future__ import annotations

from agentauth.receipts import AgentWrapper, Policy, ReceiptedMcpGateway
from agentauth.receipts.certificate import dev_certificate
from agentauth.capabilities.scoping.tools import EntityRecord, ToolCallBudgetConfig


def _gateway() -> tuple[AgentWrapper, ReceiptedMcpGateway]:
    policy = Policy.from_dict(
        {
            "version": 1,
            "name": "test-tool-lease",
            "tier": "structural",
            "capability": "fully_proven",
            "allowed_tools": {"tools": ["issue_bonus", "not_a_real_tool"]},
        }
    )
    cert = dev_certificate(policy.commitment(), scope=["issue_bonus", "not_a_real_tool"])

    def model(inp: dict) -> dict:
        return {}

    agent = AgentWrapper(
        model=model, policy=policy, certificate=cert, mode="bounded_auto", audit_db=":memory:"
    )
    gw = ReceiptedMcpGateway(agent, server_name="test-server", query_id="q-1")
    gw.register_tool("issue_bonus", lambda args: {"recorded": True})
    return agent, gw


def test_tool_capability_lease_blocks_second_same_target_call():
    _agent, gw = _gateway()
    lease = gw.mint_tool_capability_lease(
        {"query_id": "q-1", "summary": "Issue Camille a bonus"},
        entities=[EntityRecord(entity_id="emp_1", entity_kind="employee", display_name="Camille Moreau")],
        budget_config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_bonus"})),
    )
    assert "issue_bonus" in lease.expected_tools
    assert lease.expected_targets["issue_bonus"] == {"emp_1"}

    first = gw.call_tool("issue_bonus", {"employee_id": "emp_1", "amount": 100})
    assert first.blocked is False

    second = gw.call_tool("issue_bonus", {"employee_id": "emp_1", "amount": 100})
    assert second.blocked is True
    assert any("target_call_budget_exhausted" in v for v in second.policy_violations)


def test_tool_capability_lease_blocks_out_of_scope_target():
    _agent, gw = _gateway()
    gw.mint_tool_capability_lease(
        {"query_id": "q-1", "summary": "Issue Camille a bonus"},
        entities=[
            EntityRecord(entity_id="emp_1", entity_kind="employee", display_name="Camille Moreau"),
            EntityRecord(entity_id="emp_2", entity_kind="employee", display_name="Owen Kim"),
        ],
    )
    result = gw.call_tool("issue_bonus", {"employee_id": "emp_2", "amount": 100})
    assert result.blocked is True
    assert any("target_out_of_scope" in v for v in result.policy_violations)


def test_tool_capability_lease_blocked_call_does_not_consume_budget():
    """A call blocked by an *unrelated* check (unregistered tool, in this
    case) must not have already consumed budget -- confirms the deferred
    commit (only right before the handler actually runs) is correctly
    wired, not applied eagerly during the pre-execution violations pass."""
    _agent, gw = _gateway()
    gw.mint_tool_capability_lease(
        {"query_id": "q-1", "summary": "Issue Camille a bonus"},
        entities=[EntityRecord(entity_id="emp_1", entity_kind="employee", display_name="Camille Moreau")],
        budget_config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_bonus"})),
    )
    budget = gw.active_tool_call_budget()
    assert budget.calls == {}

    # A call to an unregistered tool name is blocked for an unrelated
    # reason before the lease/budget check would even matter for it, but
    # confirms no phantom consumption happens on the *real* tool's budget.
    unregistered = gw.call_tool("not_a_real_tool", {"employee_id": "emp_1"})
    assert unregistered.blocked is True
    assert budget.calls == {}

    real = gw.call_tool("issue_bonus", {"employee_id": "emp_1", "amount": 100})
    assert real.blocked is False
    assert budget.calls == {("issue_bonus", "emp_1"): 1}


def test_no_lease_means_no_enforcement():
    """Existing callers that never mint a tool capability lease are
    unaffected -- this is additive, opt-in behavior."""
    _agent, gw = _gateway()
    result = gw.call_tool("issue_bonus", {"employee_id": "emp_1", "amount": 100})
    assert result.blocked is False


def _lease_gateway_with_handler_recorder():
    _agent, gw = _gateway()
    ran: list[dict] = []

    def handler(args: dict) -> dict:
        ran.append(args)
        return {"recorded": True}

    gw.register_tool("issue_bonus", handler)
    gw.mint_tool_capability_lease(
        {"query_id": "q-1", "summary": "Issue Camille a bonus"},
        entities=[
            EntityRecord(entity_id="emp_1", entity_kind="employee", display_name="Camille Moreau")
        ],
        budget_config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_bonus"})),
    )
    return gw, ran


def test_gate_blocks_when_reservation_denied_after_precheck(monkeypatch):
    """The atomic reservation at the gate must block a call that loses the
    budget race even though the non-mutating pre-check passed -- this is the
    check/commit TOCTOU the reserve() gate defeats. We simulate the race by
    forcing reserve() to deny after would_allow() has already passed, and
    assert the handler never runs and no budget is consumed."""
    from agentauth.capabilities.scoping.tools import ToolCallReservation

    gw, ran = _lease_gateway_with_handler_recorder()
    budget = gw.active_tool_call_budget()
    monkeypatch.setattr(
        budget,
        "reserve",
        lambda *a, **k: ToolCallReservation(False, "target_call_budget_exhausted"),
    )

    result = gw.call_tool("issue_bonus", {"employee_id": "emp_1", "amount": 100})
    assert result.blocked is True
    assert any("target_call_budget_exhausted" in v for v in result.policy_violations)
    assert ran == []  # denied at the gate: the handler must not execute
    assert budget.calls == {}  # nothing consumed


def test_async_gate_blocks_when_reservation_denied_after_precheck(monkeypatch):
    """Async variant of the reserve-deny gate (call_tool_async is wired the
    same way as the sync path)."""
    import asyncio

    from agentauth.capabilities.scoping.tools import ToolCallReservation

    gw, ran = _lease_gateway_with_handler_recorder()
    budget = gw.active_tool_call_budget()
    monkeypatch.setattr(
        budget,
        "reserve",
        lambda *a, **k: ToolCallReservation(False, "target_call_budget_exhausted"),
    )

    result = asyncio.run(gw.call_tool_async("issue_bonus", {"employee_id": "emp_1", "amount": 100}))
    assert result.blocked is True
    assert any("target_call_budget_exhausted" in v for v in result.policy_violations)
    assert ran == []
    assert budget.calls == {}
