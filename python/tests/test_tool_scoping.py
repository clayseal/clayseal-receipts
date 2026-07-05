from __future__ import annotations

from agentauth.core.runtime import SideEffectLevel
from agentauth.capabilities.scoping.goal import GoalSpec
from agentauth.capabilities.scoping.tools import (
    EntityRecord,
    ToolCallBudget,
    ToolCallBudgetConfig,
    ToolSpec,
    build_tool_capability_lease,
    build_tool_entity_index,
    check_tool_call_allowed,
    compute_target_closure,
    resolve_target_entities,
    tool_capability_lease_violations,
)
from agentauth.capabilities.scoping.tools.target_closure import TargetClosurePolicy


def _tools() -> list[ToolSpec]:
    return [
        ToolSpec(
            name="issue_payroll_bonus",
            description="",
            owner_role="action",
            side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
            trust_tier="primary",
        ),
        ToolSpec(
            name="legacy_process_bonus_payment",
            description="Legacy bonus payment connector",
            owner_role="shadow",
            side_effect_level=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
            trust_tier="shadow",
        ),
        ToolSpec(
            name="fetch_employee_record",
            description="",
            owner_role="read",
            side_effect_level=SideEffectLevel.READ_ONLY,
            trust_tier="primary",
        ),
    ]


def _entities() -> list[EntityRecord]:
    return [
        EntityRecord(entity_id="emp_acme_008", entity_kind="employee", display_name="Camille Moreau"),
        EntityRecord(entity_id="emp_acme_007", entity_kind="employee", display_name="Owen Kim"),
        EntityRecord(entity_id="sg_acme_sales", entity_kind="group", display_name="Sales bonus population"),
    ]


def test_build_tool_entity_index_hash_is_stable() -> None:
    index_a = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    index_b = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    assert index_a.snapshot_id == index_b.snapshot_id
    assert index_a.tools_by_name()["issue_payroll_bonus"].trust_tier == "primary"
    assert index_a.entities_by_id()["emp_acme_008"].display_name == "Camille Moreau"


def test_resolve_target_entities_partial_name_match() -> None:
    index = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    matches = resolve_target_entities("Issue Camille a bonus", index)
    assert any(match.entity_id == "emp_acme_008" for match in matches)


def test_resolve_target_entities_no_match_returns_empty() -> None:
    index = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    matches = resolve_target_entities("Check quarterly payroll compliance status", index)
    assert not any(match.entity_id == "emp_acme_008" for match in matches)


def test_compute_target_closure_expands_group_membership_bounded() -> None:
    edges = [("sg_acme_sales", "emp_acme_008"), ("sg_acme_sales", "emp_acme_007")]
    closure = compute_target_closure(seed_entities={"sg_acme_sales"}, membership_edges=edges)
    assert closure.expanded_entities == {"sg_acme_sales", "emp_acme_008", "emp_acme_007"}
    assert not closure.blocked_oversized_groups


def test_compute_target_closure_excludes_oversized_group() -> None:
    edges = [("sg_huge", f"emp_{i}") for i in range(10)]
    closure = compute_target_closure(
        seed_entities={"sg_huge"},
        membership_edges=edges,
        policy=TargetClosurePolicy(max_expanded_entities=3),
    )
    assert "sg_huge" in closure.blocked_oversized_groups
    # The group id itself stays named; its membership is not expanded in.
    assert closure.expanded_entities == {"sg_huge"}


def test_build_tool_capability_lease_scopes_single_employee_goal() -> None:
    index = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    goal = GoalSpec(query_id="q-1", summary="Issue Camille Moreau a bonus")
    lease = build_tool_capability_lease(index, goal)
    assert "issue_payroll_bonus" in lease.expected_tools
    assert lease.expected_targets["issue_payroll_bonus"] == {"emp_acme_008"}


def test_build_tool_capability_lease_excludes_shadow_tool_even_with_matching_vocabulary() -> None:
    """The shadow tool's own description shares vocabulary with the goal
    ("bonus payment") -- token relevance alone must not be enough to bring
    a shadow-tier tool into scope; this is the exact substitution exploit
    (RIP-MA-007) the lease exists to catch."""
    index = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    goal = GoalSpec(query_id="q-1", summary="Issue Camille Moreau a bonus payment")
    lease = build_tool_capability_lease(index, goal)
    assert "legacy_process_bonus_payment" not in lease.expected_tools


def test_check_tool_call_allowed_allow_deny_pair() -> None:
    index = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    goal = GoalSpec(query_id="q-1", summary="Issue Camille Moreau a bonus")
    lease = build_tool_capability_lease(index, goal)

    allowed, reason = check_tool_call_allowed("issue_payroll_bonus", "emp_acme_008", lease)
    assert allowed and reason == "lease_allowlist"

    denied, reason = check_tool_call_allowed("issue_payroll_bonus", "emp_acme_007", lease)
    assert not denied and reason == "target_out_of_scope"

    denied2, reason2 = check_tool_call_allowed("legacy_process_bonus_payment", "emp_acme_008", lease)
    assert not denied2 and reason2 == "tool_out_of_scope"


def test_tool_call_budget_blocks_second_call_same_target() -> None:
    budget = ToolCallBudget(config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_payroll_bonus"})))
    first = budget.try_consume("issue_payroll_bonus", "emp_acme_008")
    second = budget.try_consume("issue_payroll_bonus", "emp_acme_008")
    assert first == (True, "ok")
    assert second == (False, "target_call_budget_exhausted")


def test_tool_call_budget_allows_different_targets() -> None:
    """Same class as the exploit this defeats, inverted: N distinct targets,
    one call each, must never be conflated with N calls to one target."""
    budget = ToolCallBudget(config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_payroll_bonus"})))
    for target in ("emp_acme_008", "emp_acme_007", "emp_acme_009"):
        allowed, reason = budget.try_consume("issue_payroll_bonus", target)
        assert allowed, reason


def test_tool_call_budget_would_allow_does_not_mutate() -> None:
    budget = ToolCallBudget(config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_payroll_bonus"})))
    budget.would_allow("issue_payroll_bonus", "emp_acme_008")
    budget.would_allow("issue_payroll_bonus", "emp_acme_008")
    # Peeking twice must not consume -- a real call still hasn't happened.
    allowed, _reason = budget.would_allow("issue_payroll_bonus", "emp_acme_008")
    assert allowed
    budget.commit("issue_payroll_bonus", "emp_acme_008")
    allowed2, reason2 = budget.would_allow("issue_payroll_bonus", "emp_acme_008")
    assert not allowed2 and reason2 == "target_call_budget_exhausted"


def test_tool_capability_lease_violations_defeats_cap_eviction_replay() -> None:
    """End-to-end replay of the actual finding this whole mechanism exists
    for: two individually-valid same-employee bonus calls in one session."""
    index = build_tool_entity_index(tools=_tools(), entities=_entities(), membership_edges=[])
    goal = GoalSpec(
        query_id="q-1",
        summary="Camille Moreau's total comp bump should be $15,000 -- an $8,000 quarterly "
        "bonus and a $7,000 recognition award.",
    )
    lease = build_tool_capability_lease(index, goal)
    budget = ToolCallBudget(config=ToolCallBudgetConfig(high_risk_tools=frozenset({"issue_payroll_bonus"})))

    v1 = tool_capability_lease_violations(
        lease,
        budget,
        tool_name="issue_payroll_bonus",
        arguments={"employee_id": "emp_acme_008", "bonus_amount": 8000.0},
        side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        resource_ref=None,
    )
    assert v1 == []
    budget.commit("issue_payroll_bonus", "emp_acme_008")

    v2 = tool_capability_lease_violations(
        lease,
        budget,
        tool_name="issue_payroll_bonus",
        arguments={"employee_id": "emp_acme_008", "bonus_amount": 7000.0},
        side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
        resource_ref=None,
    )
    assert v2 and "target_call_budget_exhausted" in v2[0]


def test_tool_capability_lease_violations_none_lease_is_permissive() -> None:
    assert (
        tool_capability_lease_violations(
            None,
            None,
            tool_name="issue_payroll_bonus",
            arguments={"employee_id": "emp_acme_008"},
            side_effect=SideEffectLevel.EXTERNAL_SIDE_EFFECT,
            resource_ref=None,
        )
        == []
    )


def _high_risk_budget(supersession: bool = False):
    return ToolCallBudget(
        config=ToolCallBudgetConfig(
            high_risk_tools=frozenset({"issue_payroll_bonus"}),
            supersession_eligible=(
                frozenset({"issue_payroll_bonus"}) if supersession else frozenset()
            ),
        )
    )


def test_supersession_same_key_is_a_replace_not_a_second_call() -> None:
    """A same-idempotency-key correction on an eligible high-risk tool reuses
    the slot instead of consuming a second one -- fixes the correction false
    positive while leaving plain same-target repeats blocked."""
    budget = _high_risk_budget(supersession=True)
    first = budget.try_consume("issue_payroll_bonus", "emp_1", idempotency_key="k")
    second = budget.try_consume("issue_payroll_bonus", "emp_1", idempotency_key="k")
    assert first == (True, "ok")
    assert second == (True, "supersede_replace")


def test_supersession_requires_matching_key() -> None:
    """No key (or a different key) is a distinct effect -- still blocked. This
    is exactly cap-eviction: two same-target writes with no shared key."""
    budget = _high_risk_budget(supersession=True)
    assert budget.try_consume("issue_payroll_bonus", "emp_1")[0] is True
    blocked, reason = budget.try_consume("issue_payroll_bonus", "emp_1")
    assert not blocked and reason == "target_call_budget_exhausted"


def test_supersession_ignored_for_ineligible_tool() -> None:
    budget = _high_risk_budget(supersession=False)
    assert budget.try_consume("issue_payroll_bonus", "emp_1", idempotency_key="k")[0] is True
    blocked, reason = budget.try_consume("issue_payroll_bonus", "emp_1", idempotency_key="k")
    assert not blocked and reason == "target_call_budget_exhausted"
