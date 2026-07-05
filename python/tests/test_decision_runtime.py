from agentauth.core.decision import (
    ApprovalMetadata,
    ApprovalState,
    BudgetEffect,
    DecisionResult,
    Obligation,
)
from agentauth.receipts.proof import DecisionOutcome
from agentauth.core.runtime import (
    ActionDescriptor,
    ActorKind,
    ActorRef,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)


def test_decision_result_roundtrip_with_obligations_and_budget_effects():
    decision = DecisionResult(
        outcome=DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
        policy_satisfied=True,
        violations=[],
        obligations=[
            Obligation(
                type="notify_reviewer",
                status="pending",
                details={"channel": "slack"},
                required_after_effect=True,
            )
        ],
        recommended_action="queue_follow_up",
        approval_state=ApprovalState.PENDING,
        approval_metadata=ApprovalMetadata(
            approval_id="approval-123",
            approval_policy_ref="deploy-prod",
        ),
        budget_effects=[
            BudgetEffect(
                budget_id="refunds-usd",
                effect_type="reserve",
                amount=250.0,
                status="planned",
                notes="awaiting approval",
            )
        ],
        authority_version=4,
        session_id="sess-roundtrip",
    )

    restored = DecisionResult.from_dict(decision.to_dict())

    assert restored == decision
    assert restored.obligations[0].details["channel"] == "slack"
    assert restored.budget_effects[0].amount == 250.0
    assert restored.approval_metadata is not None
    assert restored.approval_metadata.approval_id == "approval-123"


def test_decision_result_execution_helpers_cover_pending_and_blocking_states():
    pending = DecisionResult(
        outcome=DecisionOutcome.PENDING_APPROVAL,
        policy_satisfied=True,
        approval_state=ApprovalState.PENDING,
    )
    assert pending.requires_approval() is True
    assert pending.can_execute() is False

    blocked = DecisionResult(
        outcome=DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
        policy_satisfied=True,
        approval_state=ApprovalState.NOT_REQUIRED,
        obligations=[
            Obligation(
                type="persist_handoff",
                status="pending",
                required_before_effect=True,
            ),
            Obligation(
                type="emit_summary",
                status="completed",
                required_before_effect=True,
            ),
        ],
    )
    assert [item.type for item in blocked.blocking_obligations()] == ["persist_handoff"]
    assert [item.type for item in blocked.pending_obligations()] == ["persist_handoff"]
    assert blocked.can_execute() is False

    executable = DecisionResult(
        outcome=DecisionOutcome.ALLOW,
        policy_satisfied=True,
        approval_state=ApprovalState.APPROVED,
        obligations=[
            Obligation(
                type="create_case",
                status="pending",
                required_after_effect=True,
            )
        ],
    )
    assert executable.requires_approval() is False
    assert [item.type for item in executable.after_effect_obligations()] == ["create_case"]
    assert executable.can_execute() is True


def test_obligation_status_helpers_distinguish_blocking_and_follow_up_work():
    before = Obligation(
        type="persist_handoff",
        status="pending",
        required_before_effect=True,
    )
    after = Obligation(
        type="emit_summary",
        status="pending",
        required_after_effect=True,
    )
    fulfilled = Obligation(
        type="create_case",
        status="completed",
        required_before_effect=True,
    )

    assert before.is_pending() is True
    assert before.blocks_before_effect() is True
    assert before.requires_after_effect_follow_up() is False

    assert after.blocks_before_effect() is False
    assert after.requires_after_effect_follow_up() is True

    assert fulfilled.is_fulfilled() is True
    assert fulfilled.blocks_before_effect() is False

    decision = DecisionResult(
        outcome=DecisionOutcome.ALLOW_WITH_OBLIGATIONS,
        policy_satisfied=True,
        obligations=[before, after, fulfilled],
    )
    summary = decision.obligation_summary()
    assert [item.type for item in summary.pending] == ["persist_handoff", "emit_summary"]
    assert [item.type for item in summary.blocking] == ["persist_handoff"]
    assert [item.type for item in summary.after_effect] == ["emit_summary"]
    assert decision.obligation_section() == {
        "all": [item.to_dict() for item in [before, after, fulfilled]],
        "pending": [item.to_dict() for item in [before, after]],
        "blocking": [before.to_dict()],
        "after_effect": [after.to_dict()],
    }


def test_budget_effect_helpers_distinguish_pending_final_and_reservations():
    decision = DecisionResult(
        outcome=DecisionOutcome.BUDGET_RESERVATION_REQUIRED,
        policy_satisfied=True,
        budget_effects=[
            BudgetEffect(
                budget_id="usd-daily",
                effect_type="reserve",
                amount=100,
                status="planned",
            ),
            BudgetEffect(
                budget_id="usd-daily",
                effect_type="consume",
                amount=25,
                status="committed",
            ),
            BudgetEffect(
                budget_id="usd-daily",
                effect_type="release",
                amount=75,
                status="released",
            ),
        ],
    )

    assert decision.requires_budget_reservation() is True
    assert len(decision.budget_effects_for("usd-daily")) == 3
    assert [item.effect_type for item in decision.pending_budget_effects()] == ["reserve"]
    assert [item.effect_type for item in decision.final_budget_effects()] == [
        "consume",
        "release",
    ]
    assert [item.effect_type for item in decision.reservation_budget_effects()] == [
        "reserve"
    ]
    assert decision.budget_effects[1].is_consumption() is True
    assert decision.budget_effects[2].is_release() is True

    summaries = decision.summarize_budget_effects()
    assert summaries["usd-daily"].pending_amount == 100.0
    assert summaries["usd-daily"].final_amount == 100.0
    assert summaries["usd-daily"].reserved_amount == 100.0
    assert summaries["usd-daily"].consumed_amount == 25.0
    assert summaries["usd-daily"].released_amount == 75.0
    assert decision.budget_summary_dict()["usd-daily"]["consumed_amount"] == 25.0
    assert decision.budget_section() == {
        "effects": [effect.to_dict() for effect in decision.budget_effects],
        "summary": decision.budget_summary_dict(),
    }


def test_execution_context_roundtrip_with_actor_lineage():
    context = ExecutionContext(
        action=ActionDescriptor(
            action_name="cloud.deploy",
            action_category="deployment",
            resource_type="service",
            resource_ref="payments-api",
            side_effect_level=SideEffectLevel.PRIVILEGED_MUTATION,
        ),
        input={"release_id": "rel-42"},
        authority=AuthorityContext(
            authority_id="grant-prod-1",
            authority_version=7,
            session_id="sess-deploy",
            prior_action_count=3,
            actor_ref=ActorRef(
                kind=ActorKind.AUTHORITY_BEARING_SUBAGENT,
                actor_id="deployer-1",
                display_name="Deploy Worker",
            ),
            parent_actor_ref=ActorRef(
                kind=ActorKind.TOP_LEVEL_AGENT,
                actor_id="planner-1",
                display_name="Planner",
            ),
            resource_scope=["service:payments-api"],
            budget_refs=["deploy-budget"],
            approval_refs=["approval-77"],
        ),
        authorization={"policy": "prod_deploy", "decision_id": "dec-1"},
        touched_resources=["service:payments-api", "env:prod"],
    )

    restored = ExecutionContext.from_dict(context.to_dict())

    assert restored == context
    assert restored.authority.actor_ref is not None
    assert restored.authority.actor_ref.kind == ActorKind.AUTHORITY_BEARING_SUBAGENT
    assert restored.authority.prior_action_count == 3
    assert restored.action.side_effect_level == SideEffectLevel.PRIVILEGED_MUTATION
