# Execution context (L3-3)

Agent Receipts separates **model input** from **authority-bearing runtime context**. The boundary is `ExecutionContext`.

## Structure

```python
from agentauth.receipts import (
    ActionDescriptor,
    ActorKind,
    ActorRef,
    AuthorityContext,
    ExecutionContext,
    SideEffectLevel,
)

ctx = ExecutionContext(
    action=ActionDescriptor(
        action_name="payments.refund",
        action_category="payments",
        resource_type="transaction",
        resource_ref="transaction:txn-42",
        side_effect_level=SideEffectLevel.BOUNDED_WRITE,
    ),
    input={"amount_usd": 250.0},  # model / tool input only
    authority=AuthorityContext(
        authority_id="grant-prod-1",
        authority_version=3,
        session_id="sess-abc",
        prior_action_count=2,
        actor_ref=ActorRef(
            kind=ActorKind.AUTHORITY_BEARING_SUBAGENT,
            actor_id="worker-7",
        ),
        resource_scope=["transaction:txn-42"],
        budget_refs=["usd-daily"],
        approval_refs=["approval-88"],
    ),
    authorization={"mcp_server": "fraud", "tool_name": "score_transaction"},
    touched_resources=["transaction:txn-42"],
)
```

## AgentWrapper usage

`AgentWrapper.record()` accepts either a dict (legacy) or an `ExecutionContext`:

```python
result = agent.record(
    action=ctx.action,
    context=ctx,
    output={"decision": "approve", "fraud_score": 0.1},
)
```

Dict context remains supported for backward compatibility:

```python
result = agent.record(
    action="agent.run",
    context={
        "input": {"transaction_id": "t1"},
        "authority": {"authority_id": "grant-1", "session_id": "s1"},
        "touched_resources": ["transaction:t1"],
    },
    output={...},
)
```

## L1 alignment

`AuthorityContext` can also carry normalized identity-side facts so Layer 1 and Layers 3/4 share the same foundation while L2 evolves:

- `subject_id`
- `issuer`
- `tenant_id`
- `subject_type`
- `owner_ref`
- `workload_principal`
- `capabilities`
- `scope_claims`
- `capability_rules`
- `selectors`
- `attestation_type`
- `delegation_chain`
- `expires_at`
- `trust_tier`
- `proof_of_possession`

The normalized handoff object is documented in [l1_l3l4_boundary.md](l1_l3l4_boundary.md).

## Receipt placement (v2)

| Field | Location |
|-------|----------|
| Structured action | `action` |
| Authority snapshot | `authority` |
| Full runtime context | `execution_context` (optional, for replay) |
| Session binding | `session` |

## Resource references

Use scoped (`kind:value`) or URI (`kind://value`) forms via `format_resource_ref()` / `parse_resource_ref()` in `resource_refs.py`. `ActionDescriptor.parsed_resource_ref()` parses `resource_ref`.

## Related docs

- [decision_model.md](decision_model.md) — decision outcomes, obligations, budgets
- [backward_compatibility.md](backward_compatibility.md) — dict vs structured context migration
