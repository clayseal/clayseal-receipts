# Decision model (L3)

Agent Receipts separates **what was decided** from **what was cryptographically proven**. The lower-layer decision objects live in Python (`agentauth.receipts.decision`, `agentauth.receipts.runtime`) and appear on exported receipts under `decision`, `authority`, `action`, and optional `approval` / `budget` sections.

## DecisionResult

`DecisionResult` is the canonical decision object embedded in `RunResult` and serialized to receipt bundles.

| Field | Purpose |
|-------|---------|
| `outcome` | Portable decision vocabulary (`DecisionOutcome`) |
| `policy_satisfied` | Whether committed policy rules passed at execution time |
| `violations` | Human-readable policy violation strings |
| `obligations` | Structured follow-up conditions on an allow |
| `recommended_action` | Operator hint (e.g. abstain in recommend mode) |
| `approval_state` | Workflow state (`ApprovalState`) |
| `approval_metadata` | Optional approval IDs and approver refs |
| `budget_effects` | Recorded budget reservations/consumption |
| `authority_version` | Monotonic authority snapshot version |
| `session_id` | Session binding for the action |

Helper methods:

- `requires_review()` — monitoring escalated to `allow_with_review`
- `can_execute()` — whether downstream side effects should proceed
- `blocking_obligations()` — obligations with `required_before_effect` not yet fulfilled
- `budget_section()` — `{effects, summary}` for v2 `budget` export
- `summarize_budget_effects()` — per-`budget_id` rollups

## DecisionOutcome vocabulary

Initial supported outcomes:

| Outcome | Meaning |
|---------|---------|
| `allow` | Policy satisfied; no extra gates |
| `deny` | Policy failed or execution gate blocked |
| `pending_approval` | Human/workflow approval required |
| `pending_step_up` | Stronger auth required |
| `allow_with_obligations` | Allowed with recorded follow-ups |
| `allow_with_review` | Policy satisfied but monitoring flagged human review |
| `budget_reservation_required` | Budget hold required before effect |

Set intentionally in `AgentWrapper.record()` via `PolicyEngine` + reservation callback.

## ExecutionContext and AuthorityContext

`ExecutionContext` wraps:

- structured `ActionDescriptor` (name, category, resource, side-effect level)
- model `input` dict
- `AuthorityContext` (authority id/version, session, actor lineage, budget/approval refs)
- optional MCP `authorization` transport block
- `touched_resources` for audit/replay

Use `ExecutionContext` when callers need to distinguish model input from authority-bearing metadata.

## Approval

- `ApprovalState`: `not_required`, `required`, `pending`, `approved`, `rejected`, `expired`
- `ApprovalMetadata`: optional workflow IDs (`approval_id`, `approver_ref`, …)
- `infer_approval_state()` derives state from outcome when not explicit
- v2 receipts surface approval under top-level `approval` when non-trivial

In `bounded_auto` mode, `DecisionResult.can_execute()` gates side effects: pending approval, step-up, budget reservation, or blocking obligations cause abstain/deny even when policy rules pass. A denied bounded-auto action returns a schema-neutral blocked sentinel:

```json
{
  "decision": "abstain",
  "abstain_reason": "policy_violation",
  "blocked": true,
  "original_output_hash": "..."
}
```

The original model/tool output is committed by hash but is not passed through to callers.

## Obligations

Structured `Obligation` objects replace raw strings:

```yaml
type: create_case
status: pending
required_before_effect: true
details: { queue: fraud-review }
```

Standard types (`STANDARD_OBLIGATION_TYPES`): `log_extra`, `create_case`, `require_redaction`, `persist_handoff`, `emit_summary`. Use `is_standard_obligation_type()` to check.

v2 receipts include structured obligations on `decision.obligations` and a rollup on `evidence.obligations` (`all`, `pending`, `blocking`, `after_effect`).

## Budget effects

`BudgetEffect` records ledger-oriented events without requiring a ledger in-repo:

| Field | Example |
|-------|---------|
| `budget_id` | `usd-daily` |
| `effect_type` | `reserve`, `consume`, `release` |
| `amount` | `250.0` |
| `status` | `planned`, `committed`, `released` |

`ReservationCallback` on `AgentWrapper` can return `ReservationResult` with effects and `budget_reservation_required` outcome.

v2 receipt `budget` section:

```json
{
  "items": [ { "budget_id": "usd-daily", "limit": 1000, "remaining": 900 } ],
  "effects": [ { "budget_id": "usd-daily", "effect_type": "reserve", "amount": 100 } ],
  "summary": { "usd-daily": { "reserved_amount": 100, "consumed_amount": 0 } }
}
```

## Policy engine seam

`PolicyEngine.evaluate(output, execution_context=…)` returns a `DecisionResult`. Default: `YamlPolicyEngine` over committed YAML policy. Custom engines plug into `AgentWrapper(policy_engine=…)`.

The current default engine now does a minimal lower-layer authority pass before
software policy checks when authority facts are present:

- rejects expired authority
- rejects `sender_constrained` or capability-grant authority that is missing
  proof-of-possession
- enforces simple L2 capability/action compatibility against `ActionDescriptor`

This is intentionally conservative and is the first integration slice between
partner `L1/L2` authority data and the native `L3` decision runtime.

## Replay and explain

| API | Purpose |
|-----|---------|
| `rebuild_context_from_bundle()` | Decision-relevant context for replay |
| `compare_stored_decision()` | Decision block vs execution proof |
| `compare_budget_effects()` | `decision.budget_effects` vs `budget` section |
| `re_evaluate_policy_decision()` | Re-run software policy on stored output |
| `explain_receipt_bundle()` | Human/auditor report incl. `can_execute`, budget |
| `auditor_evidence_summary()` | Compliance-facing subset |

CLI: `arctl replay-check`, `arctl explain`, `arctl audit-summary`.

## Receipt placement (v2)

| Concept | v2 location |
|---------|-------------|
| Decision fields | `decision.*` |
| Assurance | `evidence.assurance` |
| Approval | `approval` (optional) |
| Budget caps + effects | `budget` (optional) |
| Authority | `authority` |
| Action metadata | `action` |

See [receipt_bundle_v2.md](receipt_bundle_v2.md).
