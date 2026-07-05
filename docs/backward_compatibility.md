# Backward compatibility (X-1)

The SDK moved scattered run fields into structured objects without breaking existing integrations.

## RunResult shims

`RunResult` embeds `DecisionResult` and `ExecutionContext`. Legacy attribute access still works:

| Legacy access | Canonical location |
|---------------|-------------------|
| `result.policy_violations` | `result.decision.violations` |
| `result.decision_outcome` | `result.decision.outcome` |
| `result.policy_satisfied` | `result.decision.policy_satisfied` |
| `result.authority_version` | `result.decision.authority_version` |
| `result.session_id` | `result.decision.session_id` |
| `result.obligations` | `result.decision.obligations` |
| `result.recommended_action` | `result.decision.recommended_action` |
| `result.approval_state` | `result.decision.approval_state` |
| `result.budget_effects` | `result.decision.budget_effects` |

For serializers expecting a flat dict:

```python
legacy = result.to_legacy_dict()
```

## ToolCallResult shims

MCP `ToolCallResult` exposes the same outcome fields via properties on `decision`, plus `to_legacy_dict()` for flat exports.

## Receipt schema

| Version | Notes |
|---------|--------|
| v1 | Top-level `policy_violations`, `assurance`, `budgets` |
| v2 (default) | Violations under `decision`; assurance under `evidence`; budget under `budget` |

Use `schema_version="v1"` on `build_receipt_bundle()` or `migrate_v1_to_v2()` for upgrades. See [receipt_bundle_v2.md](receipt_bundle_v2.md).

## Policy proofs

| Circuit ID | Notes |
|------------|--------|
| `policy_range_v2` | Range + output/policy binding |
| `policy_range_v3` (current) | Adds in-circuit required-field presence mask |

Rebuild the Rust CLI after pulling: `cargo build -p agent-receipts-cli --release`.

## Migration guidance

1. New code should use `result.decision` and `result.execution_context` directly.
2. Keep flat property reads during transition; they delegate to `DecisionResult`.
3. Export receipts with default v2; keep v1 only if downstream parsers require it.
4. See [decision_model.md](decision_model.md) for approval, obligations, and budget semantics.
