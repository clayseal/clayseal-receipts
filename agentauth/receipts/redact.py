"""Redact sensitive fields from receipt bundles before external sharing."""

from __future__ import annotations

import copy
from typing import Any

REDACTED = "[REDACTED]"

DEFAULT_REDACT_PATHS = (
    "certificate.principal.principal_id",
    "certificate.principal.organization",
    "context.input",
    "context.authorization",
    "execution_context.input",
    "execution_context.authorization",
    "execution_context.touched_resources",
    "execution_context.authority.session_id",
    "execution_context.authority.actor_ref.actor_id",
    "execution_context.authority.parent_actor_ref.actor_id",
    "execution_context.authority.budget_refs",
    "execution_context.authority.approval_refs",
    "authority.session_id",
    "authority.actor_ref.actor_id",
    "authority.parent_actor_ref.actor_id",
    "authority.budget_refs",
    "authority.approval_refs",
    "session.session_id",
    "approval.metadata.approval_id",
    "approval.metadata.approver_ref",
    "decision.session_id",
    "decision.approval_state",
    "decision.approval_metadata.approval_id",
    "decision.approval_metadata.approver_ref",
    "budget.summary",
    "evidence.decision_record.approval_metadata.approval_id",
    "evidence.decision_record.authority.session_id",
    "evidence_refs.state_snapshot_id",
    "lineage.authority_id",
    "lineage.parent_authority_id",
    "action.resource_ref",
    "output",
    "output.result.transaction_id",
    # List-aware paths (require [] wildcard support in _set_path)
    "decision.obligations[].details",
    "decision.budget_effects[].budget_id",
    "decision.budget_effects[].amount",
    "budget.items[].budget_id",
    "budget.items[].limit",
    "budget.items[].remaining",
    "budget.items[].scope",
    "budget.effects[].budget_id",
    "budget.effects[].amount",
    # Actual exported budget block is `budgets` (a CapabilityBudget list)
    "budgets[].budget_id",
    "budgets[].limit",
    "budgets[].remaining",
    "budgets[].scope",
    # Session handoff artifact
    "handoff.session_id",
    "handoff.touched_resources",
    "handoff.prior_receipt_refs",
    "handoff.budget_snapshot",
    "handoff.pending_obligations[]",
)


def _set_path(obj: Any, path: str, value: Any) -> None:
    """Redact a dot path, supporting a ``[]`` wildcard to descend into list items.

    Examples: ``decision.budget_effects[].amount`` redacts ``amount`` in every list
    element; ``handoff.pending_obligations[]`` redacts each element wholesale. Plain
    dot paths behave as before.
    """
    _set_parts(obj, path.split("."), value)


def _set_parts(obj: Any, parts: list[str], value: Any) -> None:
    token = parts[0]
    rest = parts[1:]
    if token.endswith("[]"):
        key = token[:-2]
        if not isinstance(obj, dict) or not isinstance(obj.get(key), list):
            return
        container = obj[key]
        for i, item in enumerate(container):
            if rest:
                _set_parts(item, rest, value)
            else:
                container[i] = value
        return
    if not isinstance(obj, dict) or token not in obj:
        return
    if rest:
        _set_parts(obj[token], rest, value)
    else:
        obj[token] = value


def redact_receipt_bundle(
    bundle: dict[str, Any],
    *,
    fields: list[str] | None = None,
) -> dict[str, Any]:
    """Return a copy with default and optional dot-path fields redacted."""
    out = copy.deepcopy(bundle)
    paths = list(DEFAULT_REDACT_PATHS)
    if fields:
        paths.extend(fields)
    for path in paths:
        _set_path(out, path, REDACTED)
    return out
