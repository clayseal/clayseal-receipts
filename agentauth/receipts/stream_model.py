"""L2.5 per-action stream features (SM-16 / README §3.1).

Structured feature block for each step in a session action stream: action type,
tool, scope alignment, sequence position, timing, and schema conformance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentauth.receipts.action_features import FEATURE_NAMES, feature_vector_from_actions
from agentauth.core.hash_util import hash_canonical_json
from agentauth.core.runtime import ExecutionContext, SideEffectLevel
from agentauth.core.task_scope import TaskScope, action_path_candidates, task_scope_allows_path

if False:  # TYPE_CHECKING without import cycle
    from agentauth.receipts.action_monitor import MonitoredAction


@dataclass
class StreamActionFeatures:
    """Receipt-facing L2.5 stream feature block for one action."""

    schema: str = "agent-receipts.stream-features.v1"
    action_index: int = 0
    action_name: str = ""
    action_category: str = ""
    tool_name: str | None = None
    resource_ref: str | None = None
    side_effect_level: str = SideEffectLevel.READ_ONLY.value
    in_scope: bool | None = None
    scope_paths_checked: list[str] = field(default_factory=list)
    sequence_position: float = 0.0
    inter_action_ms: float | None = None
    capability_usage_delta: float = 0.0
    schema_conformant: bool | None = None
    feature_names: list[str] = field(default_factory=lambda: list(FEATURE_NAMES))
    feature_vector: list[float] = field(default_factory=list)
    commitment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": self.schema,
            "action_index": self.action_index,
            "action_name": self.action_name,
            "action_category": self.action_category,
            "tool_name": self.tool_name,
            "resource_ref": self.resource_ref,
            "side_effect_level": self.side_effect_level,
            "in_scope": self.in_scope,
            "scope_paths_checked": list(self.scope_paths_checked),
            "sequence_position": round(self.sequence_position, 4),
            "inter_action_ms": (
                round(self.inter_action_ms, 2) if self.inter_action_ms is not None else None
            ),
            "capability_usage_delta": round(self.capability_usage_delta, 4),
            "schema_conformant": self.schema_conformant,
            "feature_names": list(self.feature_names),
            "feature_vector": [round(value, 6) for value in self.feature_vector],
        }
        payload["commitment"] = self.commitment or hash_canonical_json(
            {
                "action_index": self.action_index,
                "action_name": self.action_name,
                "feature_vector": payload["feature_vector"],
                "in_scope": self.in_scope,
            }
        )
        return payload


def _side_effect_rank(level: SideEffectLevel) -> int:
    ranks = {
        SideEffectLevel.READ_ONLY: 0,
        SideEffectLevel.BOUNDED_WRITE: 1,
        SideEffectLevel.EXTERNAL_SIDE_EFFECT: 2,
        SideEffectLevel.PRIVILEGED_MUTATION: 3,
    }
    return ranks.get(level, 2)


def extract_stream_features(
    history: list[Any],
    current: Any,
    *,
    execution_context: ExecutionContext | None = None,
    task_scope: TaskScope | None = None,
    inter_action_ms: float | None = None,
    schema_conformant: bool | None = None,
) -> StreamActionFeatures:
    """Build README §3.1 stream features for the current monitored action."""
    actions = list(history) + [current]
    index = len(history)
    vector = feature_vector_from_actions(history, current)

    paths_checked = action_path_candidates(
        resource_ref=current.resource_ref,
        touched_resources=(
            list(execution_context.touched_resources)
            if execution_context and execution_context.touched_resources
            else None
        ),
    )
    in_scope: bool | None = None
    if task_scope is not None and paths_checked:
        in_scope = all(task_scope_allows_path(task_scope, path) for path in paths_checked)
    elif task_scope is not None and task_scope.allowed_paths:
        in_scope = True

    prior_ranks = [_side_effect_rank(item.side_effect_level) for item in history]
    current_rank = _side_effect_rank(current.side_effect_level)
    usage_delta = 0.0
    if prior_ranks:
        usage_delta = max(0.0, (current_rank - max(prior_ranks)) / 3.0)

    window = 32.0
    sequence_position = min(1.0, float(index) / window)

    return StreamActionFeatures(
        action_index=index,
        action_name=current.action_name,
        action_category=current.action_category,
        tool_name=current.tool_name,
        resource_ref=current.resource_ref,
        side_effect_level=current.side_effect_level.value,
        in_scope=in_scope,
        scope_paths_checked=paths_checked,
        sequence_position=sequence_position,
        inter_action_ms=inter_action_ms,
        capability_usage_delta=usage_delta,
        schema_conformant=schema_conformant,
        feature_vector=vector,
    )
