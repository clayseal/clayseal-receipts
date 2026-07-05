"""ATIF / session trajectory feature extraction for L2.5 anomaly baseline (SM-9)."""

from __future__ import annotations

import math
from typing import TYPE_CHECKING, Any

from agentauth.core.runtime import SideEffectLevel

if TYPE_CHECKING:
    from agentauth.receipts.action_monitor import MonitoredAction

_SIDE_EFFECT_RANK = {
    SideEffectLevel.READ_ONLY: 0,
    SideEffectLevel.BOUNDED_WRITE: 1,
    SideEffectLevel.EXTERNAL_SIDE_EFFECT: 2,
    SideEffectLevel.PRIVILEGED_MUTATION: 3,
}

_EXTERNAL_MARKERS = ("curl", "shell", "exec", "deploy", "secret", "transfer", "wget")

FEATURE_NAMES = [
    "action_count",
    "unique_tool_ratio",
    "tool_switch_rate",
    "max_tool_streak",
    "external_side_effect_ratio",
    "high_risk_name_ratio",
    "side_effect_escalation",
]


def trajectory_tool_names(trajectory: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for step in trajectory.get("steps") or []:
        for call in step.get("tool_calls") or []:
            names.append(str(call.get("function_name", "")))
    return [name for name in names if name]


def tools_from_history(history: list[MonitoredAction], current: MonitoredAction) -> list[str]:
    tools = [item.tool_name for item in history if item.tool_name]
    if current.tool_name:
        tools.append(current.tool_name)
    return tools


def feature_vector_from_tools(tools: list[str]) -> list[float]:
    if not tools:
        return [0.0] * len(FEATURE_NAMES)

    count = float(len(tools))
    unique = len(set(tools))
    switches = sum(1 for left, right in zip(tools, tools[1:]) if left != right)
    switch_rate = switches / max(1.0, count - 1.0)

    streak = 1
    max_streak = 1
    for left, right in zip(tools, tools[1:]):
        if left == right:
            streak += 1
            max_streak = max(max_streak, streak)
        else:
            streak = 1

    lowered = [tool.lower() for tool in tools]
    high_risk = sum(
        1 for tool in lowered if any(marker in tool for marker in _EXTERNAL_MARKERS)
    )

    return [
        count,
        unique / count,
        switch_rate,
        float(max_streak),
        0.0,  # placeholder for side-effect ratio when only tool names known
        high_risk / count,
        0.0,
    ]


def feature_vector_from_actions(
    history: list[MonitoredAction],
    current: MonitoredAction,
) -> list[float]:
    actions = list(history) + [current]
    if not actions:
        return [0.0] * len(FEATURE_NAMES)

    count = float(len(actions))
    tool_names = [item.tool_name for item in actions if item.tool_name]
    unique_ratio = len(set(tool_names)) / max(1.0, float(len(tool_names)))
    switches = sum(
        1
        for left, right in zip(tool_names, tool_names[1:])
        if left and right and left != right
    )
    switch_rate = switches / max(1.0, float(len(tool_names) - 1))

    streak = 1
    max_streak = 1
    for left, right in zip(tool_names, tool_names[1:]):
        if left and right and left == right:
            streak += 1
            max_streak = max(max_streak, streak)
        else:
            streak = 1

    ranks = [_SIDE_EFFECT_RANK.get(item.side_effect_level, 2) for item in actions]
    external_ratio = sum(1 for rank in ranks if rank >= 2) / count
    high_risk = sum(
        1
        for item in actions
        if item.tool_name
        and any(marker in item.tool_name.lower() for marker in _EXTERNAL_MARKERS)
    ) / count

    escalation = 0.0
    if len(ranks) >= 2:
        prior_max = max(ranks[:-1])
        current_rank = ranks[-1]
        if prior_max <= 0 and current_rank >= 2:
            escalation = 1.0
        elif current_rank > prior_max:
            escalation = min(1.0, (current_rank - prior_max) / 3.0)

    return [
        count,
        unique_ratio if tool_names else 0.0,
        switch_rate if tool_names else 0.0,
        float(max_streak),
        external_ratio,
        high_risk,
        escalation,
    ]


def trajectory_entropy(tools: list[str]) -> float:
    if not tools:
        return 0.0
    counts: dict[str, int] = {}
    for tool in tools:
        counts[tool] = counts.get(tool, 0) + 1
    total = float(len(tools))
    entropy = 0.0
    for value in counts.values():
        probability = value / total
        entropy -= probability * math.log(probability, 2)
    return entropy
