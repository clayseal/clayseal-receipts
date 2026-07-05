from __future__ import annotations

from dataclasses import dataclass
import math
import statistics
from typing import Any


@dataclass(frozen=True)
class GoalMetrics:
    tool_calls: int
    blocked_calls: int
    step_up_required: int
    avg_broker_pre_tool_ms: float | None
    p95_total_ms: float | None


@dataclass(frozen=True)
class GoalMetricBaselines:
    """Conservative default baselines for early pilots (DP-40)."""

    max_step_ups_per_goal: int = 1
    max_p95_total_ms: float = 250.0


def summarize_receipt_bundles(bundles: list[dict[str, Any]]) -> GoalMetrics:
    """
    Compute a minimal set of success/perf metrics over a set of receipt bundles (DP-40/41).

    This intentionally avoids needing the full internal Python types; it works on exported bundles.
    """
    tool_calls = len(bundles)
    blocked_calls = 0
    step_up_required = 0
    broker_pre_tool: list[float] = []
    total_ms: list[float] = []

    for bundle in bundles:
        output = bundle.get("output") or {}
        status = output.get("status")
        if status in {"blocked", "error"}:
            blocked_calls += 1
        if status == "step_up_required":
            step_up_required += 1
        sandboxing = bundle.get("sandboxing") or {}
        if sandboxing.get("enforcement") == "step_up":
            step_up_required += 1
        timings = sandboxing.get("timings_ms") or {}
        if isinstance(timings, dict):
            pre = timings.get("broker_pre_tool_ms")
            tot = timings.get("total_ms")
            if isinstance(pre, (int, float)):
                broker_pre_tool.append(float(pre))
            if isinstance(tot, (int, float)):
                total_ms.append(float(tot))

    avg_pre = statistics.fmean(broker_pre_tool) if broker_pre_tool else None
    if total_ms:
        total_ms_sorted = sorted(total_ms)
        idx = max(0, min(len(total_ms_sorted) - 1, math.ceil(0.95 * len(total_ms_sorted)) - 1))
        p95 = float(total_ms_sorted[idx])
    else:
        p95 = None
    return GoalMetrics(
        tool_calls=tool_calls,
        blocked_calls=blocked_calls,
        step_up_required=step_up_required,
        avg_broker_pre_tool_ms=avg_pre,
        p95_total_ms=p95,
    )


def evaluate_goal_against_baselines(
    metrics: GoalMetrics,
    *,
    baselines: GoalMetricBaselines | None = None,
) -> list[str]:
    baselines = baselines or GoalMetricBaselines()
    warnings: list[str] = []
    if metrics.step_up_required > baselines.max_step_ups_per_goal:
        warnings.append(
            f"baseline_exceeded:step_ups:{metrics.step_up_required}>{baselines.max_step_ups_per_goal}"
        )
    if metrics.p95_total_ms is not None and metrics.p95_total_ms > baselines.max_p95_total_ms:
        warnings.append(
            f"baseline_exceeded:p95_total_ms:{metrics.p95_total_ms:.2f}>{baselines.max_p95_total_ms:.2f}"
        )
    return warnings
