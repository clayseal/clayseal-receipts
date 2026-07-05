from __future__ import annotations

from agentauth.receipts.goal_metrics import summarize_receipt_bundles


def test_summarize_receipt_bundles_counts_and_timings() -> None:
    bundles = [
        {
            "output": {"status": "ok"},
            "sandboxing": {"enforcement": "allow", "timings_ms": {"broker_pre_tool_ms": 10, "total_ms": 30}},
        },
        {
            "output": {"status": "step_up_required"},
            "sandboxing": {"enforcement": "step_up", "timings_ms": {"broker_pre_tool_ms": 20, "total_ms": 80}},
        },
        {
            "output": {"status": "blocked"},
            "sandboxing": {"enforcement": "deny"},
        },
    ]
    metrics = summarize_receipt_bundles(bundles)
    assert metrics.tool_calls == 3
    assert metrics.blocked_calls == 1
    assert metrics.step_up_required >= 2  # status + enforcement both count
    assert metrics.avg_broker_pre_tool_ms is not None
    assert metrics.avg_broker_pre_tool_ms > 0
    assert metrics.p95_total_ms is not None
    assert metrics.p95_total_ms >= 30

