"""Composite monitor: combines drift, scanning, and novelty monitors.

Evaluates all three monitors on each tool call and returns the worst
recommendation. This is the standard monitor composition for the
dynamic sandboxing stack.
"""
from __future__ import annotations

from typing import Any

from .behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from .drift_monitor import DriftScorer
from .monitor_contract import MonitorInput
from .novelty_monitor import NoveltyMonitor
from .scanning_monitor import ScanningScorer


class CompositeMonitor:
    """Combines drift + scanning + novelty monitors into one evaluator.

    Usage::

        monitor = CompositeMonitor(drift=drift, scan=scan, novelty=novelty)
        gw = ReceiptedMcpGateway(agent, behavior_monitor=monitor, ...)
    """

    def __init__(
        self,
        drift: DriftScorer,
        scan: ScanningScorer,
        novelty: NoveltyMonitor,
    ) -> None:
        self.drift = drift
        self.scan = scan
        self.novelty = novelty

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        results: list[BehaviorMonitorResult] = []
        for monitor in (self.drift, self.scan, self.novelty):
            r = monitor.evaluate_contract(contract)
            if r is not None:
                results.append(r)

        if not results:
            return None

        worst = BehaviorRecommendation.ALLOW
        all_reasons: list[str] = []
        max_risk = 0.0
        for r in results:
            if r.recommendation == BehaviorRecommendation.DENY:
                worst = BehaviorRecommendation.DENY
            elif (
                r.recommendation == BehaviorRecommendation.STEP_UP
                and worst != BehaviorRecommendation.DENY
            ):
                worst = BehaviorRecommendation.STEP_UP
            all_reasons.extend(r.reasons)
            max_risk = max(max_risk, r.risk_score or 0.0)

        return BehaviorMonitorResult(
            monitor_id="composite",
            monitor_version="v1",
            detector_family="rules",
            feature_set_id="composite_v1",
            risk_score=max_risk,
            threshold=0.3,
            recommendation=worst,
            reasons=all_reasons[:10],
        )

    def evaluate(self, ctx: Any) -> BehaviorMonitorResult | None:
        return None
