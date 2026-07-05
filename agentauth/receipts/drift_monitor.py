"""DP-34: Drift scorer — detects goal-scope divergence from the trace.

Watches the rolling window of touched resource refs and computes how many
recent actions fall outside the allowed scope.  Emits a non-binding STEP_UP
when the out-of-scope ratio exceeds a configurable threshold, signaling
that the agent may be drifting from its goal.

This monitor is deterministic and non-LLM: it operates only on trusted
telemetry from the MonitorInput contract (resource_ref, touched_resources).
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from agentauth.core.hash_util import hash_canonical_json

from agentauth.receipts.behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from agentauth.receipts.monitor_contract import MonitorInput


@dataclass
class DriftScorerConfig:
    window: int = 10
    threshold: float = 0.5
    monitor_id: str = "drift_scorer"
    monitor_version: str = "v1"


class DriftScorer:
    """Rolling out-of-scope ratio over the last *window* actions (DP-34).

    ``scope_resources`` is the set of allowed resource refs (e.g.
    ``{"repo://src/main.py", "repo://src/utils.py"}``).  Each action's
    ``resource_ref`` is checked against this set.  The scorer tracks a
    rolling window and emits STEP_UP when the fraction of out-of-scope
    actions exceeds ``threshold``.

    This is a ``BehaviorMonitorWithContract``-compatible monitor.
    """

    def __init__(
        self,
        scope_resources: set[str],
        *,
        config: DriftScorerConfig | None = None,
    ) -> None:
        cfg = config or DriftScorerConfig()
        if cfg.window <= 0:
            raise ValueError("window must be > 0")
        self.scope_resources = set(scope_resources)
        self.window = cfg.window
        self.threshold = float(cfg.threshold)
        self.monitor_id = cfg.monitor_id
        self.monitor_version = cfg.monitor_version
        self._hits: deque[bool] = deque(maxlen=cfg.window)

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        ref = contract.proposed.resource_ref
        in_scope = ref is not None and ref in self.scope_resources
        self._hits.append(in_scope)

        if len(self._hits) < 2:
            return None

        out_count = sum(1 for h in self._hits if not h)
        ratio = out_count / len(self._hits)

        trace_payload = {
            "recent_in_scope": [h for h in self._hits],
            "window": self.window,
            "threshold": self.threshold,
        }
        trace_commitment = f"sha256:{hash_canonical_json(trace_payload)}"

        if ratio >= self.threshold:
            return BehaviorMonitorResult(
                monitor_id=self.monitor_id,
                monitor_version=self.monitor_version,
                detector_family="rules",
                feature_set_id="drift_scope_v1",
                risk_score=min(1.0, ratio),
                threshold=self.threshold,
                recommendation=BehaviorRecommendation.STEP_UP,
                reasons=[
                    f"drift: {out_count}/{len(self._hits)} recent actions "
                    f"out of scope (ratio={ratio:.2f} >= {self.threshold})"
                ],
                trace_commitment=trace_commitment,
            )

        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family="rules",
            feature_set_id="drift_scope_v1",
            risk_score=ratio,
            threshold=self.threshold,
            recommendation=BehaviorRecommendation.ALLOW,
            reasons=[],
            trace_commitment=trace_commitment,
        )

    @property
    def out_of_scope_ratio(self) -> float:
        if not self._hits:
            return 0.0
        return sum(1 for h in self._hits if not h) / len(self._hits)
