from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from agentauth.core.hash_util import hash_canonical_json

from agentauth.receipts.monitor_contract import MonitorInput
from agentauth.core.runtime import ExecutionContext


class BehaviorRecommendation(str, Enum):
    """Non-binding recommendation emitted by a behavior monitor."""

    ALLOW = "allow"
    STEP_UP = "step_up"
    DENY = "deny"


@dataclass(frozen=True)
class BehaviorMonitorResult:
    """
    Behavior-monitor output carried as evidence on a receipt.

    This result is intentionally non-enforcing. Enforcement belongs to a sandbox governor.
    """

    monitor_id: str
    monitor_version: str | None = None
    detector_family: str | None = None
    feature_set_id: str | None = None
    risk_score: float | None = None
    threshold: float | None = None
    recommendation: BehaviorRecommendation | None = None
    reasons: list[str] = field(default_factory=list)
    trace_commitment: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "monitor_id": self.monitor_id,
            "monitor_version": self.monitor_version,
            "detector_family": self.detector_family,
            "feature_set_id": self.feature_set_id,
            "risk_score": self.risk_score,
            "threshold": self.threshold,
            "recommendation": self.recommendation.value if self.recommendation else None,
            "reasons": list(self.reasons),
            "trace_commitment": self.trace_commitment,
        }

    def with_trace_commitment(self, trace_commitment: str) -> "BehaviorMonitorResult":
        if self.trace_commitment:
            return self
        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family=self.detector_family,
            feature_set_id=self.feature_set_id,
            risk_score=self.risk_score,
            threshold=self.threshold,
            recommendation=self.recommendation,
            reasons=list(self.reasons),
            trace_commitment=trace_commitment,
        )

    def bounded(self, *, max_reasons: int = 10, max_reason_chars: int = 200) -> "BehaviorMonitorResult":
        if not self.reasons:
            return self
        bounded_reasons = [str(r)[:max_reason_chars] for r in list(self.reasons)[:max_reasons]]
        if bounded_reasons == list(self.reasons):
            return self
        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family=self.detector_family,
            feature_set_id=self.feature_set_id,
            risk_score=self.risk_score,
            threshold=self.threshold,
            recommendation=self.recommendation,
            reasons=bounded_reasons,
            trace_commitment=self.trace_commitment,
        )


@runtime_checkable
class BehaviorMonitor(Protocol):
    """Score behavior risk for an execution step (non-binding)."""

    def evaluate(self, ctx: ExecutionContext) -> BehaviorMonitorResult | None: ...


@runtime_checkable
class BehaviorMonitorWithContract(Protocol):
    """Score behavior risk from the structured monitor input contract (preferred)."""

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None: ...


def evaluate_behavior_monitor(
    monitor: BehaviorMonitor,
    *,
    ctx: ExecutionContext,
    contract: MonitorInput,
) -> BehaviorMonitorResult | None:
    """
    Evaluate a behavior monitor using the safest available interface.

    - Prefer the structured monitor-input contract (`evaluate_contract`) when supported.
    - Fall back to legacy `evaluate(ctx)` for older/inline monitors.
    """
    if isinstance(monitor, BehaviorMonitorWithContract):
        return monitor.evaluate_contract(contract)
    # Legacy monitors should not receive raw args (which can contain untrusted tool output).
    sanitized = ExecutionContext(
        action=ctx.action,
        input={"arguments_hash": contract.proposed.arguments_hash},
        authority=ctx.authority,
        query_id=ctx.query_id,
        authorization=ctx.authorization,
        touched_resources=list(ctx.touched_resources),
    )
    return monitor.evaluate(sanitized)


class NullBehaviorMonitor:
    """Default no-op monitor."""

    def evaluate(self, ctx: ExecutionContext) -> BehaviorMonitorResult | None:
        return None


class LoopingToolCallMonitor:
    """
    Baseline abnormal-behavior monitor for tool-call loops.

    Detects repeated patterns in recent tool-call signatures (tool + args hash) and
    emits a non-binding STEP_UP recommendation when a loop is detected.
    """

    def __init__(
        self,
        *,
        window: int = 8,
        pattern_len: int = 2,
        repeats: int = 3,
        threshold: float = 0.8,
        monitor_id: str = "looping_tool_call_monitor",
        monitor_version: str = "v1",
    ) -> None:
        if window <= 0:
            raise ValueError("window must be > 0")
        if pattern_len <= 0:
            raise ValueError("pattern_len must be > 0")
        if repeats <= 1:
            raise ValueError("repeats must be > 1")
        self.window = window
        self.pattern_len = pattern_len
        self.repeats = repeats
        self.threshold = float(threshold)
        self.monitor_id = monitor_id
        self.monitor_version = monitor_version
        self._recent: list[str] = []

    def _signature(self, *, action_name: str, arguments_hash: str) -> str:
        return f"{action_name}|{arguments_hash}"

    def evaluate(self, ctx: ExecutionContext) -> BehaviorMonitorResult | None:
        args_hash = None
        if isinstance(ctx.input, dict):
            args_hash = ctx.input.get("arguments_hash")
        if not isinstance(args_hash, str) or not args_hash:
            args_hash = f"sha256:{hash_canonical_json(ctx.input)}"
        sig = self._signature(action_name=ctx.action.action_name, arguments_hash=args_hash)
        self._recent.append(sig)
        if len(self._recent) > self.window:
            self._recent = self._recent[-self.window :]

        n = self.pattern_len
        k = self.repeats
        if len(self._recent) < n * k:
            return None

        tail = self._recent[-n * k :]
        pattern = tail[:n]
        for i in range(1, k):
            if tail[i * n : (i + 1) * n] != pattern:
                return None

        trace_commitment = hash_canonical_json(
            {
                "recent": list(self._recent),
                "window": self.window,
                "pattern_len": self.pattern_len,
                "repeats": self.repeats,
            }
        )
        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family="rules",
            feature_set_id="mcp_tool_trace_v1",
            risk_score=1.0,
            threshold=self.threshold,
            recommendation=BehaviorRecommendation.STEP_UP,
            reasons=[
                f"detected repeating tool-call pattern (len={n}) repeated {k} times"
            ],
            trace_commitment=f"sha256:{trace_commitment}",
        )

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        sig = self._signature(
            action_name=contract.proposed.action_name,
            arguments_hash=contract.proposed.arguments_hash,
        )
        self._recent.append(sig)
        if len(self._recent) > self.window:
            self._recent = self._recent[-self.window :]

        n = self.pattern_len
        k = self.repeats
        if len(self._recent) < n * k:
            return None

        tail = self._recent[-n * k :]
        pattern = tail[:n]
        for i in range(1, k):
            if tail[i * n : (i + 1) * n] != pattern:
                return None

        trace_commitment = hash_canonical_json(
            {
                "recent": list(self._recent),
                "window": self.window,
                "pattern_len": self.pattern_len,
                "repeats": self.repeats,
            }
        )
        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family="rules",
            feature_set_id="mcp_tool_trace_v1",
            risk_score=1.0,
            threshold=self.threshold,
            recommendation=BehaviorRecommendation.STEP_UP,
            reasons=[
                f"detected repeating tool-call pattern (len={n}) repeated {k} times"
            ],
            trace_commitment=f"sha256:{trace_commitment}",
        )
