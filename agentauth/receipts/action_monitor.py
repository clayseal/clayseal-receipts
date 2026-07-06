"""Per-session action monitoring and heuristic suspiciousness (L2.5 / L3 seam).

Tracks a rolling action history per session, increments ``prior_action_count``,
and emits a ``MonitoringSignal`` consumed by :class:`YamlPolicyEngine`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from agentauth.core.runtime import ActionDescriptor, ExecutionContext, SideEffectLevel
from agentauth.receipts.action_features import feature_vector_from_actions
from agentauth.receipts.anomaly_baseline import AnomalyBaselineModel, load_anomaly_model
from agentauth.core.task_scope import TaskScope

_HIGH_RISK_TOOL_MARKERS = (
    "curl",
    "shell",
    "transfer",
    "exec",
    "deploy",
    "secret",
    "credential",
    "exfil",
)

_SIDE_EFFECT_RANK = {
    SideEffectLevel.READ_ONLY: 0,
    SideEffectLevel.BOUNDED_WRITE: 1,
    SideEffectLevel.EXTERNAL_SIDE_EFFECT: 2,
    SideEffectLevel.PRIVILEGED_MUTATION: 3,
}


@dataclass
class MonitoredAction:
    action_name: str
    action_category: str
    resource_ref: str | None
    side_effect_level: SideEffectLevel
    tool_name: str | None = None

    @classmethod
    def from_execution_context(cls, execution_context: ExecutionContext) -> MonitoredAction:
        action = execution_context.action
        tool_name: str | None = None
        if action.action_name.startswith("mcp.tools/call/"):
            tool_name = action.action_name.rsplit("/", 1)[-1]
        return cls(
            action_name=action.action_name,
            action_category=action.action_category,
            resource_ref=action.resource_ref,
            side_effect_level=action.side_effect_level,
            tool_name=tool_name,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_name": self.action_name,
            "action_category": self.action_category,
            "resource_ref": self.resource_ref,
            "side_effect_level": self.side_effect_level.value,
            "tool_name": self.tool_name,
        }


@dataclass
class MonitoringSignal:
    """Suspiciousness signal attached to a single action receipt."""

    score: float
    review_required: bool
    flags: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    action_index: int = 0
    model_id: str = "heuristic-v1"
    anomaly_score: float | None = None
    model_commitment: str | None = None
    stream_features: dict[str, Any] | None = None
    anomaly_proof: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "score": round(self.score, 4),
            "review_required": self.review_required,
            "flags": list(self.flags),
            "reasons": list(self.reasons),
            "action_index": self.action_index,
            "model_id": self.model_id,
        }
        if self.anomaly_score is not None:
            payload["anomaly_score"] = round(self.anomaly_score, 4)
        if self.model_commitment is not None:
            payload["model_commitment"] = self.model_commitment
        if self.stream_features is not None:
            payload["stream_features"] = self.stream_features
        if self.anomaly_proof is not None:
            payload["anomaly_proof"] = self.anomaly_proof
        return payload

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> MonitoringSignal:
        anomaly = raw.get("anomaly_score")
        return cls(
            score=float(raw.get("score", 0.0)),
            review_required=bool(raw.get("review_required", False)),
            flags=[str(item) for item in raw.get("flags", [])],
            reasons=[str(item) for item in raw.get("reasons", [])],
            action_index=int(raw.get("action_index", 0)),
            model_id=str(raw.get("model_id", "heuristic-v1")),
            anomaly_score=float(anomaly) if anomaly is not None else None,
            model_commitment=raw.get("model_commitment"),
            stream_features=raw.get("stream_features"),
            anomaly_proof=raw.get("anomaly_proof"),
        )


@dataclass
class MonitoringPolicy:
    enabled: bool = False
    review_threshold: float = 0.5
    block_threshold: float | None = None
    sensitive_keywords: list[str] = field(default_factory=list)
    history_window: int = 32
    thresholds_by_side_effect: dict[str, dict[str, float]] = field(default_factory=dict)

    @classmethod
    def from_policy_dict(cls, raw: dict[str, Any] | None) -> MonitoringPolicy:
        if not raw:
            return cls()
        block = raw.get("block_threshold")
        by_level = raw.get("thresholds_by_side_effect") or raw.get("class_thresholds")
        normalized: dict[str, dict[str, float]] = {}
        if isinstance(by_level, dict):
            for level, values in by_level.items():
                if isinstance(values, dict):
                    normalized[str(level)] = {
                        str(k): float(v) for k, v in values.items() if v is not None
                    }
        return cls(
            enabled=bool(raw.get("enabled", False)),
            review_threshold=float(raw.get("review_threshold", 0.5)),
            block_threshold=float(block) if block is not None else None,
            sensitive_keywords=[str(item) for item in raw.get("sensitive_keywords", [])],
            history_window=int(raw.get("history_window", 32)),
            thresholds_by_side_effect=normalized,
        )

    def thresholds_for(self, side_effect_level: SideEffectLevel | str) -> tuple[float, float | None]:
        """Return (review_threshold, block_threshold) for an action side-effect class."""
        key = (
            side_effect_level.value
            if isinstance(side_effect_level, SideEffectLevel)
            else str(side_effect_level)
        )
        override = self.thresholds_by_side_effect.get(key) or {}
        review = float(override.get("review", self.review_threshold))
        block_raw = override.get("block", self.block_threshold)
        block = float(block_raw) if block_raw is not None else self.block_threshold
        return review, block


def evaluate_heuristic_suspiciousness(
    history: list[MonitoredAction],
    current: MonitoredAction,
    *,
    monitoring: MonitoringPolicy,
    task_summary: str | None = None,
) -> MonitoringSignal:
    """Deterministic baseline scorer (L2.5 v0 before ML model lands)."""
    score = 0.0
    flags: list[str] = []
    reasons: list[str] = []

    if not history:
        return MonitoringSignal(
            score=0.0,
            review_required=False,
            flags=flags,
            reasons=reasons,
            action_index=0,
        )

    prior = history[-monitoring.history_window :]
    read_streak = all(
        item.side_effect_level == SideEffectLevel.READ_ONLY for item in prior
    )
    current_rank = _SIDE_EFFECT_RANK.get(current.side_effect_level, 2)
    if read_streak and len(prior) >= 2 and current_rank >= _SIDE_EFFECT_RANK[
        SideEffectLevel.EXTERNAL_SIDE_EFFECT
    ]:
        score += 0.45
        flags.append("side_effect_escalation")
        reasons.append(
            "external side-effect after a read-only stretch (possible scope break)"
        )

    if current.tool_name:
        repeats = sum(1 for item in prior if item.tool_name == current.tool_name)
        if repeats >= 2:
            score += 0.2
            flags.append("repeated_tool")
            reasons.append(f"tool {current.tool_name!r} invoked repeatedly in session")

        lowered = current.tool_name.lower()
        if any(marker in lowered for marker in _HIGH_RISK_TOOL_MARKERS):
            score += 0.25
            flags.append("high_risk_tool")
            reasons.append(f"tool name matches high-risk marker: {current.tool_name!r}")

    keywords = monitoring.sensitive_keywords or list(_HIGH_RISK_TOOL_MARKERS)
    action_blob = " ".join(
        filter(
            None,
            [current.action_name, current.resource_ref or "", current.tool_name or ""],
        )
    ).lower()
    summary_lower = (task_summary or "").lower()
    for keyword in keywords:
        token = keyword.strip().lower()
        if not token:
            continue
        if token in action_blob and token not in summary_lower:
            score += 0.15
            flags.append("keyword_not_in_task")
            reasons.append(
                f"action references {token!r} but task summary does not mention it"
            )
            break

    unique_tools = {item.tool_name for item in prior if item.tool_name}
    if current.tool_name and unique_tools and current.tool_name not in unique_tools:
        if current_rank >= _SIDE_EFFECT_RANK[SideEffectLevel.EXTERNAL_SIDE_EFFECT]:
            score += 0.15
            flags.append("novel_external_tool")
            reasons.append(f"first use of external tool {current.tool_name!r} in session")

    score = min(1.0, score)
    review_threshold, _ = monitoring.thresholds_for(current.side_effect_level)
    review_required = score >= review_threshold
    return MonitoringSignal(
        score=score,
        review_required=review_required,
        flags=sorted(set(flags)),
        reasons=reasons,
        action_index=len(history),
        model_id="heuristic-v1",
    )


class SessionActionMonitor:
    """In-memory per-session action history for one agent wrapper / gateway."""

    def __init__(
        self,
        *,
        monitoring: MonitoringPolicy | None = None,
        anomaly_model: AnomalyBaselineModel | None = None,
        canary: Any | None = None,
        task_scope: TaskScope | None = None,
    ) -> None:
        from agentauth.receipts.model_canary import CanaryPolicy

        self.monitoring = monitoring or MonitoringPolicy()
        self.canary = canary or CanaryPolicy()
        self.task_scope = task_scope
        self._history: dict[str, list[MonitoredAction]] = {}
        self._last_observed_at: dict[str, float] = {}
        if anomaly_model is not None:
            self.anomaly_model = anomaly_model
        else:
            self.anomaly_model = load_anomaly_model()

    def configure(self, monitoring: MonitoringPolicy) -> None:
        self.monitoring = monitoring

    def reset(self, session_id: str | None = None) -> None:
        if session_id is None:
            self._history.clear()
            return
        self._history.pop(session_id, None)

    def prior_action_count(self, session_id: str) -> int:
        return len(self._history.get(session_id, []))

    def commit(self, execution_context: ExecutionContext) -> None:
        """Append an action to session history after a pre-check evaluation."""
        session_id = execution_context.authority.session_id or "default"
        current = MonitoredAction.from_execution_context(execution_context)
        history = self._history.setdefault(session_id, [])
        history.append(current)
        if len(history) > self.monitoring.history_window:
            del history[: -self.monitoring.history_window]

    def observe(
        self,
        execution_context: ExecutionContext,
        *,
        task_summary: str | None = None,
    ) -> MonitoringSignal:
        return self.evaluate(
            execution_context,
            task_summary=task_summary,
            commit=True,
        )

    def evaluate(
        self,
        execution_context: ExecutionContext,
        *,
        task_summary: str | None = None,
        commit: bool = True,
    ) -> MonitoringSignal:
        session_id = execution_context.authority.session_id or "default"
        current = MonitoredAction.from_execution_context(execution_context)
        history = self._history.setdefault(session_id, [])

        if not self.monitoring.enabled:
            signal = MonitoringSignal(
                score=0.0,
                review_required=False,
                action_index=len(history),
            )
            if commit:
                history.append(current)
                if len(history) > self.monitoring.history_window:
                    del history[: -self.monitoring.history_window]
            return signal

        signal = evaluate_heuristic_suspiciousness(
            history,
            current,
            monitoring=self.monitoring,
            task_summary=task_summary,
        )
        now = time.monotonic()
        inter_action_ms = None
        if session_id in self._last_observed_at:
            inter_action_ms = (now - self._last_observed_at[session_id]) * 1000.0
        self._last_observed_at[session_id] = now

        from agentauth.receipts.stream_model import extract_stream_features

        stream = extract_stream_features(
            history,
            current,
            execution_context=execution_context,
            task_scope=self.task_scope,
            inter_action_ms=inter_action_ms,
        )
        signal.stream_features = stream.to_dict()

        if self.anomaly_model is not None:
            features = feature_vector_from_actions(history, current)
            anomaly_score = self.anomaly_model.score(features)
            signal.anomaly_score = anomaly_score
            signal.model_commitment = self.anomaly_model.model_commitment()
            signal.score = min(1.0, max(signal.score, anomaly_score))
            review_threshold, block_threshold = self.monitoring.thresholds_for(
                current.side_effect_level
            )
            signal.review_required = signal.score >= review_threshold
            if block_threshold is not None and signal.score >= block_threshold:
                signal.review_required = True
            if anomaly_score >= review_threshold:
                signal.flags = sorted(set([*signal.flags, "anomaly_baseline"]))
                signal.reasons.append(
                    f"ATIF baseline anomaly score {anomaly_score:.2f} exceeds review threshold"
                )
            signal.model_id = (
                f"{signal.model_id}+{self.anomaly_model.model_id}"
                if self.anomaly_model.model_id not in signal.model_id
                else signal.model_id
            )
            from agentauth.receipts.anomaly_proof import build_anomaly_score_proof

            signal.anomaly_proof = build_anomaly_score_proof(
                model=self.anomaly_model,
                feature_vector=features,
                score=anomaly_score,
            ).to_dict()
        from agentauth.receipts.model_canary import evaluate_canary_delta

        canary_signal = evaluate_canary_delta(history, policy=self.canary)
        if canary_signal is not None:
            signal.score = min(1.0, max(signal.score, canary_signal.score))
            signal.flags = sorted(set([*signal.flags, *canary_signal.flags]))
            signal.reasons.extend(canary_signal.reasons)
            review_threshold, _ = self.monitoring.thresholds_for(current.side_effect_level)
            signal.review_required = signal.score >= review_threshold
            signal.model_id = f"{signal.model_id}+canary-v1"
        if commit:
            history.append(current)
            if len(history) > self.monitoring.history_window:
                del history[: -self.monitoring.history_window]
        return signal
