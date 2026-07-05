"""DP-35: Scanning scorer — detects breadth/entropy anomalies in the trace.

Tracks the number of unique directories, files, and subsystems touched
within a rolling window.  Emits a non-binding STEP_UP when the agent's
resource-access breadth grows too rapidly, which is a signal of directory
walking, mass grep, or reconnaissance.

This monitor is deterministic and non-LLM: it operates only on trusted
telemetry from the MonitorInput contract.
"""
from __future__ import annotations

import math
from collections import Counter, deque
from dataclasses import dataclass

from agentauth.core.hash_util import hash_canonical_json

from .behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from .monitor_contract import MonitorInput


@dataclass
class ScanScorerConfig:
    window: int = 20
    max_unique_dirs: int = 8
    max_unique_files: int = 15
    entropy_threshold: float = 2.5
    monitor_id: str = "scanning_scorer"
    monitor_version: str = "v1"


def _dir_of(resource_ref: str) -> str:
    path = resource_ref
    for prefix in ("repo_write://", "repo_read://", "repo://", "file:"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    parts = path.replace("\\", "/").strip("/").rsplit("/", 1)
    return parts[0] if len(parts) > 1 else "."


def _resource_entropy(counts: Counter[str]) -> float:
    total = sum(counts.values())
    if total <= 1:
        return 0.0
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class ScanningScorer:
    """Rolling breadth/entropy tracker over recent resource accesses (DP-35).

    Triggers:
    - unique directories in the window exceed ``max_unique_dirs``
    - unique files in the window exceed ``max_unique_files``
    - directory-access entropy exceeds ``entropy_threshold``

    Any trigger emits STEP_UP; multiple triggers raise the risk score.

    This is a ``BehaviorMonitorWithContract``-compatible monitor.
    """

    def __init__(self, *, config: ScanScorerConfig | None = None) -> None:
        cfg = config or ScanScorerConfig()
        if cfg.window <= 0:
            raise ValueError("window must be > 0")
        self.window = cfg.window
        self.max_unique_dirs = cfg.max_unique_dirs
        self.max_unique_files = cfg.max_unique_files
        self.entropy_threshold = float(cfg.entropy_threshold)
        self.monitor_id = cfg.monitor_id
        self.monitor_version = cfg.monitor_version
        self._recent_refs: deque[str] = deque(maxlen=cfg.window)

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        ref = contract.proposed.resource_ref
        if ref:
            self._recent_refs.append(ref)

        if len(self._recent_refs) < 3:
            return None

        dirs = Counter(_dir_of(r) for r in self._recent_refs)
        files = Counter(self._recent_refs)
        entropy = _resource_entropy(dirs)

        reasons: list[str] = []
        triggers = 0

        if len(dirs) > self.max_unique_dirs:
            reasons.append(
                f"scan: {len(dirs)} unique dirs in window "
                f"(limit {self.max_unique_dirs})"
            )
            triggers += 1

        if len(files) > self.max_unique_files:
            reasons.append(
                f"scan: {len(files)} unique files in window "
                f"(limit {self.max_unique_files})"
            )
            triggers += 1

        if entropy > self.entropy_threshold:
            reasons.append(
                f"scan: dir entropy {entropy:.2f} > {self.entropy_threshold}"
            )
            triggers += 1

        risk = min(1.0, triggers * 0.4) if triggers else 0.0

        trace_payload = {
            "unique_dirs": len(dirs),
            "unique_files": len(files),
            "dir_entropy": round(entropy, 4),
            "window": self.window,
        }
        trace_commitment = f"sha256:{hash_canonical_json(trace_payload)}"

        recommendation = (
            BehaviorRecommendation.STEP_UP if triggers > 0
            else BehaviorRecommendation.ALLOW
        )

        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family="rules",
            feature_set_id="scan_breadth_v1",
            risk_score=risk,
            threshold=0.4,
            recommendation=recommendation,
            reasons=reasons,
            trace_commitment=trace_commitment,
        )

    @property
    def unique_dirs(self) -> int:
        return len(set(_dir_of(r) for r in self._recent_refs))

    @property
    def unique_files(self) -> int:
        return len(set(self._recent_refs))
