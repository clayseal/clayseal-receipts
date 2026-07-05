from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from agentauth.receipts.behavior_monitor import (
    BehaviorMonitorResult,
    BehaviorMonitorWithContract,
    BehaviorRecommendation,
)
from agentauth.receipts.monitor_contract import MonitorInput


@dataclass(frozen=True)
class SidecarMonitorStatus:
    ok: bool
    message: str | None = None


class HttpSidecarBehaviorMonitor(BehaviorMonitorWithContract):
    """
    Sidecar-backed behavior monitor.

    Intended for integrating external monitoring systems (e.g., BACA) without importing
    heavy dependencies into the agent process.

    Contract:
    - Request body: ``{"input": <MonitorInput dict>}``
    - Response body: either a raw monitor result dict, or ``{"monitoring": {...}}``.
    """

    def __init__(
        self,
        *,
        url: str,
        timeout_seconds: float = 1.0,
        monitor_id: str = "sidecar_behavior_monitor",
        monitor_version: str | None = None,
    ) -> None:
        self.url = url
        self.timeout_seconds = float(timeout_seconds)
        self.monitor_id = monitor_id
        self.monitor_version = monitor_version

    def status(self) -> SidecarMonitorStatus:
        if not isinstance(self.url, str) or not self.url:
            return SidecarMonitorStatus(False, "missing url")
        return SidecarMonitorStatus(True, None)

    def _post_json(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            self.url,
            method="POST",
            data=body,
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        with urlopen(req, timeout=self.timeout_seconds) as resp:  # noqa: S310
            data = resp.read()
        parsed = json.loads(data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data)
        if not isinstance(parsed, dict):
            raise ValueError("sidecar response must be a JSON object")
        return parsed

    def _parse_result(self, raw: dict[str, Any]) -> BehaviorMonitorResult:
        if "monitoring" in raw and isinstance(raw["monitoring"], dict):
            raw = dict(raw["monitoring"])

        rec_raw = raw.get("recommendation")
        recommendation = None
        if isinstance(rec_raw, str) and rec_raw:
            try:
                recommendation = BehaviorRecommendation(rec_raw)
            except ValueError:
                recommendation = None

        reasons_raw = raw.get("reasons", [])
        reasons = []
        if isinstance(reasons_raw, list):
            reasons = [str(item) for item in reasons_raw if item is not None]
        elif isinstance(reasons_raw, str) and reasons_raw:
            reasons = [reasons_raw]

        return BehaviorMonitorResult(
            monitor_id=str(raw.get("monitor_id") or self.monitor_id),
            monitor_version=str(raw.get("monitor_version") or self.monitor_version)
            if (raw.get("monitor_version") or self.monitor_version)
            else None,
            detector_family=str(raw.get("detector_family")) if raw.get("detector_family") else None,
            feature_set_id=str(raw.get("feature_set_id")) if raw.get("feature_set_id") else None,
            risk_score=float(raw["risk_score"]) if raw.get("risk_score") is not None else None,
            threshold=float(raw["threshold"]) if raw.get("threshold") is not None else None,
            recommendation=recommendation,
            reasons=reasons,
            trace_commitment=str(raw.get("trace_commitment")) if raw.get("trace_commitment") else None,
        )

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        status = self.status()
        if not status.ok:
            return None
        try:
            raw = self._post_json({"input": contract.to_dict()})
        except (URLError, TimeoutError, ValueError, json.JSONDecodeError):
            return None
        return self._parse_result(raw)

