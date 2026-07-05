"""DP-22: Novelty triggers — detects first-time access to new subsystems,
tool classes, network domains, and protected zones.

Emits STEP_UP when the agent crosses a novelty boundary that was not
seen earlier in the session.  Once a boundary has been approved (via
step-up or explicit allow), subsequent accesses to the same category
are silently allowed.

This monitor is deterministic and non-LLM.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentauth.core.hash_util import hash_canonical_json

from .behavior_monitor import BehaviorMonitorResult, BehaviorRecommendation
from .monitor_contract import MonitorInput


@dataclass
class NoveltyConfig:
    track_subsystems: bool = True
    track_tool_classes: bool = True
    track_net_domains: bool = True
    track_protected_zones: bool = True
    protected_zone_prefixes: tuple[str, ...] = (
        "repo://keys/",
        "repo://auth/",
        "repo://identity/",
        "repo://deploy/",
        "repo://terraform/",
        "repo://helm/",
        "repo://.github/workflows/",
        "repo://.env",
        "secrets://",
    )
    monitor_id: str = "novelty_trigger"
    monitor_version: str = "v1"


def _subsystem_of(resource_ref: str) -> str | None:
    path = resource_ref
    for prefix in ("repo_write://", "repo_read://", "repo://", "file:"):
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    parts = path.replace("\\", "/").strip("/").split("/")
    if len(parts) >= 2:
        return parts[0]
    return None


def _tool_class_of(action_name: str) -> str:
    parts = action_name.rsplit("/", 1)
    return parts[0] if len(parts) > 1 else action_name


def _net_domain_of(resource_ref: str) -> str | None:
    if resource_ref.startswith("net://"):
        host = resource_ref[len("net://"):].split("/")[0].split(":")[0]
        return host or None
    return None


class NoveltyMonitor:
    """Detects first-time access to new subsystems / tool classes / domains (DP-22).

    Once a novelty has been seen and the action was allowed (not blocked),
    call ``approve(category)`` to suppress future triggers for that category.

    This is a ``BehaviorMonitorWithContract``-compatible monitor.
    """

    def __init__(self, *, config: NoveltyConfig | None = None) -> None:
        cfg = config or NoveltyConfig()
        self.config = cfg
        self.monitor_id = cfg.monitor_id
        self.monitor_version = cfg.monitor_version
        self._seen_subsystems: set[str] = set()
        self._seen_tool_classes: set[str] = set()
        self._seen_domains: set[str] = set()
        self._seen_protected: set[str] = set()
        self._approved_subsystems: set[str] = set()
        self._approved_tool_classes: set[str] = set()
        self._approved_domains: set[str] = set()
        self._approved_protected: set[str] = set()

    def approve_subsystem(self, subsystem: str) -> None:
        self._approved_subsystems.add(subsystem)

    def approve_tool_class(self, tool_class: str) -> None:
        self._approved_tool_classes.add(tool_class)

    def approve_domain(self, domain: str) -> None:
        self._approved_domains.add(domain)

    def approve_protected(self, prefix: str) -> None:
        self._approved_protected.add(prefix)

    def evaluate_contract(self, contract: MonitorInput) -> BehaviorMonitorResult | None:
        triggers: list[str] = []

        ref = contract.proposed.resource_ref
        action_name = contract.proposed.action_name

        if self.config.track_subsystems and ref:
            sub = _subsystem_of(ref)
            if sub and sub not in self._seen_subsystems and sub not in self._approved_subsystems:
                triggers.append(f"novelty: first access to subsystem '{sub}'")
            if sub:
                self._seen_subsystems.add(sub)

        if self.config.track_tool_classes:
            tc = _tool_class_of(action_name)
            if tc not in self._seen_tool_classes and tc not in self._approved_tool_classes:
                if self._seen_tool_classes:
                    triggers.append(f"novelty: new tool class '{tc}'")
            self._seen_tool_classes.add(tc)

        if self.config.track_net_domains and ref:
            domain = _net_domain_of(ref)
            if domain and domain not in self._seen_domains and domain not in self._approved_domains:
                triggers.append(f"novelty: new network domain '{domain}'")
            if domain:
                self._seen_domains.add(domain)

        if self.config.track_protected_zones and ref:
            for prefix in self.config.protected_zone_prefixes:
                if ref.startswith(prefix) and prefix not in self._seen_protected:
                    if prefix not in self._approved_protected:
                        triggers.append(f"novelty: first access to protected zone '{prefix}'")
                    self._seen_protected.add(prefix)

        if not triggers:
            return None

        trace_payload = {
            "triggers": triggers,
            "seen_subsystems": sorted(self._seen_subsystems),
            "seen_tool_classes": sorted(self._seen_tool_classes),
        }
        trace_commitment = f"sha256:{hash_canonical_json(trace_payload)}"

        return BehaviorMonitorResult(
            monitor_id=self.monitor_id,
            monitor_version=self.monitor_version,
            detector_family="rules",
            feature_set_id="novelty_v1",
            risk_score=min(1.0, len(triggers) * 0.3),
            threshold=0.3,
            recommendation=BehaviorRecommendation.STEP_UP,
            reasons=triggers,
            trace_commitment=trace_commitment,
        )

    @property
    def seen_subsystems(self) -> frozenset[str]:
        return frozenset(self._seen_subsystems)

    @property
    def seen_tool_classes(self) -> frozenset[str]:
        return frozenset(self._seen_tool_classes)

    @property
    def seen_domains(self) -> frozenset[str]:
        return frozenset(self._seen_domains)
