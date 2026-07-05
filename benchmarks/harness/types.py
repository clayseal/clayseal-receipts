from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

SuiteName = Literal[
    "ulb_fraud",
    "ieee_cis_fraud",
    "paysim_fraud",
    "elliptic_fraud",
    "baf_fraud",
    "amazon_fdb",
    "atif_mcp",
    "bfcl_caps",
    "tau2_policy",
    "mcp_bench_tasks",
    "swe_session",
    "red_team",
    "synthetic_revocation",
    "synthetic_tenant",
    "synthetic_l1",
    "synthetic_assurance",
]


@dataclass
class BenchmarkCase:
    suite: SuiteName
    case_id: str
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    model: Callable[[dict[str, Any]], dict[str, Any]] | None = None
    execute: Callable[[Any], dict[str, Any]] | None = None


@dataclass
class CaseResult:
    suite: str
    case_id: str
    ok: bool
    latency_ms: float
    policy_satisfied: bool | None = None
    decision_outcome: str | None = None
    export_ok: bool = False
    verify_valid: bool | None = None
    verify_reasons: list[str] = field(default_factory=list)
    audit_records: int = 0
    audit_chain_ok: bool = False
    tamper_total_mutations: int | None = None
    tamper_detected_mutations: int | None = None
    tamper_invalidated_mutations: int | None = None
    tamper_detection_rate: float | None = None
    tamper_invalidation_rate: float | None = None
    tamper_survivor_paths: list[str] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SuiteSummary:
    suite: str
    total: int
    passed: int
    failed: int
    skipped: int
    avg_latency_ms: float
    p50_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    verify_valid_rate: float | None = None
    policy_satisfied_rate: float | None = None
    export_ok_rate: float | None = None
    audit_chain_ok_rate: float | None = None
    tamper_total_mutations: int | None = None
    tamper_detected_mutations: int | None = None
    tamper_invalidated_mutations: int | None = None
    tamper_detection_rate: float | None = None
    tamper_invalidation_rate: float | None = None
    control_pass_rate: float | None = None
    baseline_pass_rate: float | None = None
    blind_spot_open_rate: float | None = None
    label_mismatch_rate: float | None = None
    red_team_metrics: dict[str, Any] | None = None
    synthetic_metrics: dict[str, Any] | None = None
    identity_metrics: dict[str, Any] | None = None
    prove_metrics: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
