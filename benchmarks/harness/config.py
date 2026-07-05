from __future__ import annotations

from dataclasses import dataclass, field

TAU2_DOMAIN_CHOICES = ("mock", "airline", "retail", "telecom", "banking_knowledge")
POLICY_MODE_CHOICES = ("permissive", "tight")

FRAUD_SUITES = frozenset(
    {
        "ulb_fraud",
        "ieee_cis_fraud",
        "paysim_fraud",
        "elliptic_fraud",
        "baf_fraud",
        "amazon_fdb",
    }
)


TAU2_TELECOM_TASK_CHOICES = ("full", "small")


@dataclass
class AdapterOptions:
    limit: int | None = None
    tau2_domains: list[str] = field(default_factory=lambda: ["mock"])
    tau2_telecom_tasks: str = "full"
    ulb_sample: str = "sequential"
    swe_shards: list[int] = field(default_factory=lambda: [0])
    require_verify: bool = False
    policy_mode: str = "permissive"
