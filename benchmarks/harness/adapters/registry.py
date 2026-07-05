from __future__ import annotations

from typing import Iterator

from harness.adapters import fraud_tabular
from harness.config import AdapterOptions
from harness.types import BenchmarkCase, SuiteName

from . import (
    amazon_fdb,
    atif_mcp,
    bfcl_caps,
    mcp_bench_tasks,
    red_team,
    swe_session,
    synthetic_assurance,
    synthetic_l1,
    synthetic_revocation,
    synthetic_tenant,
    tau2_policy,
    ulb_fraud,
)

SUITE_LOADERS: dict[SuiteName, callable] = {
    "ulb_fraud": ulb_fraud.iter_cases,
    "ieee_cis_fraud": lambda **kw: fraud_tabular.iter_cases("ieee_cis_fraud", **kw),
    "paysim_fraud": lambda **kw: fraud_tabular.iter_cases("paysim_fraud", **kw),
    "elliptic_fraud": lambda **kw: fraud_tabular.iter_cases("elliptic_fraud", **kw),
    "baf_fraud": lambda **kw: fraud_tabular.iter_cases("baf_fraud", **kw),
    "amazon_fdb": amazon_fdb.iter_cases,
    "atif_mcp": atif_mcp.iter_cases,
    "bfcl_caps": bfcl_caps.iter_cases,
    "tau2_policy": tau2_policy.iter_cases,
    "mcp_bench_tasks": mcp_bench_tasks.iter_cases,
    "swe_session": swe_session.iter_cases,
    "red_team": red_team.iter_cases,
    "synthetic_revocation": synthetic_revocation.iter_cases,
    "synthetic_tenant": synthetic_tenant.iter_cases,
    "synthetic_l1": synthetic_l1.iter_cases,
    "synthetic_assurance": synthetic_assurance.iter_cases,
}


def all_suite_names() -> list[SuiteName]:
    return list(SUITE_LOADERS.keys())


def iter_cases(
    suite: SuiteName,
    *,
    limit: int | None = None,
    options: AdapterOptions | None = None,
) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    count = 0
    for case in SUITE_LOADERS[suite](limit=limit, options=opts):
        yield case
        count += 1
        if limit is not None and count >= limit:
            break
