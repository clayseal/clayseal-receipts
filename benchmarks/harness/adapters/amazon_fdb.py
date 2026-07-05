from __future__ import annotations

from typing import Iterator

from harness.config import AdapterOptions
from harness.fdb_corpus import (
    FDB_VERSIONED_DATASETS,
    FdbDatasetSpec,
    available_fdb_keys,
    load_versioned_test_rows,
)
from harness.fraud_metrics import decision_label_mismatch
from harness.fraud_model import feature_fraud_agent
from harness.types import BenchmarkCase, SuiteName

SUITE_NAME: SuiteName = "amazon_fdb"


def _ip_score_signal(ip: str) -> float:
    parts = ip.split(".")
    if len(parts) == 4:
        try:
            return int(parts[-1]) / 255.0
        except ValueError:
            pass
    return 0.5


def _score_signal_for_row(spec: FdbDatasetSpec, row: dict[str, str]) -> float:
    if spec.key == "ipblock":
        return _ip_score_signal(row.get("ip", ""))
    return 0.5


def _select_rows(
    spec: FdbDatasetSpec,
    *,
    limit: int | None,
    sample: str,
) -> list[tuple[int, dict[str, str], int]]:
    rows = load_versioned_test_rows(spec)
    if sample == "stratified":
        fraud_rows = [item for item in rows if item[2] == 1]
        normal_rows = [item for item in rows if item[2] == 0]
        if limit is None:
            return fraud_rows + normal_rows
        fraud_take = min(len(fraud_rows), max(1, limit // 10), limit)
        normal_take = limit - fraud_take
        return fraud_rows[:fraud_take] + normal_rows[:normal_take]

    if limit is None:
        return rows
    return rows[:limit]


def iter_cases(
    *,
    limit: int | None = None,
    options: AdapterOptions | None = None,
) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    if not available_fdb_keys():
        return

    for spec in FDB_VERSIONED_DATASETS:
        if spec.key not in available_fdb_keys():
            continue
        rows = _select_rows(spec, limit=limit, sample=opts.ulb_sample)
        for index, row, label in rows:
            signal = _score_signal_for_row(spec, row)
            case_id = f"{spec.key}_{index:06d}"
            event_id = row.get("EVENT_ID", case_id)

            def make_execute(
                txn_id: str,
                fraud_label: int,
                score_signal: float,
                fdb_key: str,
                fdb_version: str | None,
                sample_mode: str,
            ):
                def execute(agent):
                    result = agent.run(
                        {"transaction_id": txn_id, "score_signal": score_signal},
                        session_id=f"amazon-fdb-{fdb_key}-{txn_id}",
                    )
                    decision = result.output.get("decision")
                    return {
                        "ok": result.policy_satisfied,
                        "run_result": result,
                        "require_policy_ok": True,
                        "require_audit": True,
                        "metadata": {
                            "ground_truth_fraud": fraud_label,
                            "score_signal": score_signal,
                            "decision": decision,
                            "label_mismatch": decision_label_mismatch(decision, fraud_label),
                            "sample_mode": sample_mode,
                            "fdb_key": fdb_key,
                            "fdb_version": fdb_version,
                        },
                    }

                return execute

            yield BenchmarkCase(
                suite=SUITE_NAME,
                case_id=case_id,
                description=f"amazon_fdb/{spec.key} row {index} signal={signal:.4f}",
                metadata={
                    "label": label,
                    "score_signal": signal,
                    "sample_mode": opts.ulb_sample,
                    "fdb_key": spec.key,
                    "fdb_version": spec.version,
                },
                model=feature_fraud_agent,
                execute=make_execute(
                    event_id,
                    label,
                    signal,
                    spec.key,
                    spec.version,
                    opts.ulb_sample,
                ),
            )
