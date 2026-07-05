from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from harness.config import AdapterOptions
from harness.corpus_paths import resolve_csv
from harness.fraud_metrics import decision_label_mismatch
from harness.fraud_model import feature_fraud_agent
from harness.types import BenchmarkCase, SuiteName

LABEL_FIELD = "label"


@dataclass(frozen=True)
class FraudDatasetSpec:
    suite: SuiteName
    env_var: str
    corpus_relative: Path
    arl_filename: str
    case_prefix: str


FRAUD_DATASETS: tuple[FraudDatasetSpec, ...] = (
    FraudDatasetSpec(
        suite="ieee_cis_fraud",
        env_var="AGENTAUTH_CORPUS_IEEE_CIS",
        corpus_relative=Path("ieee_cis/ieee_cis_full.csv"),
        arl_filename="ieee_cis_full.csv",
        case_prefix="ieee",
    ),
    FraudDatasetSpec(
        suite="paysim_fraud",
        env_var="AGENTAUTH_CORPUS_PAYSIM",
        corpus_relative=Path("paysim/paysim.csv"),
        arl_filename="paysim.csv",
        case_prefix="paysim",
    ),
    FraudDatasetSpec(
        suite="elliptic_fraud",
        env_var="AGENTAUTH_CORPUS_ELLIPTIC",
        corpus_relative=Path("elliptic/elliptic_fraud.csv"),
        arl_filename="elliptic_fraud.csv",
        case_prefix="elliptic",
    ),
    FraudDatasetSpec(
        suite="baf_fraud",
        env_var="AGENTAUTH_CORPUS_BAF",
        corpus_relative=Path("baf/baf_base_fraud.csv"),
        arl_filename="baf_base_fraud.csv",
        case_prefix="baf",
    ),
)

_SPECS_BY_SUITE = {spec.suite: spec for spec in FRAUD_DATASETS}


def _csv_path(spec: FraudDatasetSpec) -> Path | None:
    return resolve_csv(
        env_var=spec.env_var,
        corpus_relative=spec.corpus_relative,
        arl_filename=spec.arl_filename,
    )


def _select_rows(
    csv_path: Path,
    *,
    limit: int | None,
    sample: str,
) -> list[tuple[int, dict[str, str]]]:
    if sample == "stratified":
        fraud_rows: list[tuple[int, dict[str, str]]] = []
        normal_rows: list[tuple[int, dict[str, str]]] = []
        with csv_path.open(newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if int(row[LABEL_FIELD]) == 1:
                    fraud_rows.append((index, row))
                else:
                    normal_rows.append((index, row))
        if limit is None:
            return fraud_rows + normal_rows
        fraud_take = min(len(fraud_rows), max(1, limit // 10), limit)
        normal_take = limit - fraud_take
        return fraud_rows[:fraud_take] + normal_rows[:normal_take]

    selected: list[tuple[int, dict[str, str]]] = []
    with csv_path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            selected.append((index, row))
            if limit is not None and len(selected) >= limit:
                break
    return selected


def _score_signal(row: dict[str, str]) -> float:
    return abs(float(row.get("feature_0") or 0))


def iter_cases_for(
    spec: FraudDatasetSpec,
    *,
    limit: int | None = None,
    options: AdapterOptions | None = None,
) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    csv_path = _csv_path(spec)
    if csv_path is None:
        return

    rows = _select_rows(csv_path, limit=limit, sample=opts.ulb_sample)
    for index, row in rows:
        label = int(row[LABEL_FIELD])
        signal = _score_signal(row)
        case_id = f"{spec.case_prefix}_{index:06d}"

        def make_execute(
            txn_id: str,
            fraud_label: int,
            score_signal: float,
            sample_mode: str,
            source: str,
        ):
            def execute(agent):
                result = agent.run(
                    {"transaction_id": txn_id, "score_signal": score_signal},
                    session_id=f"{spec.case_prefix}-{txn_id}",
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
                        "source_csv": source,
                    },
                }

            return execute

        yield BenchmarkCase(
            suite=spec.suite,
            case_id=case_id,
            description=f"{spec.suite} row {index} signal={signal:.4f}",
            metadata={
                "label": label,
                "score_signal": signal,
                "sample_mode": opts.ulb_sample,
                "source_csv": str(csv_path),
            },
            model=feature_fraud_agent,
            execute=make_execute(
                case_id,
                label,
                signal,
                opts.ulb_sample,
                str(csv_path),
            ),
        )


def iter_cases(
    suite: SuiteName,
    *,
    limit: int | None = None,
    options: AdapterOptions | None = None,
) -> Iterator[BenchmarkCase]:
    spec = _SPECS_BY_SUITE.get(suite)
    if spec is None:
        return
    yield from iter_cases_for(spec, limit=limit, options=options)
