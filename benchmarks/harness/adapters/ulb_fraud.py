from __future__ import annotations

import csv
from typing import Iterator

from harness.config import AdapterOptions
from harness.fraud_metrics import decision_label_mismatch
from harness.fraud_model import amount_fraud_agent
from harness.paths import CORPUS
from harness.types import BenchmarkCase

CSV_PATH = CORPUS / "ulb_creditcard" / "creditcard.csv"


def _iter_selected_rows(*, limit: int | None, sample: str) -> list[tuple[int, dict[str, str]]]:
    if not CSV_PATH.is_file():
        return []

    if sample == "stratified":
        fraud_rows: list[tuple[int, dict[str, str]]] = []
        normal_rows: list[tuple[int, dict[str, str]]] = []
        with CSV_PATH.open(newline="") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if int(row["Class"]) == 1:
                    fraud_rows.append((index, row))
                else:
                    normal_rows.append((index, row))
        if limit is None:
            return fraud_rows + normal_rows
        fraud_take = min(len(fraud_rows), max(1, limit // 10), limit)
        normal_take = limit - fraud_take
        return fraud_rows[:fraud_take] + normal_rows[:normal_take]

    selected: list[tuple[int, dict[str, str]]] = []
    with CSV_PATH.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for index, row in enumerate(reader):
            selected.append((index, row))
            if limit is not None and len(selected) >= limit:
                break
    return selected


def iter_cases(*, limit: int | None = None, options: AdapterOptions | None = None) -> Iterator[BenchmarkCase]:
    opts = options or AdapterOptions()
    rows = _iter_selected_rows(limit=limit, sample=opts.ulb_sample)
    if not rows:
        return

    for index, row in rows:
        amount = float(row["Amount"])
        label = int(row["Class"])
        case_id = f"ulb_{index:06d}"

        def make_execute(amt: float, txn_id: str, fraud_label: int, sample_mode: str):
            def execute(agent):
                result = agent.run(
                    {"transaction_id": txn_id, "amount": amt},
                    session_id=f"ulb-{txn_id}",
                )
                decision = result.output.get("decision")
                return {
                    "ok": result.policy_satisfied,
                    "run_result": result,
                    "require_policy_ok": True,
                    "require_audit": True,
                    "metadata": {
                        "ground_truth_fraud": fraud_label,
                        "amount": amt,
                        "decision": decision,
                        "label_mismatch": decision_label_mismatch(decision, fraud_label),
                        "sample_mode": sample_mode,
                    },
                }

            return execute

        yield BenchmarkCase(
            suite="ulb_fraud",
            case_id=case_id,
            description=f"ULB creditcard row {index} Amount={amount}",
            metadata={"amount": amount, "class": label, "sample_mode": opts.ulb_sample},
            model=amount_fraud_agent,
            execute=make_execute(amount, case_id, label, opts.ulb_sample),
        )
