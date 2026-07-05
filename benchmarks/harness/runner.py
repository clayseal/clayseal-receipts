from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from harness.adapters.registry import SUITE_LOADERS, all_suite_names, iter_cases
from harness.config import FRAUD_SUITES, AdapterOptions
from harness.paths import RESULTS, ensure_import_paths
from harness.pipeline import (
    BenchmarkPipeline,
    PipelineConfig,
    fraud_policy,
    mcp_policy,
    tau2_policy,
)
from harness.provenance import collect_run_provenance
from harness.identity_metrics import summarize_identity
from harness.prove_metrics import summarize_prove
from harness.red_team_metrics import summarize_red_team
from harness.synthetic_metrics import SYNTHETIC_SUITES, summarize_synthetic
from harness.types import BenchmarkCase, CaseResult, SuiteName, SuiteSummary

SUITE_POLICIES = {
    "ulb_fraud": fraud_policy,
    "ieee_cis_fraud": fraud_policy,
    "paysim_fraud": fraud_policy,
    "elliptic_fraud": fraud_policy,
    "baf_fraud": fraud_policy,
    "atif_mcp": mcp_policy,
    "bfcl_caps": mcp_policy,
    "tau2_policy": tau2_policy,
    "mcp_bench_tasks": mcp_policy,
    "swe_session": mcp_policy,
    "red_team": mcp_policy,
    "synthetic_revocation": fraud_policy,
    "synthetic_tenant": fraud_policy,
    "synthetic_l1": fraud_policy,
    "synthetic_assurance": fraud_policy,
}


@dataclass
class RunReport:
    started_at: str
    finished_at: str
    config: dict
    suites: list[SuiteSummary]
    cases: list[CaseResult]
    corpora: list[dict]
    overview: dict | None = None
    tamper_coverage: dict | None = None

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "config": self.config,
            "suites": [suite.to_dict() for suite in self.suites],
            "cases": [case.to_dict() for case in self.cases],
            "corpora": self.corpora,
            "overview": self.overview,
            "tamper_coverage": self.tamper_coverage,
        }


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * pct / 100.0
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    if low == high:
        return ordered[low]
    weight = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * weight


def _rate(values: list[bool | None]) -> float | None:
    present = [value for value in values if value is not None]
    if not present:
        return None
    return sum(1 for value in present if value) / len(present)


def _label_mismatch_rate(results: list[CaseResult]) -> float | None:
    flags = [item.metadata.get("label_mismatch") for item in results]
    present = [value for value in flags if value is not None]
    if not present:
        return None
    return sum(1 for value in present if value) / len(present)


def _tamper_totals(results: list[CaseResult]) -> tuple[int, int, int] | None:
    relevant = [item for item in results if item.tamper_total_mutations is not None]
    if not relevant:
        return None
    total = sum(int(item.tamper_total_mutations or 0) for item in relevant)
    detected = sum(int(item.tamper_detected_mutations or 0) for item in relevant)
    invalidated = sum(int(item.tamper_invalidated_mutations or 0) for item in relevant)
    return total, detected, invalidated


def _classify_survivor_path(path: str) -> str:
    expected_prefixes = (
        "sdk_version",
        "exported_at",
        "verification.reasons",
        "decision.approval_metadata",
        "decision.budget_effects",
        "action.",
        "audit_record.action",
        "audit_record.authorization_context.action.",
        "audit_record.authorization_context.authority.",
        # Harness/local-only metadata, not part of the receipt's integrity model:
        "policy_path",
        "context.",
    )
    security_prefixes = (
        "output.",
        "execution_context.",
        "certificate.",
        "execution_proof.",
        "policy.",
        "signatures",
        "audit_inclusion",
        "scitt.",
        "lineage.",
        "handoff.",
        "evidence_refs.",
        "mandate.",
        "authority.",
        "decision.outcome",
        "decision.policy_satisfied",
        "decision.session_id",
        "decision.authority_version",
        # EV-RT-2/EV-RT-3: these are now bound at verify time (see export.py).
        "decision.recommended_action",
        "decision.approval_state",
        "decision.violations",
        "evidence.",
        "audit_record.",
        "session.",
    )
    if path.startswith(expected_prefixes):
        return "expected_informational"
    if path.startswith(security_prefixes):
        return "security_relevant"
    return "uncategorized"


def _summarize_tamper_coverage(results: list[CaseResult]) -> dict | None:
    relevant = [item for item in results if item.tamper_total_mutations is not None]
    if not relevant:
        return None
    total_mutations = sum(int(item.tamper_total_mutations or 0) for item in relevant)
    detected_mutations = sum(int(item.tamper_detected_mutations or 0) for item in relevant)
    invalidated_mutations = sum(int(item.tamper_invalidated_mutations or 0) for item in relevant)
    valid_baseline = [item for item in relevant if item.verify_valid is True]
    invalid_baseline = [item for item in relevant if item.verify_valid is not True]
    valid_total_mutations = sum(int(item.tamper_total_mutations or 0) for item in valid_baseline)
    valid_detected_mutations = sum(
        int(item.tamper_detected_mutations or 0) for item in valid_baseline
    )
    valid_invalidated_mutations = sum(
        int(item.tamper_invalidated_mutations or 0) for item in valid_baseline
    )
    invalid_total_mutations = sum(
        int(item.tamper_total_mutations or 0) for item in invalid_baseline
    )
    invalid_detected_mutations = sum(
        int(item.tamper_detected_mutations or 0) for item in invalid_baseline
    )

    survivor_counts: dict[str, int] = {}
    survivor_examples: dict[str, list[str]] = {}
    by_suite: dict[str, dict[str, int]] = {}
    by_classification: dict[str, dict[str, int]] = {}
    for item in relevant:
        suite_counts = by_suite.setdefault(item.suite, {})
        for path in item.tamper_survivor_paths:
            survivor_counts[path] = survivor_counts.get(path, 0) + 1
            suite_counts[path] = suite_counts.get(path, 0) + 1
            classification = _classify_survivor_path(path)
            class_counts = by_classification.setdefault(classification, {})
            class_counts[path] = class_counts.get(path, 0) + 1
            examples = survivor_examples.setdefault(path, [])
            example = f"{item.suite}:{item.case_id}"
            if len(examples) < 5 and example not in examples:
                examples.append(example)

    top_survivors = [
        {
            "path": path,
            "count": count,
            "examples": survivor_examples.get(path, []),
        }
        for path, count in sorted(
            survivor_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )
    ]
    by_suite_rows = {
        suite: [
            {"path": path, "count": count}
            for path, count in sorted(
                suite_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
        for suite, suite_counts in sorted(by_suite.items())
    }
    by_classification_rows = {
        classification: [
            {
                "path": path,
                "count": count,
                "examples": survivor_examples.get(path, []),
            }
            for path, count in sorted(
                class_counts.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
        for classification, class_counts in sorted(by_classification.items())
    }
    classification_counts = {
        classification: sum(class_counts.values())
        for classification, class_counts in sorted(by_classification.items())
    }

    return {
        "cases_analyzed": len(relevant),
        "cases_with_valid_baseline": len(valid_baseline),
        "cases_with_invalid_baseline": len(invalid_baseline),
        "total_mutations": total_mutations,
        "detected_mutations": detected_mutations,
        "invalidated_mutations": invalidated_mutations,
        "detection_rate": (detected_mutations / total_mutations) if total_mutations else None,
        "invalidation_rate": (invalidated_mutations / total_mutations) if total_mutations else None,
        "valid_baseline_total_mutations": valid_total_mutations,
        "valid_baseline_detected_mutations": valid_detected_mutations,
        "valid_baseline_invalidated_mutations": valid_invalidated_mutations,
        "valid_baseline_detection_rate": (
            valid_detected_mutations / valid_total_mutations
        )
        if valid_total_mutations
        else None,
        "valid_baseline_invalidation_rate": (
            valid_invalidated_mutations / valid_total_mutations
        )
        if valid_total_mutations
        else None,
        "invalid_baseline_total_mutations": invalid_total_mutations,
        "invalid_baseline_detected_mutations": invalid_detected_mutations,
        "invalid_baseline_detection_rate": (
            invalid_detected_mutations / invalid_total_mutations
        )
        if invalid_total_mutations
        else None,
        "survivor_field_count": len(survivor_counts),
        "survivor_classification_counts": classification_counts,
        "top_survivors": top_survivors,
        "survivors_by_suite": by_suite_rows,
        "survivors_by_classification": by_classification_rows,
    }


def _build_overview(
    results: list[CaseResult],
    suites: list[SuiteSummary],
    *,
    started_at: str,
    finished_at: str,
) -> dict:
    total_cases = len(results)
    passed_cases = sum(1 for item in results if item.ok)
    failed_cases = sum(1 for item in results if not item.ok)
    exported_cases = sum(1 for item in results if item.export_ok)
    verified_cases = sum(1 for item in results if item.verify_valid is not None)
    verify_valid_cases = sum(1 for item in results if item.verify_valid is True)
    audit_ok_cases = sum(1 for item in results if item.audit_chain_ok)
    policy_ok_cases = sum(1 for item in results if item.policy_satisfied is True)
    errored_cases = sum(1 for item in results if item.error is not None)
    skipped_suites = sum(1 for item in suites if item.skipped and item.total == 0)
    latencies = [item.latency_ms for item in results]
    return {
        "started_at": started_at,
        "finished_at": finished_at,
        "suite_count": len(suites),
        "suite_count_with_cases": sum(1 for item in suites if item.total > 0),
        "suite_count_skipped": skipped_suites,
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "errored_cases": errored_cases,
        "exported_cases": exported_cases,
        "verified_cases": verified_cases,
        "verify_valid_cases": verify_valid_cases,
        "audit_chain_ok_cases": audit_ok_cases,
        "policy_satisfied_cases": policy_ok_cases,
        "pass_rate": (passed_cases / total_cases) if total_cases else None,
        "export_rate": (exported_cases / total_cases) if total_cases else None,
        "verify_attempt_rate": (verified_cases / total_cases) if total_cases else None,
        "verify_valid_rate": (verify_valid_cases / total_cases) if total_cases else None,
        "audit_chain_ok_rate": (audit_ok_cases / total_cases) if total_cases else None,
        "policy_satisfied_rate": (policy_ok_cases / total_cases) if total_cases else None,
        "avg_latency_ms": (sum(latencies) / len(latencies)) if latencies else None,
        "p50_latency_ms": _percentile(latencies, 50),
        "p95_latency_ms": _percentile(latencies, 95),
    }


def _summarize_suite(
    suite: str,
    results: list[CaseResult],
    *,
    mode: str = "bounded_auto",
    with_identity: bool = False,
) -> SuiteSummary:
    if not results:
        return SuiteSummary(
            suite=suite,
            total=0,
            passed=0,
            failed=0,
            skipped=0,
            avg_latency_ms=0.0,
        )
    passed = sum(1 for item in results if item.ok)
    failed = sum(1 for item in results if not item.ok and item.error is None)
    skipped = sum(1 for item in results if item.error and "skipped" in (item.error or "").lower())
    latencies = [item.latency_ms for item in results]
    summary = SuiteSummary(
        suite=suite,
        total=len(results),
        passed=passed,
        failed=failed,
        skipped=skipped,
        avg_latency_ms=sum(latencies) / len(latencies),
        p50_latency_ms=_percentile(latencies, 50),
        p95_latency_ms=_percentile(latencies, 95),
        verify_valid_rate=_rate([item.verify_valid for item in results]),
        policy_satisfied_rate=_rate([item.policy_satisfied for item in results]),
        export_ok_rate=_rate([item.export_ok for item in results]),
        audit_chain_ok_rate=_rate([item.audit_chain_ok for item in results]),
    )
    tamper = _tamper_totals(results)
    if tamper is not None:
        total_mutations, detected_mutations, invalidated_mutations = tamper
        summary.tamper_total_mutations = total_mutations
        summary.tamper_detected_mutations = detected_mutations
        summary.tamper_invalidated_mutations = invalidated_mutations
        if total_mutations:
            summary.tamper_detection_rate = detected_mutations / total_mutations
            summary.tamper_invalidation_rate = invalidated_mutations / total_mutations
    if suite == "red_team":
        rt = summarize_red_team(results)
        summary.control_pass_rate = rt["rates"]["control_pass_rate"]
        summary.baseline_pass_rate = rt["rates"]["baseline_pass_rate"]
        summary.blind_spot_open_rate = rt["rates"]["blind_spot_open_rate"]
        summary.red_team_metrics = rt
    if suite in SYNTHETIC_SUITES:
        syn = summarize_synthetic(results)
        summary.control_pass_rate = syn["rates"]["control_pass_rate"]
        summary.baseline_pass_rate = syn["rates"]["baseline_pass_rate"]
        summary.blind_spot_open_rate = syn["rates"]["blind_spot_open_rate"]
        summary.synthetic_metrics = syn
    if suite in FRAUD_SUITES:
        summary.label_mismatch_rate = _label_mismatch_rate(results)
    if with_identity:
        identity = summarize_identity(results)
        if identity:
            summary.identity_metrics = identity
    prove = summarize_prove(results, mode=mode)
    if prove is not None:
        summary.prove_metrics = prove
    return summary


def run_benchmarks(
    *,
    suites: list[SuiteName] | None = None,
    limit: int | None = 50,
    mode: str = "bounded_auto",
    export_receipts: bool = True,
    with_identity: bool = False,
    require_verify: bool = False,
    tamper_analysis: bool = False,
    shared_audit_db: bool = False,
    inference_backend: str = "ezkl",
    model_provenance_hash: str | None = None,
    prove_composed: bool | None = None,
    attach_mock_tee: bool = False,
    adapter_options: AdapterOptions | None = None,
    results_dir: Path | None = None,
) -> RunReport:
    ensure_import_paths()
    started = datetime.now(UTC).isoformat()
    selected = suites or all_suite_names()
    options = adapter_options or AdapterOptions()
    if limit is not None:
        options.limit = limit
    out_dir = results_dir or (RESULTS / datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ"))
    out_dir.mkdir(parents=True, exist_ok=True)

    from harness.pipeline import DEFAULT_PROVE_MODEL_HASH

    config = PipelineConfig(
        mode=mode,  # type: ignore[arg-type]
        export_receipts=export_receipts,
        results_dir=out_dir if export_receipts else None,
        with_identity=with_identity,
        require_verify=require_verify,
        tamper_analysis=tamper_analysis,
        shared_audit_db=shared_audit_db,
        inference_backend=inference_backend,  # type: ignore[arg-type]
        model_provenance_hash=model_provenance_hash or DEFAULT_PROVE_MODEL_HASH,
        prove_composed=prove_composed,
        attach_mock_tee=attach_mock_tee,
    )

    all_results: list[CaseResult] = []
    suite_summaries: list[SuiteSummary] = []
    cases_by_suite: dict[str, list[BenchmarkCase]] = {}

    for suite in selected:
        if suite not in SUITE_LOADERS:
            continue
        policy_factory = SUITE_POLICIES.get(suite, mcp_policy)
        pipeline = BenchmarkPipeline(policy_factory(), config=config)
        suite_results: list[CaseResult] = []
        cases = list(iter_cases(suite, limit=limit, options=options))
        cases_by_suite[suite] = cases
        if not cases:
            suite_summaries.append(
                SuiteSummary(
                    suite=suite,
                    total=0,
                    passed=0,
                    failed=0,
                    skipped=1,
                    avg_latency_ms=0.0,
                )
            )
            continue

        for case in cases:
            result = pipeline.run_case(case)
            suite_results.append(result)
            all_results.append(result)

        suite_summaries.append(
            _summarize_suite(
                suite,
                suite_results,
                mode=mode,
                with_identity=with_identity,
            )
        )

    finished = datetime.now(UTC).isoformat()
    corpora = [
        record.to_dict()
        for record in collect_run_provenance(
            selected,
            options=options,
            cases_by_suite=cases_by_suite,
        )
    ]
    report = RunReport(
        started_at=started,
        finished_at=finished,
        config={
            "suites": selected,
            "limit_per_suite": limit,
            "mode": mode,
            "export_receipts": export_receipts,
            "with_identity": with_identity,
            "require_verify": require_verify,
            "tamper_analysis": tamper_analysis,
            "shared_audit_db": shared_audit_db,
            "inference_backend": inference_backend,
            "model_provenance_hash": config.model_provenance_hash,
            "prove_composed": prove_composed,
            "tau2_domains": options.tau2_domains,
            "tau2_telecom_tasks": options.tau2_telecom_tasks,
            "ulb_sample": options.ulb_sample,
            "swe_shards": options.swe_shards,
            "attach_mock_tee": attach_mock_tee,
            "policy_mode": options.policy_mode,
            "results_dir": str(out_dir),
        },
        suites=suite_summaries,
        cases=all_results,
        corpora=corpora,
        overview=_build_overview(
            all_results,
            suite_summaries,
            started_at=started,
            finished_at=finished,
        ),
        tamper_coverage=_summarize_tamper_coverage(all_results),
    )

    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(report.to_dict(), indent=2))
    with (out_dir / "cases.jsonl").open("w") as handle:
        for case in all_results:
            handle.write(json.dumps(case.to_dict()) + "\n")

    return report
