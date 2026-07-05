#!/usr/bin/env python3
"""Run end-to-end benchmark suites against the agent-receipts pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.adapters.registry import all_suite_names  # noqa: E402
from harness.config import (  # noqa: E402
    FRAUD_SUITES,
    POLICY_MODE_CHOICES,
    TAU2_DOMAIN_CHOICES,
    TAU2_TELECOM_TASK_CHOICES,
    AdapterOptions,
)
from harness.paths import ensure_import_paths  # noqa: E402
from harness.runner import run_benchmarks  # noqa: E402
from harness.types import SuiteName  # noqa: E402


def _parse_suites(raw: str | None) -> list[SuiteName] | None:
    if not raw or raw == "all":
        return None
    names: list[SuiteName] = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            names.append(part)  # type: ignore[arg-type]
    return names


def _parse_tau2_domains(raw: str | None) -> list[str]:
    if not raw:
        return ["mock"]
    if raw.strip().lower() == "all":
        return list(TAU2_DOMAIN_CHOICES)
    domains = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [domain for domain in domains if domain not in TAU2_DOMAIN_CHOICES]
    if unknown:
        raise SystemExit(f"Unknown tau2 domains: {', '.join(unknown)}")
    return domains


def _parse_swe_shards(raw: str) -> list[int]:
    from harness.adapters.swe_session import shard_count

    text = raw.strip()
    if text.lower() == "all":
        count = shard_count()
        if count == 0:
            return [0]
        return list(range(count))
    shards: list[int] = []
    for part in text.split(","):
        part = part.strip()
        if part:
            shards.append(int(part))
    return shards or [0]


def _format_rate(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def _print_red_team_metrics(red_team) -> None:
    metrics = red_team.red_team_metrics
    if not metrics:
        print(
            f"Red team: control={red_team.control_pass_rate!s} "
            f"baseline={red_team.baseline_pass_rate!s} "
            f"blind_spots_open={red_team.blind_spot_open_rate!s}"
        )
        return

    counts = metrics["counts"]
    rates = metrics["rates"]
    print(
        "Red team summary: "
        f"controls={counts['controls']} ({counts['controls_failed']} failed) · "
        f"baselines={counts['baselines']} ({counts['baselines_failed']} failed) · "
        "blind_spots="
        f"{counts['blind_spots']} "
        f"({counts['blind_spots_closed_unexpectedly']} closed unexpectedly) · "
        f"skipped={counts['skipped']}"
    )
    print(
        "Enforcement rates: "
        f"schema={_format_rate(rates.get('schema_enforcement_rate'))} · "
        f"tool_block={_format_rate(rates.get('tool_block_rate'))} · "
        f"cert_scope={_format_rate(rates.get('cert_scope_enforcement_rate'))} · "
        f"audit_integrity={_format_rate(rates.get('audit_integrity_rate'))}"
    )

    gaps = metrics["documented_gaps"]
    if gaps["open_gaps"]:
        gap_names = ", ".join(item["attack_surface"] for item in gaps["open_gaps"])
        print(f"Documented gaps open ({gaps['open_count']}): {gap_names}")

    by_layer = metrics.get("by_defense_layer") or {}
    if by_layer:
        layer_parts = [
            f"{layer}={_format_rate(stats.get('pass_rate'))}"
            for layer, stats in sorted(by_layer.items())
            if stats.get("active")
        ]
        if layer_parts:
            print(f"Defense layers: {', '.join(layer_parts)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Agent-receipts corpus E2E harness")
    parser.add_argument(
        "--suite",
        default="all",
        help=f"Comma-separated suites or 'all'. Available: {', '.join(all_suite_names())}",
    )
    parser.add_argument("--limit", type=int, default=20, help="Max cases per suite")
    parser.add_argument(
        "--mode",
        default="bounded_auto",
        choices=["shadow", "recommend", "bounded_auto", "prove"],
        help="AgentWrapper operating mode",
    )
    parser.add_argument("--no-export", action="store_true", help="Skip receipt export")
    parser.add_argument(
        "--with-identity",
        action="store_true",
        help="Bootstrap embedded AgentAuth and bind L1 credentials",
    )
    parser.add_argument(
        "--require-verify",
        action="store_true",
        help="Fail cases when verify_receipt_bundle.valid is false (assurance tier)",
    )
    parser.add_argument(
        "--tamper-analysis",
        action="store_true",
        help="Run systematic receipt-bundle tamper detection analysis for exported receipts",
    )
    parser.add_argument(
        "--tau2-domain",
        default="mock",
        help=f"Comma-separated tau2 domains or 'all'. Choices: {', '.join(TAU2_DOMAIN_CHOICES)}",
    )
    parser.add_argument(
        "--tau2-telecom-tasks",
        default="full",
        choices=list(TAU2_TELECOM_TASK_CHOICES),
        help="Telecom task corpus: full tasks.json or small tasks_small.json smoke set",
    )
    parser.add_argument(
        "--ulb-sample",
        default="sequential",
        choices=["sequential", "stratified"],
        help="ULB row selection: file order or stratified fraud/normal mix",
    )
    parser.add_argument(
        "--swe-shard",
        default="0",
        help="SWE parquet shard index (0-based), comma-separated list, or 'all'",
    )
    parser.add_argument(
        "--policy-mode",
        default="permissive",
        choices=list(POLICY_MODE_CHOICES),
        help="MCP replay policy: permissive (default) or tight allowlist (ATIF/tau2)",
    )
    parser.add_argument(
        "--attach-mock-tee",
        action="store_true",
        help="Attach mock Nitro attestation quote before export (EV-203 dev path)",
    )
    parser.add_argument(
        "--results-dir",
        type=Path,
        default=None,
        help="Directory for summary.json, cases.jsonl, and receipt bundles",
    )
    parser.add_argument(
        "--shared-audit-db",
        action="store_true",
        help="Reuse one audit SQLite DB per suite (slow at 10k+; for EV-008 volume tests)",
    )
    parser.add_argument(
        "--inference-backend",
        default="ezkl",
        choices=["ezkl", "risc0", "sp1"],
        help="Composed prove inference backend (prove mode only)",
    )
    parser.add_argument(
        "--model-hash",
        default=None,
        help="Model provenance hash for prove mode (default: sha256:fraud-head-onnx-v1)",
    )
    parser.add_argument(
        "--no-prove-composed",
        action="store_true",
        help="Prove mode: use policy-only proofs instead of composed policy+inference",
    )
    args = parser.parse_args()

    ensure_import_paths()
    adapter_options = AdapterOptions(
        limit=args.limit,
        tau2_domains=_parse_tau2_domains(args.tau2_domain),
        tau2_telecom_tasks=args.tau2_telecom_tasks,
        ulb_sample=args.ulb_sample,
        swe_shards=_parse_swe_shards(args.swe_shard),
        require_verify=args.require_verify,
        policy_mode=args.policy_mode,
    )
    report = run_benchmarks(
        suites=_parse_suites(args.suite),
        limit=args.limit,
        mode=args.mode,
        export_receipts=not args.no_export,
        with_identity=args.with_identity,
        require_verify=args.require_verify,
        tamper_analysis=args.tamper_analysis,
        shared_audit_db=args.shared_audit_db,
        inference_backend=args.inference_backend,
        model_provenance_hash=args.model_hash,
        prove_composed=False if args.no_prove_composed else None,
        attach_mock_tee=args.attach_mock_tee,
        adapter_options=adapter_options,
        results_dir=args.results_dir,
    )

    print(json.dumps({"suites": [s.to_dict() for s in report.suites]}, indent=2))
    total = sum(suite.total for suite in report.suites)
    passed = sum(suite.passed for suite in report.suites)
    print(f"\n{passed}/{total} cases passed. Results: {report.config['results_dir']}")
    if report.overview:
        overview = report.overview
        print(
            "Overview: "
            f"cases={overview['total_cases']} · "
            f"pass_rate={_format_rate(overview.get('pass_rate'))} · "
            f"export_rate={_format_rate(overview.get('export_rate'))} · "
            f"verify_valid_rate={_format_rate(overview.get('verify_valid_rate'))} · "
            f"audit_ok_rate={_format_rate(overview.get('audit_chain_ok_rate'))} · "
            f"p50={_format_rate(overview.get('p50_latency_ms'))}ms · "
            f"p95={_format_rate(overview.get('p95_latency_ms'))}ms"
        )
        print(
            "Counts: "
            f"verified={overview['verified_cases']} · "
            f"verify_valid={overview['verify_valid_cases']} · "
            f"policy_satisfied={overview['policy_satisfied_cases']} · "
            f"errored={overview['errored_cases']} · "
            f"skipped_suites={overview['suite_count_skipped']}"
        )

    fraud_summaries = [
        s
        for s in report.suites
        if s.suite in FRAUD_SUITES and s.label_mismatch_rate is not None
    ]
    if fraud_summaries:
        parts = [f"{s.suite}={s.label_mismatch_rate:.3f}" for s in fraud_summaries]
        print(f"Decision-branch coverage (label_mismatch, fixture sanity): {', '.join(parts)}")

    identity_suites = [s for s in report.suites if s.identity_metrics]
    if identity_suites:
        for summary in identity_suites:
            rates = summary.identity_metrics.get("rates", {})
            print(
                f"Identity ({summary.suite}): "
                f"spiffe={_format_rate(rates.get('spiffe_in_authority_rate'))} · "
                f"jwt_section={_format_rate(rates.get('identity_section_rate'))} · "
                f"offline_identity_ok={_format_rate(rates.get('identity_verify_ok_rate'))} · "
                f"live_validate={_format_rate(rates.get('live_validate_ok_rate'))}"
            )

    prove_suites = [s for s in report.suites if s.prove_metrics and s.prove_metrics.get("counts", {}).get("cases")]
    if prove_suites:
        backend = report.config.get("inference_backend")
        for summary in prove_suites:
            pm = summary.prove_metrics
            pb = pm.get("proof_bytes") or {}
            backend_label = f" backend={backend}" if backend else ""
            print(
                f"Prove ({summary.suite}){backend_label}: "
                f"cases={pm['counts']['cases']} · "
                f"avg_proof_bytes={pb.get('avg', 0):.0f} · "
                f"verify_valid={_format_rate((pm.get('rates') or {}).get('verify_valid_rate'))} · "
                f"avg_latency={((pm.get('latency_ms') or {}).get('avg') or 0):.1f}ms"
            )

    red_team = next((suite for suite in report.suites if suite.suite == "red_team"), None)
    if red_team and red_team.total:
        _print_red_team_metrics(red_team)
        control_cases = [
            case
            for case in report.cases
            if case.suite == "red_team" and case.metadata.get("red_team_category") == "control"
        ]
        baseline_cases = [
            case
            for case in report.cases
            if case.suite == "red_team" and case.metadata.get("red_team_category") == "baseline"
        ]
        if any(not case.ok for case in control_cases + baseline_cases):
            print("Red team REGRESSION: control or baseline mitigation failed.")
            sys.exit(1)

    tamper_summaries = [suite for suite in report.suites if suite.tamper_total_mutations]
    if tamper_summaries:
        parts = [
            (
                f"{suite.suite}=detect:{suite.tamper_detection_rate:.3f},"
                f"invalidate:{suite.tamper_invalidation_rate:.3f}"
            )
            for suite in tamper_summaries
            if suite.tamper_detection_rate is not None
            and suite.tamper_invalidation_rate is not None
        ]
        if parts:
            print(f"Tamper coverage: {', '.join(parts)}")
    if report.tamper_coverage:
        tc = report.tamper_coverage
        print(
            "Tamper overview: "
            f"cases={tc['cases_analyzed']} · "
            f"mutations={tc['total_mutations']} · "
            f"detect={_format_rate(tc.get('detection_rate'))} · "
            f"invalidate={_format_rate(tc.get('invalidation_rate'))}"
        )
        print(
            "Tamper baselines: "
            f"valid_cases={tc['cases_with_valid_baseline']} · "
            f"invalid_cases={tc['cases_with_invalid_baseline']} · "
            f"valid_detect={_format_rate(tc.get('valid_baseline_detection_rate'))} · "
            f"valid_invalidate={_format_rate(tc.get('valid_baseline_invalidation_rate'))} · "
            f"invalid_detect={_format_rate(tc.get('invalid_baseline_detection_rate'))}"
        )
        top = report.tamper_coverage.get("top_survivors") or []
        if top:
            preview = ", ".join(
                f"{item['path']} ({item['count']})"
                for item in top[:8]
            )
            print(f"Tamper survivors: {preview}")
        classified = report.tamper_coverage.get("survivors_by_classification") or {}
        counts = report.tamper_coverage.get("survivor_classification_counts") or {}
        if counts:
            print(
                "Tamper survivor classes: "
                + ", ".join(f"{name}={count}" for name, count in sorted(counts.items()))
            )
        security = classified.get("security_relevant") or []
        informational = classified.get("expected_informational") or []
        if security:
            preview = ", ".join(
                f"{item['path']} ({item['count']})"
                for item in security[:5]
            )
            print(f"Security-relevant survivors: {preview}")
        if informational:
            preview = ", ".join(
                f"{item['path']} ({item['count']})"
                for item in informational[:5]
            )
            print(f"Expected informational survivors: {preview}")

    if passed < total and red_team is None:
        sys.exit(1)


if __name__ == "__main__":
    main()
