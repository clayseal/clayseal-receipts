#!/usr/bin/env python3
"""EV-302: automated compliance crosswalk coverage over receipt bundles."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parent
REPO_ROOT = BENCHMARKS_ROOT.parent
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.paths import ensure_import_paths  # noqa: E402

DEFAULT_PROFILES = ("soc2", "eu-ai-act", "iso27001")


def _collect_receipt_paths(results_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(results_dir.glob("*.json")):
        if path.name in {"summary.json", "rollup.json", "ecs_mapping_report.json", "crosswalk_coverage.json"}:
            continue
        if path.name.endswith(".tamper.json"):
            continue
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if "execution_proof" in payload:
            paths.append(path)
    return paths


def crosswalk_coverage(
    results_dir: Path,
    *,
    profiles: list[str],
) -> dict:
    ensure_import_paths()
    from agentauth.receipts.compliance import export_compliance_mapped

    receipt_paths = _collect_receipt_paths(results_dir)
    profile_rollups: dict[str, dict] = {}

    for profile in profiles:
        field_hits: dict[str, int] = {}
        control_hits: dict[str, int] = {}
        complete_count = 0
        crypto_verified = 0
        per_receipt: list[dict] = []

        for path in receipt_paths:
            bundle = json.loads(path.read_text())
            mapped = export_compliance_mapped(bundle, profile)
            completeness = mapped.get("completeness") or {}
            if completeness.get("complete"):
                complete_count += 1
            if completeness.get("cryptographically_verified"):
                crypto_verified += 1
            for key, spec in (mapped.get("fields") or {}).items():
                if spec.get("present"):
                    field_hits[key] = field_hits.get(key, 0) + 1
            for control_id, fields in (mapped.get("controls") or {}).items():
                if all(item.get("present") for item in fields.values()):
                    control_hits[control_id] = control_hits.get(control_id, 0) + 1
            per_receipt.append(
                {
                    "receipt": path.name,
                    "complete": completeness.get("complete"),
                    "missing_fields": completeness.get("missing_fields", []),
                    "cryptographically_verified": completeness.get(
                        "cryptographically_verified"
                    ),
                }
            )

        total = len(receipt_paths)
        required_fields = len(field_hits) or 1
        profile_rollups[profile] = {
            "receipt_count": total,
            "complete_count": complete_count,
            "complete_rate": complete_count / total if total else 0.0,
            "cryptographically_verified_count": crypto_verified,
            "cryptographically_verified_rate": crypto_verified / total if total else 0.0,
            "field_presence_rate": {
                key: hits / total for key, hits in sorted(field_hits.items())
            },
            "control_coverage_rate": {
                key: hits / total for key, hits in sorted(control_hits.items())
            },
            "receipts": per_receipt,
        }

    return {
        "results_dir": str(results_dir),
        "profiles": profile_rollups,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="EV-302 compliance crosswalk coverage")
    parser.add_argument(
        "--results-dir",
        type=Path,
        required=True,
        help="Directory containing exported receipt JSON files",
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help=f"Compliance profile (default: {', '.join(DEFAULT_PROFILES)})",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=None,
        help="Exit 1 if any profile complete_rate falls below this threshold (0-1)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Write crosswalk_coverage.json (default: results-dir/crosswalk_coverage.json)",
    )
    args = parser.parse_args()

    profiles = args.profile or list(DEFAULT_PROFILES)
    report = crosswalk_coverage(args.results_dir, profiles=profiles)
    out_path = args.out or (args.results_dir / "crosswalk_coverage.json")
    out_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print(f"\nWrote {out_path}")

    if args.fail_under is not None:
        for profile, rollup in report["profiles"].items():
            rate = rollup.get("complete_rate", 0.0)
            if rate < args.fail_under:
                raise SystemExit(
                    f"Profile {profile} complete_rate {rate:.3f} < {args.fail_under}"
                )


if __name__ == "__main__":
    main()
