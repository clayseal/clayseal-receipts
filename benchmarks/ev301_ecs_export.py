#!/usr/bin/env python3
"""EV-301: transform exported receipt bundles into ECS JSONL + mapping report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

BENCHMARKS_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCHMARKS_ROOT))

from harness.paths import ensure_import_paths  # noqa: E402


def _collect_receipt_paths(results_dir: Path) -> list[Path]:
    paths: list[Path] = []
    for path in sorted(results_dir.glob("*.json")):
        if path.name in {"summary.json", "rollup.json"}:
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


def export_ecs_from_results(
    results_dir: Path,
    *,
    profiles: list[str] | None = None,
) -> dict:
    ensure_import_paths()
    from agentauth.receipts.compliance import export_compliance_mapped, export_siem_ecs

    receipt_paths = _collect_receipt_paths(results_dir)
    events: list[dict] = []
    crosswalk_reports: dict[str, list[dict]] = {}
    field_presence: dict[str, int] = {}
    live_valid = 0

    for path in receipt_paths:
        bundle = json.loads(path.read_text())
        event = export_siem_ecs(bundle)
        events.append(event)
        for key in event.keys():
            if event.get(key) is not None:
                field_presence[key] = field_presence.get(key, 0) + 1
        ar = event.get("agent_receipts") or {}
        for key, value in ar.items():
            if value is not None:
                field_presence[f"agent_receipts.{key}"] = (
                    field_presence.get(f"agent_receipts.{key}", 0) + 1
                )
        if ar.get("verification_valid"):
            live_valid += 1
        if profiles:
            for profile in profiles:
                mapped = export_compliance_mapped(bundle, profile)
                crosswalk_reports.setdefault(profile, []).append(
                    {
                        "receipt": path.name,
                        "completeness": mapped.get("completeness"),
                        "verification": mapped.get("verification"),
                    }
                )

    report = {
        "receipt_count": len(receipt_paths),
        "ecs_event_count": len(events),
        "live_verification_valid_rate": live_valid / len(events) if events else 0.0,
        "field_presence": field_presence,
        "crosswalk": crosswalk_reports,
    }
    return {"events": events, "report": report}


def main() -> None:
    parser = argparse.ArgumentParser(description="EV-301 ECS export from benchmark receipts")
    parser.add_argument(
        "--results-dir",
        type=Path,
        required=True,
        help="Directory containing exported receipt JSON files",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory (default: results-dir)",
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        help="Optional compliance profile(s) to embed crosswalk snippets (soc2, eu-ai-act, iso27001)",
    )
    args = parser.parse_args()

    out_dir = args.out_dir or args.results_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = export_ecs_from_results(args.results_dir, profiles=args.profile or None)

    events_path = out_dir / "ecs_events.jsonl"
    with events_path.open("w") as handle:
        for event in payload["events"]:
            handle.write(json.dumps(event) + "\n")

    report_path = out_dir / "ecs_mapping_report.json"
    report_path.write_text(json.dumps(payload["report"], indent=2) + "\n")
    print(json.dumps(payload["report"], indent=2))
    print(f"\nWrote {events_path} ({len(payload['events'])} events) and {report_path}")


if __name__ == "__main__":
    main()
