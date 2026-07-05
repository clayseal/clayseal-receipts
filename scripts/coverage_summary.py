#!/usr/bin/env python3
"""Summarize a coverage.json into a human-readable "blind spots" report.

Reads the JSON report produced by `coverage json` (config in pyproject.toml
writes it to ./coverage.json) and emits a Markdown summary that surfaces the
*least* tested modules — the blind spots — rather than a single headline number.

Usage:
    python scripts/coverage_summary.py [coverage.json] [--top N] [--threshold PCT]

Behavior:
    - Prints the report to stdout.
    - If GITHUB_STEP_SUMMARY is set (GitHub Actions), appends the report there
      too so it shows up on the workflow run page and in PRs.
    - Exit code is always 0; this is a reporting tool, not a gate. Enforcement
      lives in CI via `coverage report --fail-under` / diff-cover.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def _bar(pct: float, width: int = 20) -> str:
    filled = round(pct / 100 * width)
    return "█" * filled + "░" * (width - filled)


def build_report(data: dict, top: int, threshold: float) -> str:
    totals = data.get("totals", {})
    files = data.get("files", {})

    overall = totals.get("percent_covered", 0.0)
    n_stmts = totals.get("num_statements", 0)
    n_missing = totals.get("missing_lines", 0)
    n_branches = totals.get("num_branches", 0)
    n_missing_branches = totals.get("missing_branches", 0)

    lines: list[str] = []
    lines.append("## 🧪 Coverage & blind spots")
    lines.append("")
    lines.append(f"**Overall: {overall:.1f}%** `{_bar(overall)}`")
    lines.append("")
    lines.append(f"- Statements: {n_stmts - n_missing}/{n_stmts} covered "
                 f"({n_missing} missing)")
    if n_branches:
        covered_branches = n_branches - n_missing_branches
        lines.append(f"- Branches: {covered_branches}/{n_branches} covered "
                     f"({n_missing_branches} missing)")
    lines.append("")

    # Rank files by coverage ascending — the worst-covered modules first.
    ranked = sorted(
        (
            (path, info.get("summary", {}))
            for path, info in files.items()
        ),
        key=lambda item: (
            item[1].get("percent_covered", 0.0),
            -item[1].get("missing_lines", 0),
        ),
    )

    below = [(p, s) for p, s in ranked
             if s.get("percent_covered", 0.0) < threshold and s.get("num_statements", 0)]

    lines.append(f"### Blind spots — least-covered modules (top {top})")
    lines.append("")
    lines.append("| Module | Coverage | Missing lines | Missing branches |")
    lines.append("| --- | ---: | ---: | ---: |")
    shown = [item for item in ranked if item[1].get("num_statements", 0)][:top]
    for path, summary in shown:
        pct = summary.get("percent_covered", 0.0)
        miss = summary.get("missing_lines", 0)
        miss_br = summary.get("missing_branches", 0)
        flag = " ⚠️" if pct < threshold else ""
        lines.append(f"| `{path}` | {pct:.1f}%{flag} | {miss} | {miss_br} |")
    lines.append("")

    if below:
        lines.append(
            f"**{len(below)} module(s) below the {threshold:.0f}% threshold.** "
            "These carry the most untested risk — prioritize tests here."
        )
    else:
        lines.append(f"✅ All modules at or above the {threshold:.0f}% threshold.")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default="coverage.json",
                        help="Path to coverage.json (default: ./coverage.json)")
    parser.add_argument("--top", type=int, default=15,
                        help="How many least-covered modules to list (default: 15)")
    parser.add_argument("--threshold", type=float, default=70.0,
                        help="Flag modules below this percent (default: 70)")
    args = parser.parse_args(argv)

    coverage_path = Path(args.path)
    if not coverage_path.exists():
        print(f"coverage_summary: {coverage_path} not found; "
              "run `coverage json` first.", file=sys.stderr)
        return 0

    data = json.loads(coverage_path.read_text())
    report = build_report(data, top=args.top, threshold=args.threshold)

    print(report)

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write(report + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
