#!/usr/bin/env bash
# Run all Devin red-team gate harnesses (issue #1–#14 + advanced I/J/G/M).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PY="${PYTHON:-python3.11}"

echo "=== Issue attacks (#1–#14) ==="
"$PY" scripts/evaluate_devin_issue_attacks.py

echo ""
echo "=== Advanced attacks (I/J/G/M) ==="
"$PY" scripts/evaluate_devin_advanced_attacks.py

echo ""
echo "=== Compromise scenarios (C00–C13 matrix) ==="
"$PY" scripts/evaluate_devin_compromise_scenarios.py 2>&1 | tail -5
