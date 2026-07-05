#!/usr/bin/env bash
# K1: Tool-description poisoning / line-jumping class (local demo).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="${DEVIN_RESULTS_DIR:-$ROOT/artifacts/devin-experiments/k1-tool-desc-poison}"
mkdir -p "$RESULTS_DIR"

SUMMARY="$RESULTS_DIR/k1-tool-desc-poison.summary.json"

python3.11 "$ROOT/examples/k1_mcp_tool_description_poison_demo.py" > "$SUMMARY"
echo "Wrote $SUMMARY"

