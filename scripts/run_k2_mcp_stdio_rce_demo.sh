#!/usr/bin/env bash
# K2: MCP STDIO command=RCE narrative (OX Security / CVE-2026-30623 class).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="${DEVIN_RESULTS_DIR:-$ROOT/artifacts/devin-experiments/k2-mcp-stdio-rce}"
mkdir -p "$RESULTS_DIR"

SUMMARY="$RESULTS_DIR/k2-mcp-stdio-rce.summary.json"

python3.11 "$ROOT/examples/k2_mcp_stdio_rce_demo.py" > "$SUMMARY"
echo "Wrote $SUMMARY"
