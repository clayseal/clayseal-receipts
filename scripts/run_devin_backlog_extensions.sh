#!/usr/bin/env bash
# Run backlog extension experiments (need Devin CLI + rate-limit budget).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SLEEP="${DEVIN_SLEEP_SECS:-60}"
_run() {
  bash "$@"
  if [[ -n "${DEVIN_SLEEP_SECS:-}" ]]; then
    sleep "$SLEEP"
  fi
}
echo "=== C1b Unicode smuggling ==="
_run "$ROOT/scripts/run_devin_c1b_unicode.sh"
echo ""
echo "=== G1 slow-drip (2 PRs) ==="
_run "$ROOT/scripts/run_devin_g1_slowdrip.sh"
echo ""
echo "=== L1 cross-agent infection (simulated) ==="
_run "$ROOT/scripts/run_devin_l1_infection.sh"
echo ""
if [[ -n "${NGROK_MCP_URL:-}" ]]; then
  echo "=== C7b unprompted MCP ==="
  bash "$ROOT/scripts/run_devin_c7b_unprompted.sh"
else
  echo "=== C7b skipped (set NGROK_MCP_URL and run mcp-lab) ==="
fi
