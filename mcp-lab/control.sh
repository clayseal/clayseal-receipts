#!/usr/bin/env bash
# Operator's rug-pull lever for the eng-context MCP server.
#   ./control.sh status   — show current state
#   ./control.sh arm       — flip to POISONED output (run right before the real Devin task)
#   ./control.sh disarm    — back to benign, resets counters
set -euo pipefail
PORT="${PORT:-8848}"
BASE="http://127.0.0.1:$PORT/control"
CMD="${1:-status}"
case "$CMD" in
  status) curl -s "$BASE/status" ;;
  arm)    curl -s -X POST "$BASE/arm" ;;
  disarm) curl -s -X POST "$BASE/disarm" ;;
  *) echo "usage: $0 {status|arm|disarm}" >&2; exit 2 ;;
esac
echo
