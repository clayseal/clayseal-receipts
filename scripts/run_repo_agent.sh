#!/usr/bin/env bash
# Live split-terminal: same arctl command; right pane adds pip install + --receipts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ARCTL="$ROOT/scripts/arctl.sh"

pick_python() {
  local candidate
  for candidate in \
    "${AGENTAUTH_PYTHON:-}" \
    python3.11 python3.12 python3.13 python3.10 \
    /opt/homebrew/bin/python3.11; do
    [[ -n "$candidate" && -x "$(command -v "$candidate" 2>/dev/null || true)" ]] || continue
    if "$candidate" - <<'PY' >/dev/null 2>&1
import sys
if not (3, 10) <= sys.version_info[:2] < (3, 14):
    raise SystemExit(1)
import agentauth.receipts.cli  # noqa: F401
PY
    then
      echo "$candidate"
      return 0
    fi
  done
  for candidate in \
    "${AGENTAUTH_PYTHON:-}" \
    python3.11 python3.12 python3.13 python3.10 \
    /opt/homebrew/bin/python3.11; do
    [[ -n "$candidate" && -x "$(command -v "$candidate" 2>/dev/null || true)" ]] || continue
    if "$candidate" - <<'PY' >/dev/null 2>&1
import sys
if not (3, 10) <= sys.version_info[:2] < (3, 14):
    raise SystemExit(1)
PY
    then
      echo "$candidate"
      return 0
    fi
  done
  return 1
}

SECURED=0
for arg in "$@"; do
  if [[ "$arg" == "--receipts" || "$arg" == "--secured" ]]; then
    SECURED=1
  fi
done

PY="$(pick_python)" || {
  echo "error: need Python 3.10–3.13" >&2
  exit 1
}

if [[ "$SECURED" == "1" ]]; then
  echo '$ pip install -e ".[dev]"'
  "$PY" -m pip install -e ".[dev]" -q
  echo '$ arctl run-agent --repo examples/poisoned-repo --receipts'
  exec "$ARCTL" run-agent --repo examples/poisoned-repo --receipts
else
  echo '$ arctl run-agent --repo examples/poisoned-repo'
  exec "$ARCTL" run-agent --repo examples/poisoned-repo
fi
