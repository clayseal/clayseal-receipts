#!/usr/bin/env bash
# Comparison UI: API + dashboard (step-through rehearsal).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

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
import agentauth.receipts.repo_agent.server  # noqa: F401
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

PY="$(pick_python)" || {
  echo "error: need Python 3.10–3.13" >&2
  exit 1
}

if ! "$PY" -c "import agentauth.receipts.repo_agent.server" 2>/dev/null; then
  echo "Install package first: $PY -m pip install -e '.[dev]'"
  exit 1
fi

echo "==> Agent run API http://127.0.0.1:8790"
"$PY" -m agentauth.receipts.repo_agent.server &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT

sleep 1
curl -sf http://127.0.0.1:8790/health >/dev/null

echo "==> Dashboard http://localhost:5173/agent-run"
cd dashboard
if [[ ! -d node_modules ]]; then npm install; fi
npm run dev
