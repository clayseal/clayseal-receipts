#!/usr/bin/env bash
# Run arctl with a supported Python (3.10–3.13). Avoids stale global arctl on 3.14.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

pick_python() {
  local candidate
  for candidate in \
    "${AGENTAUTH_PYTHON:-}" \
    python3.11 python3.12 python3.13 python3.10 \
    /opt/homebrew/bin/python3.11 \
    /opt/homebrew/bin/python3.12 \
    /opt/homebrew/bin/python3.13; do
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
    /opt/homebrew/bin/python3.11 \
    /opt/homebrew/bin/python3.12 \
    /opt/homebrew/bin/python3.13; do
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
  echo "error: need Python 3.10–3.13 (AGENTAUTH_PYTHON to override). python3 is too new or missing deps." >&2
  echo "  python3.11 -m pip install -e \"$ROOT/.[dev]\"" >&2
  exit 1
}

if ! "$PY" -c "import agentauth.receipts.cli" 2>/dev/null; then
  echo "error: agentauth not installed for $PY" >&2
  echo "  $PY -m pip install -e \"$ROOT/.[dev]\"" >&2
  exit 1
fi

exec "$PY" -m agentauth.receipts.cli "$@"
