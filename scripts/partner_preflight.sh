#!/usr/bin/env bash
# Deployment gate: preflight + smoke (run before handing to a design partner).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CONFIG="${1:-config/partner.yaml}"
STRICT="${PARTNER_PREFLIGHT_STRICT:-0}"

if [[ ! -f "$CONFIG" ]]; then
  echo "Missing $CONFIG"
  exit 1
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export AGENT_RECEIPTS_CLI="${AGENT_RECEIPTS_CLI:-$CARGO_TARGET_DIR/release/agent-receipts}"
export PYTHONPATH="${PYTHONPATH:-$ROOT}"

echo "==> Preflight ($CONFIG)"
if [[ "$STRICT" == "1" ]]; then
  arctl preflight "$CONFIG" --strict
else
  arctl preflight "$CONFIG"
fi

if [[ -x "$AGENT_RECEIPTS_CLI" ]]; then
  echo "==> Prover diagnostics"
  arctl doctor --require-prover || true
fi

echo "==> Unit tests"
pytest python/tests -q

echo "==> Pilot run"
python3 examples/partner_pilot.py

RECEIPT="$(ls -t receipts/*.json 2>/dev/null | head -1)"
if [[ -n "${RECEIPT:-}" ]]; then
  MODE="$(python3 - "$CONFIG" <<'PY'
from agentauth.receipts.partner_config import PartnerConfig
import sys

print(PartnerConfig.from_yaml(sys.argv[1]).mode)
PY
)"

  if [[ "$MODE" == "shadow" ]]; then
    echo "==> Verify receipt (shadow mode; expect non-cryptographic verification)"
    python3 - "$RECEIPT" <<'PY'
from agentauth.receipts.export import load_receipt_bundle, verify_receipt_bundle
import json
import sys

result = verify_receipt_bundle(load_receipt_bundle(sys.argv[1]))
print(json.dumps(result, indent=2))
reasons = " ".join(result.get("reasons", []))
if result.get("valid"):
    raise SystemExit("shadow-mode receipt unexpectedly verified as cryptographic")
if "shadow mode" not in reasons:
    raise SystemExit("shadow-mode receipt failed for an unexpected reason")
PY
  else
    echo "==> Verify receipt"
    arctl verify-bundle "$RECEIPT"
  fi
fi

echo ""
echo "Partner preflight passed."
