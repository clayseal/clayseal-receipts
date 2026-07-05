#!/usr/bin/env bash
# Design partner smoke test: bootstrap (if needed), unit tests, pilot + verify.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
export AGENT_RECEIPTS_CLI="${AGENT_RECEIPTS_CLI:-$CARGO_TARGET_DIR/release/agent-receipts}"
export PYTHONPATH="${PYTHONPATH:-$ROOT}"

if [[ ! -x "$AGENT_RECEIPTS_CLI" ]]; then
  echo "CLI missing; running bootstrap..."
  bash scripts/bootstrap.sh
fi

if [[ ! -f config/partner.yaml ]]; then
  cp config/partner.example.yaml config/partner.yaml
fi

bash scripts/partner_preflight.sh config/partner.yaml

RECEIPT="$(ls -t receipts/*.json 2>/dev/null | head -1)"
if [[ -z "${RECEIPT:-}" ]]; then
  echo "No receipt exported"
  exit 1
fi

echo "==> Verify exported receipt"
MODE="$(python3 - config/partner.yaml <<'PY'
from agentauth.receipts.partner_config import PartnerConfig
import sys

print(PartnerConfig.from_yaml(sys.argv[1]).mode)
PY
)"

if [[ "$MODE" == "shadow" ]]; then
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
  arctl verify-bundle "$RECEIPT"
fi

echo ""
echo "Partner smoke passed."
