#!/usr/bin/env bash
# Evaluate the PR diff with the in-repo AgentAuth gate (hardened policy).
set -euo pipefail

ROOT="${GITHUB_WORKSPACE:-$(cd "$(dirname "$0")/../.." && pwd)}"
CONFIG="$ROOT/.agentauth/demo-issue.json"

if [[ ! -f "$CONFIG" ]]; then
  echo "missing $CONFIG" >&2
  exit 1
fi

python3 - <<'PY' "$CONFIG"
import json, sys
cfg = json.loads(open(sys.argv[1], encoding="utf-8").read())
for key in ("github_issue", "mandate", "issue_live"):
    if key not in cfg:
        raise SystemExit(f"demo-issue.json missing {key!r}")
PY

MANDATE="$ROOT/$(python3 -c "import json; print(json.load(open('$CONFIG'))['mandate'])")"
ISSUE_LIVE="$ROOT/$(python3 -c "import json; print(json.load(open('$CONFIG'))['issue_live'])")"
BASE_SHA="${BASE_SHA:-$(git merge-base "origin/${GITHUB_BASE_REF}" HEAD)}"
HEAD_SHA="${HEAD_SHA:-$(git rev-parse HEAD)}"
RECEIPT_DIR="$ROOT/.agentauth/receipts"
mkdir -p "$RECEIPT_DIR"
RECEIPT="$RECEIPT_DIR/pr-${GITHUB_RUN_ID:-local}.json"

export PYTHONPATH="$ROOT/_vendor${PYTHONPATH:+:$PYTHONPATH}"

python3 "$ROOT/.agentauth/agentauth_gate.py" evaluate \
  --repo "$ROOT" \
  --base "$BASE_SHA" \
  --head "$HEAD_SHA" \
  --authorization "$MANDATE" \
  --policy "$ROOT/.agentauth/policies/devin-pr-gate.hardened.policy.json" \
  --issue "$ISSUE_LIVE" \
  --receipt "$RECEIPT" \
  --key "$ROOT/.agentauth/keys/gate.ed25519.pem" \
  --github-actor "${PR_ACTOR:-devin-ai-integration[bot]}"

OUTCOME="$(python3 -c "import json; print(json.load(open('$RECEIPT'))['decision']['outcome'])")"
echo "AgentAuth outcome: $OUTCOME"
python3 -m json.tool "$RECEIPT"

case "$OUTCOME" in
  deny*)
    echo "::error::AgentAuth gate denied this PR ($OUTCOME)"
    exit 1
    ;;
esac
