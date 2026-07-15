#!/usr/bin/env bash
# Verify a clean install of standalone Clay Seal Receipts from a pinned git tag.
set -euo pipefail

TAG="${AGENTAUTH_TAG:-v0.5.2}"
PY="${PYTHON:-python3}"
REPO="${AGENTAUTH_RECEIPTS_REPO:-https://github.com/clayseal/clayseal-receipts.git}"

"$PY" - <<'PY'
import sys

if sys.version_info < (3, 10):
    raise SystemExit(
        "layer_install_smoke.sh requires Python >= 3.10; "
        f"got {sys.version.split()[0]}. Set PYTHON=/path/to/python3.10+."
    )
PY

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Creating venv in $TMP"
"$PY" -m venv "$TMP/venv"
# shellcheck disable=SC1091
source "$TMP/venv/bin/activate"
pip install -q --upgrade pip

echo "==> Installing clayseal-receipts @ $TAG"
pip install -q "clayseal-receipts[server,verifier] @ git+${REPO}@${TAG}"

echo "==> Import and receipt smoke"
python - <<'PY'
import agentauth.core
import agentauth.receipts as r

policy = r.Policy.from_dict({
    "version": 1,
    "name": "smoke",
    "tier": "structural",
    "capability": "operator_attested",
})
wrapper = r.AgentWrapper(
    lambda item: {"decision": "approve", "fraud_score": 0.1},
    policy,
    mode="shadow",
    audit_db=":memory:",
)
result = wrapper.run({"transaction_id": "smoke-1", "amount": 1.0})
bundle = r.build_receipt_bundle(result, certificate=wrapper.certificate)
assert isinstance(r.verify_receipt_bundle(bundle), dict)
print("standalone receipts smoke passed")
PY

echo ""
echo "Install smoke passed (tag=$TAG)."
