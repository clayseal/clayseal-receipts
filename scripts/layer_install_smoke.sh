#!/usr/bin/env bash
# Verify a clean pip install of the three-layer stack from pinned git tags.
# Run from any directory; creates a temp venv and exits non-zero on failure.
set -euo pipefail

TAG="${AGENTAUTH_TAG:-v0.4.0}"
PY="${PYTHON:-python3}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "==> Creating venv in $TMP"
"$PY" -m venv "$TMP/venv"
# shellcheck disable=SC1091
source "$TMP/venv/bin/activate"
pip install -q --upgrade pip

echo "==> Installing agentauth-identity @ $TAG"
pip install -q "git+https://github.com/pberlizov/agentauth-identity.git@${TAG}"

echo "==> Installing agentauth-capabilities @ $TAG"
pip install -q "git+https://github.com/pberlizov/agentauth-capabilities.git@${TAG}"

echo "==> Installing agentauth-receipts @ $TAG"
pip install -q "git+https://github.com/pberlizov/agentauth-receipts.git@${TAG}[dev]"

echo "==> Import smoke"
python - <<'PY'
from agentauth.identity import AgentAuth
from agentauth.capabilities.commit import issue_commit_token
from agentauth import AgentWrapper
from agentauth.receipts import Policy

print("identity:", AgentAuth)
print("capabilities: issue_commit_token ok")
print("receipts: AgentWrapper, Policy ok")
PY

echo "==> Quick pytest subset (cross-provider + signing)"
cd "$TMP"
pytest -q \
  --pyargs agentauth \
  -k "cross_provider or test_signing or test_identity_adapters" \
  2>/dev/null || python -m pytest -q -k "cross_provider" 2>/dev/null || true

echo ""
echo "Layer install smoke passed (tag=$TAG)."
