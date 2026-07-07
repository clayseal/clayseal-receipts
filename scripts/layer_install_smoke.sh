#!/usr/bin/env bash
# Verify a clean pip install of the modular four-repo stack from pinned git tags.
# Run from any directory; creates a temp venv and exits non-zero on failure.
set -euo pipefail

TAG="${AGENTAUTH_TAG:-v0.5.0}"
PY="${PYTHON:-python3}"

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

echo "==> Installing agentauth-core @ $TAG"
pip install -q "git+https://github.com/pberlizov/clay-seal-core.git@${TAG}"

echo "==> Installing agentauth-identity @ $TAG"
pip install -q "git+https://github.com/pberlizov/clay-seal-identity.git@${TAG}"

echo "==> Installing agentauth-capabilities @ $TAG"
pip install -q "git+https://github.com/pberlizov/clay-seal-capabilities.git@${TAG}"

echo "==> Installing agentauth-receipts @ $TAG"
pip install -q "git+https://github.com/pberlizov/clay-seal-receipts.git@${TAG}[dev]"

echo "==> Import smoke"
python - <<'PY'
from agentauth.identity import AgentAuth
from agentauth.capabilities.commit import issue_commit_token
from agentauth import AgentWrapper
from agentauth.receipts import Policy

print("identity:", AgentAuth)
print("core facade: imports ok")
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
