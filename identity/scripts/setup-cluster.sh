#!/usr/bin/env bash
# Create a local kind cluster configured for SPIRE k8s_psat attestation.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLUSTER_NAME="${AGENTAUTH_KIND_CLUSTER:-agentauth-spire}"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    exit 1
  }
}

require_cmd kind
require_cmd docker
require_cmd kubectl

if ! docker info >/dev/null 2>&1; then
  echo "Docker is not running." >&2
  echo "Start Docker Desktop, then re-run:" >&2
  echo "  bash identity/scripts/setup-cluster.sh" >&2
  exit 1
fi

if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "kind cluster '$CLUSTER_NAME' already exists."
else
  echo "==> Creating kind cluster '$CLUSTER_NAME' (SPIRE-compatible API server flags)"
  kind create cluster --name "$CLUSTER_NAME" --config "$ROOT/k8s/kind-config.yaml"
fi

kubectl cluster-info --context "kind-${CLUSTER_NAME}"
echo
echo "Cluster ready. Install SPIRE prototype with:"
echo "  bash identity/scripts/install.sh"
