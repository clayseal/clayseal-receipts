#!/usr/bin/env bash
# Deploy SPIRE + sample agent workloads into a Kubernetes cluster.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
K8S_DIR="$ROOT/k8s"
BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

detect_cluster_name() {
  if [[ -n "${AGENTAUTH_CLUSTER_NAME:-}" ]]; then
    echo "$AGENTAUTH_CLUSTER_NAME"
    return
  fi
  kubectl config view --minify -o jsonpath='{.clusters[0].name}'
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required command: $1" >&2
    if [[ "$1" == "kubectl" ]]; then
      echo "Install with: brew install kubectl kind" >&2
      echo "Then create a local cluster: bash identity/scripts/setup-cluster.sh" >&2
    fi
    exit 1
  }
}

render_manifests() {
  local src="$1" dst="$2"
  mkdir -p "$dst"
  cp -R "$src/." "$dst/"
  find "$dst" -name '*.yaml' -print0 \
    | while IFS= read -r -d '' f; do
        sed "s/__CLUSTER_NAME__/${CLUSTER_NAME}/g" "$f" > "${f}.tmp" && mv "${f}.tmp" "$f"
      done
}

require_cmd kubectl

if ! kubectl cluster-info >/dev/null 2>&1; then
  echo "No reachable Kubernetes cluster in the current kubectl context." >&2
  echo "Start Docker Desktop, then run:" >&2
  echo "  bash identity/scripts/setup-cluster.sh" >&2
  echo "  bash identity/scripts/install.sh" >&2
  exit 1
fi

CLUSTER_NAME="$(detect_cluster_name)"
export CLUSTER_NAME
echo "Using Kubernetes cluster name: $CLUSTER_NAME"
echo "(override with AGENTAUTH_CLUSTER_NAME if attestation fails)"

SPIRE_BUILD="$BUILD_DIR/spire"
AGENTS_BUILD="$BUILD_DIR/agents"
render_manifests "$K8S_DIR/spire" "$SPIRE_BUILD"
render_manifests "$K8S_DIR/agents" "$AGENTS_BUILD"

echo "==> Applying SPIRE"
kubectl apply -k "$SPIRE_BUILD"

echo "==> Waiting for SPIRE Server and Agent"
kubectl rollout status statefulset/spire-server -n spire --timeout=180s
kubectl rollout status daemonset/spire-agent -n spire --timeout=180s

echo "==> Registering workload entries (must exist before agent pods start)"
bash "$ROOT/scripts/register-entries.sh"

echo "==> Applying agent workloads"
kubectl apply -k "$AGENTS_BUILD"

echo "==> Waiting for agent pods"
kubectl rollout status deployment/finance-agent -n customer-acme --timeout=120s
kubectl rollout status deployment/research-agent -n customer-acme --timeout=120s
kubectl rollout status deployment/rogue-agent -n customer-acme --timeout=120s

# Give watch a moment to print the first SVID update.
sleep 5

echo
echo "Install complete. Run: bash identity/scripts/demo.sh"
