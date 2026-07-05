#!/usr/bin/env bash
set -euo pipefail
kubectl delete -k "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/k8s" --ignore-not-found
kubectl delete clusterrole spire-server-trust-role spire-agent-cluster-role --ignore-not-found
kubectl delete clusterrolebinding spire-server-trust-role-binding spire-agent-cluster-role-binding --ignore-not-found
echo "Torn down SPIRE prototype resources."
