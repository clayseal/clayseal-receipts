#!/usr/bin/env bash
# Register SPIRE entries that map Kubernetes workload selectors to AgentAuth
# SPIFFE IDs. Run after SPIRE Server is ready (see install.sh).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TRUST_DOMAIN="${AGENTAUTH_TRUST_DOMAIN:-agentauth.io}"
CUSTOMER="${AGENTAUTH_CUSTOMER:-acme}"
NS_AGENTS="customer-${CUSTOMER}"
SPIRE_NS="spire"

spire_exec() {
  kubectl exec -n "$SPIRE_NS" spire-server-0 -- /opt/spire/bin/spire-server "$@"
}

AGENT_PARENT="spiffe://${TRUST_DOMAIN}/ns/spire/sa/spire-agent"

echo "==> Registering SPIRE node attestation entry"
spire_exec entry create \
  -spiffeID "spiffe://${TRUST_DOMAIN}/ns/spire/sa/spire-agent" \
  -selector "k8s_psat:cluster:${CLUSTER_NAME:?set CLUSTER_NAME}" \
  -selector "k8s_psat:agent_ns:spire" \
  -selector "k8s_psat:agent_sa:spire-agent" \
  -node \
  || echo "(node entry may already exist)"

echo "==> Registering finance agent (approved workload)"
spire_exec entry create \
  -spiffeID "spiffe://${TRUST_DOMAIN}/customer/${CUSTOMER}/agent/finance" \
  -parentID "$AGENT_PARENT" \
  -selector "k8s:ns:${NS_AGENTS}" \
  -selector "k8s:sa:finance-agent" \
  -selector "k8s:pod-label:agentauth.io/agent-type:finance" \
  || echo "(finance entry may already exist)"

echo "==> Registering research agent (approved workload)"
spire_exec entry create \
  -spiffeID "spiffe://${TRUST_DOMAIN}/customer/${CUSTOMER}/agent/research" \
  -parentID "$AGENT_PARENT" \
  -selector "k8s:ns:${NS_AGENTS}" \
  -selector "k8s:sa:research-agent" \
  -selector "k8s:pod-label:agentauth.io/agent-type:research" \
  || echo "(research entry may already exist)"

echo
echo "Registered SPIFFE IDs:"
echo "  spiffe://${TRUST_DOMAIN}/customer/${CUSTOMER}/agent/finance"
echo "  spiffe://${TRUST_DOMAIN}/customer/${CUSTOMER}/agent/research"
echo
spire_exec entry show | grep -E 'SPIFFE ID|Selector' || true
