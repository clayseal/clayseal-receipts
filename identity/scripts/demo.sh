#!/usr/bin/env bash
# Show approved vs denied SVID issuance for AgentAuth agent types.
set -euo pipefail

NS="customer-acme"

pod_for() {
  kubectl get pods -n "$NS" -l "app=$1" -o jsonpath='{.items[0].metadata.name}'
}

section() {
  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "$1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

has_spiffe_id() {
  kubectl logs -n "$NS" "$1" 2>/dev/null | grep -q 'spiffe://agentauth.io/customer/acme/agent/'
}

section "1. Finance agent — attestation succeeds"
FINANCE_POD="$(pod_for finance-agent)"
kubectl logs -n "$NS" "$FINANCE_POD" --tail=30
if has_spiffe_id "$FINANCE_POD"; then
  echo
  echo "Expected SPIFFE ID: spiffe://agentauth.io/customer/acme/agent/finance"
else
  echo
  echo "(SVID not yet in logs — wait a few seconds and re-run demo.sh)"
fi

section "2. Research agent — attestation succeeds"
RESEARCH_POD="$(pod_for research-agent)"
kubectl logs -n "$NS" "$RESEARCH_POD" --tail=20
if has_spiffe_id "$RESEARCH_POD"; then
  echo
  echo "Expected SPIFFE ID: spiffe://agentauth.io/customer/acme/agent/research"
fi

section "3. Rogue agent — wrong pod label, no SVID issued"
ROGUE_POD="$(pod_for rogue-agent)"
kubectl logs -n "$NS" "$ROGUE_POD" --tail=15
if has_spiffe_id "$ROGUE_POD"; then
  echo
  echo "UNEXPECTED: rogue workload received an SVID"
else
  echo
  echo "No SVID in logs (expected): pod label agent-type=impostor does not match"
  echo "the finance registration entry selector agent-type=finance."
fi

section "4. Compare to dev JWT identify()"
cat <<'EOF'

Dev (agentauth/backend/identity.py):
  POST /v1/identify + API key  ->  RS256 JWT
  Claims: sub, aud/customer_id, agent_type, scope, owner, ...

Production (this prototype):
  Pod starts  ->  SPIRE Agent workload attestation  ->  X.509 SVID
  SAN URI: spiffe://agentauth.io/customer/acme/agent/{type}

An agent cannot claim agent_type=finance in a JWT alone; the workload must
match every selector on the SPIRE registration entry (namespace, service
account, pod labels). See identity/identity.md for the full model.
EOF
