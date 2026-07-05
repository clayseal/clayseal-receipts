# Deployment guide (design partner)

Hardening checklist before giving a partner access.

## Go / no-go

```bash
bash scripts/bootstrap.sh
cp config/partner.production.example.yaml config/partner.yaml
# Edit placeholders (model hash, org, principal)
arctl preflight config/partner.yaml --strict
bash scripts/partner_preflight.sh
```

Exit code `0` on `arctl preflight` means **safe to deploy the agent SDK**.  
For the HTTP verifier, also confirm `curl /ready` returns `"ready": true`.

## Recommended architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Agent gateway  │────▶│ Agent Receipts   │────▶│  Audit SQLite   │
│  (your code)    │     │ SDK (in-process) │     │  + receipts/    │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │
                                ▼
                        ┌──────────────────┐
                        │ HTTP verifier    │◀── compliance (VPC only)
                        │ (arctl serve)    │
                        └──────────────────┘
```

- **SDK** runs in-process with your agent — not a separate hop for decisions.
- **Verifier** is read-only verification for auditors; place behind API gateway.

## Security controls (v0.2.1+)

| Control | How |
|---------|-----|
| Verifier auth | `AGENT_RECEIPTS_VERIFIER_API_KEY` + `X-API-Key` or `Authorization: Bearer` |
| Rate limit | `AGENT_RECEIPTS_VERIFIER_RATE_LIMIT` (default 120/min/IP) |
| Body size cap | `AGENT_RECEIPTS_MAX_BODY_BYTES` (default 1 MiB) |
| K8s readiness | `GET /ready` (503 if prover required but missing) |
| Stable agent identity | `persist_certificate` in partner YAML |
| Config validation | `strict: true` + `arctl preflight --strict` |
| Receipt authenticity | Configure `AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS` or `_KEY_IDS`; unsigned bundles fail verification by default |
| Certificate issuer trust | Configure `AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS` or `_KEY_IDS`; unsigned certs require the dev override below |
| Key encryption at rest | Non-SQLite identity DBs require `AGENTAUTH_SECRET_ENCRYPTION_PROVIDER`; plaintext keys are refused once encryption is enabled |
| Prover honesty | `prove` / proof-enabled `bounded_auto` fail if a requested prover returns no proof; stubs are off unless explicitly enabled |

Public paths (no API key): `/health`, `/ready`, `/v1/version`.

Development-only overrides:

```env
AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE=1
AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=0
AGENT_RECEIPTS_ALLOW_STUB=1
```

Do not set these in production. They exist for local fixtures and offline demos where
you intentionally want to inspect self-consistent evidence that is not authenticated.

## Docker deployment

```bash
cp config/env.example .env
# Edit AGENT_RECEIPTS_VERIFIER_API_KEY
docker compose --env-file .env up verifier
curl -s http://localhost:8787/ready | jq .
curl -s -X POST http://localhost:8787/v1/verify \
  -H "X-API-Key: $AGENT_RECEIPTS_VERIFIER_API_KEY" \
  -H 'Content-Type: application/json' \
  -d @receipts/<id>.json
```

Enable prove-mode verifier:

```env
AGENT_RECEIPTS_REQUIRE_PROVER=1
```

For the identity backend, local SQLite remains acceptable for development. Any
non-SQLite `AGENTAUTH_DATABASE_URL` requires a configured secret-encryption provider:

```env
AGENTAUTH_SECRET_ENCRYPTION_PROVIDER=local
AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY=<64-hex-character-random-key>
```

Use `aws_kms` or `gcp_kms` for managed production key custody. `/health` reports
whether secret encryption is enabled and whether it is required for the configured DB.

File-backed audit logs use SQLite WAL mode, a 30s busy timeout, and transactional
single-writer appends. This prevents concurrent appenders from reading the same tip
and forking the local hash chain, but Postgres or a managed log service is still the
recommended production direction for multi-region identity state.

## TLS

Terminate TLS at your load balancer or ingress — the verifier listens HTTP inside the VPC.

## Supply-chain checks

CI runs dependency and configuration security scans in addition to tests:

- `pip-audit` for Python dependencies
- `cargo audit` for Rust advisories
- `npm audit --audit-level=high` for the dashboard
- Gitleaks for committed secrets
- Trivy config scanning for Docker/Kubernetes/IaC issues

## Certificate rotation

1. Update policy YAML → new `policy_commitment`
2. Delete or archive old `certs/partner-agent.json`
3. Restart agent — new certificate is created and persisted
4. Re-export sample receipts for compliance

## Operating mode rollout

| Week | Mode | Goal |
|------|------|------|
| 1 | `shadow` | Audit chain + policy metrics |
| 2 | `bounded_auto` | Enforce abstain on violations |
| 3+ | `prove` | Crypto demos for stakeholders |

## Still not included

- Multi-region HA, horizontal scaling of verifier state (rate limit is in-memory)
- Enterprise PKI / HSM
- Managed SaaS verifier

See [partner_runbook.md](partner_runbook.md) for operations.
