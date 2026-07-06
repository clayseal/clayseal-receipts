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
| Key encryption at rest | Non-SQLite identity DBs require `AGENTAUTH_SECRET_ENCRYPTION_PROVIDER`; plaintext keys are refused once encryption is enabled. Receipt signing keys honor `AGENT_RECEIPTS_REQUIRE_KEY_ENCRYPTION=1` (refuse to create an unencrypted on-disk key) |
| Prover honesty | `prove` / proof-enabled `bounded_auto` fail if a requested prover returns no proof; stubs are off unless explicitly enabled |
| Production guardrail | `AGENT_RECEIPTS_ENV=production` refuses to start when any soundness escape hatch is set (`AGENT_RECEIPTS_ALLOW_STUB`, `ALLOW_UNSIGNED_CERTIFICATE`, `ALLOW_UNSIGNED_CHECKPOINT`, `REQUIRE_BUNDLE_SIGNATURES=0`), implies `REQUIRE_PROVER`, forces strict config, and blocks the silent `FULL_ZK→SHADOW` downgrade |
| Stable signer | `AGENT_RECEIPTS_SIGNING_KEY_PATH` loads one durable Ed25519 key so replicas share a `key_id`; `AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER=1` (implied in production) refuses to start without it, keeping `TRUSTED_SIGNER_KEY_IDS` pinning valid |
| Identity binding | `require_identity_binding: true` (config) / `AGENT_RECEIPTS_REQUIRE_IDENTITY_BINDING=1` (verifier): producers fail closed on unbound runs, and the verifier rejects bundles lacking a validated identity with `authority_unbound` |

Public paths (no API key): `/health`, `/ready`, `/v1/version`.

Development-only overrides:

```env
AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE=1
AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=0
AGENT_RECEIPTS_ALLOW_STUB=1
```

Do not set these in production. They exist for local fixtures and offline demos where
you intentionally want to inspect self-consistent evidence that is not authenticated.
`AGENT_RECEIPTS_ENV=production` enforces this for you: the SDK, CLI, and verifier all
refuse to start if any of these downgrade flags is set.

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

## Horizontal scaling (production)

The receipt **audit chain is a single-writer, concurrency-safe hash log**: SQLite
`BEGIN IMMEDIATE` serializes concurrent appenders on **one shared store**, so many
threads/processes can append to the *same* file without forking the chain. What forks
state is giving each replica its **own** local SQLite file — you then get N divergent
hash chains and N Merkle roots. Two knobs make this safe and explicit:

- **Shared audit store** — point every producing replica at ONE durable store via
  `AGENT_RECEIPTS_AUDIT_DB` (absolute path on a shared single-writer volume). A
  `postgresql://`/other remote SQL URL is **rejected** (fail-closed) rather than
  silently forking; a real shared-SQL backend is future work. Under
  `AGENT_RECEIPTS_ENV=production` an ephemeral/relative default store is refused unless
  you set `AGENT_RECEIPTS_AUDIT_STORE_ACK=1` to acknowledge a single-instance producer.
- **Stable signer** — set `AGENT_RECEIPTS_SIGNING_KEY_PATH` (a KMS-provisioned or
  shared-secret file) so every replica signs audit records/checkpoints with the same
  key and one `key_id`, instead of auto-generating a fresh key per container.
  `AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER=1` (implied in production) refuses to start
  without it.

### Verifier scaling

`POST /v1/verify` is **stateless** — its verdict is a pure function of the request body
plus process env (trust anchors, tier/identity requirements). It holds no cross-request
state and scales horizontally behind a load balancer with no shared store. The only
stateful surface is the in-process **SCITT `/entries` transparency log** (one Merkle tree
per process): its write path is refused in production unless exactly one instance sets
`AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER=1` (or you back it with a shared durable log),
and `AGENTAUTH_SCITT_SIGNING_KEY_HEX` should be pinned so receipts stay verifiable across
restarts. The in-process rate limiter (`/v1/verify` and `/entries`) is per-instance and
advisory; behind more than one instance the **API gateway / WAF is authoritative** for
rate limiting.

## Notes / known limitations

- The ~52 MB of committed `keys/**/*.bin` are **public** Halo2/ZK proving parameters
  (not secrets). They are a good candidate for Git LFS to keep clones lean.
- Canonical JSON hashing (`hash_canonical_json`) is a stable, sorted-key encoding but is
  **not** strict RFC 8785 (JCS); it is self-consistent for producing and verifying
  receipts, not an interop guarantee with external JCS implementations.

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

- A native shared-SQL (Postgres) audit backend — production uses one shared single-writer
  SQLite store or a single producer instance (see Horizontal scaling above)
- Multi-region HA and a shared/durable SCITT transparency tree (single-writer for now)
- Enterprise PKI / HSM (KMS-provisioned signing key file is supported)
- Managed SaaS verifier

See [partner_runbook.md](partner_runbook.md) for operations.
