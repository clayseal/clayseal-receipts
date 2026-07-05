# Piece 1 — Backend foundation + Identity Service

Decisions, trade-offs, and notes for the first piece. Maps to `service.md`
("The Identity Service issues and validates signed agent credentials").

## Scope delivered

- FastAPI app skeleton with a consistent error envelope.
- SQLite persistence via SQLAlchemy 2.0 (`Customer`, `SigningKey`, `Agent`).
- Per-customer Ed25519 keypair management + automatic rotation.
- JWT (EdDSA/Ed25519) issuance with short, bounded TTLs.
- Token validation (signature + expiry + agent status) and revocation.
- JWKS endpoint for offline verification.
- Minimal append-only event log for identity events.
- 22 tests covering issuance, validation, tenant isolation, rotation, revocation,
  TTL bounds, tampering, and audit.

## Key decisions

### 1. Stack: FastAPI + SQLAlchemy + SQLite + JSONL
The repo's `.gitignore` already implied `backend/agents.db` and
`backend/audit.jsonl`, so I leaned into SQLite for relational state and a JSONL
file for the append-only audit log. FastAPI gives us typed request/response
models and OpenAPI docs for free, which matters for a developer-facing product.
A repository-ish boundary (everything goes through SQLAlchemy sessions) means
the storage layer can later be swapped for Postgres/object storage without
touching the service logic.

### 2. Multi-tenant from day one, keyed by API key
A single backend serves many customers. The tenant is resolved from the
`X-API-Key` header (`app/deps.py`). Every table carries a `customer_id` and
every query is scoped to it. This mirrors the Auth0 model (one service, many
tenants) and lets the dashboard and SDK target one base URL.

- **API key format**: `aa_<43 url-safe chars>` via `secrets.token_urlsafe(32)`.
- **Trade-off / known gap**: keys are currently stored in plaintext in SQLite
  for the reference implementation. Production should store only a hash
  (e.g. SHA-256) and compare in constant time. Noted here intentionally.

### 3. Credentials are Ed25519 JWTs with a per-customer keypair
Each customer gets its own Ed25519 keypair (`SigningKey`). Tokens are signed
with the customer's **active** private key; the `kid` header records which key,
so validation and JWKS can select the right public key. Asymmetric signing means
downstream services can verify tokens offline using the public JWKS without
holding a shared secret.

- **Why per-customer keys** instead of one global key: blast radius. A key
  compromise or rotation is isolated to one tenant.
- **Algorithm**: PyJWT currently emits the JOSE `EdDSA` alg for Ed25519 OKP
  keys. The verifier allow-lists that single alg and rejects mismatched stored
  key metadata.

### 4. Rotation keeps retired keys for verification
`rotate_key()` marks the current key `retired` (keeping it) and creates a new
`active` key. New tokens use the new key; already-issued tokens still verify
against the retired key until they expire. Because TTLs are short (≤ 24h),
retired keys can be safely garbage-collected after the max TTL window — left as
a future cleanup job. This delivers the spec's "we handle key rotation
automatically — developers never think about it."

### 5. TTLs are short and bounded
Default 1h, min 5m, max 24h (all configurable), matching `service.md`. Requests
outside the range fail with an **actionable** `ttl_out_of_range` error that
names the valid bounds, rather than silently clamping — silent clamping hides
bugs from developers.

### 6. The UTC/epoch bug worth recording
`datetime.utcnow()` returns a *naive* datetime; calling `.timestamp()` on it
interprets it as **local** time, which on this machine (UTC-7) pushed `iat`/`exp`
~7 hours into the future and made every fresh token "not yet valid." Fixed with
a `to_epoch()` helper that pins `tzinfo=UTC` before converting. Lesson encoded
in code + tests: never call `.timestamp()` on a naive UTC datetime.

### 7. Datetime storage convention
SQLite has no real tz type. We standardise on **naive == UTC** everywhere and
never mix aware/naive values. All conversions to epoch go through `to_epoch()`.

### 8. Actionable errors as a first-class concept
`app/errors.py` defines an `AgentAuthError` hierarchy where every error carries
`{code, message, suggestion}`. A single FastAPI exception handler renders them
to a consistent JSON envelope:

```json
{ "error": { "code": "ttl_out_of_range", "message": "...", "suggestion": "..." } }
```

This is the backbone for the spec's "errors are actionable, not cryptic" — the
SDK (later piece) surfaces `suggestion` directly to developers.

### 9. Validation marks agents expired as a side effect
When a token fails on expiry, we best-effort flip the `Agent.status` to
`expired` so the dashboard reflects reality without a separate sweeper. This is
wrapped in a try/except so audit/bookkeeping can never mask the real error.

### 10. Append-only identity event log
`app/audit.py` is a tiny thread-locked append-to-JSONL writer so identity
events (`identity.issued`, `identity.revoked`, `key.rotated`) are captured from
day one. It is an internal event sink, not a queryable service.

## Data model snapshot

- `Customer(id, name, api_key, created_at)`
- `SigningKey(kid, customer_id, private_pem, public_pem, status, created_at, retired_at)`
- `Agent(id, customer_id, agent_type, owner, scopes, status, jti, issued_at,
  expires_at, created_at)`

## What's intentionally deferred

- API key hashing at rest.
- Retired-key garbage collection job.
- Rate limiting / quotas per customer.
- Replacing SQLite/JSONL with production datastores.
