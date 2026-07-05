# AgentAuth — Backend (Identity Service)

The hosted identity service behind AgentAuth: an Auth0-equivalent that issues
verifiable, short-lived credentials to AI agents.

- **Identity Service** (`agentauth/backend/identity.py`) — attests workloads and
  issues signed **JWT-SVID** credentials with per-customer Ed25519 signing keys
  and JWKS, while each credential is sender-constrained to an attested Ed25519
  workload key via `cnf.jkt`.
- **Capability Service** (`agentauth/backend/capabilities.py`) — mints
  Ed25519-rooted Biscuit grants bound to the same workload key, verifies
  request-bound PoP, and deny-lists Biscuit revocation IDs when credentials are
  revoked.
- **Attestation** (`../agentauth/backend/attestation.py`) — the prototype's stand-in for SPIRE's
  node + workload attestation: a workload proves its environment with a signed
  attestation document, selectors are *derived from verified evidence*, and the
  matching registration entry (not the caller) dictates `agent_type` + `scopes`.
- **Identity event log** (`agentauth/backend/audit.py`) — hash-chained,
  append-only `audit_events` table in the database recording every credential
  lifecycle event (issuance, revocation, key rotation, attestor / registration
  changes).

## Quickstart

```bash
# From the repo root — one package, one venv
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[server]"        # or ".[dev]" to include the test deps

# run the API
uvicorn agentauth.backend.main:app --reload
# -> http://127.0.0.1:8000/docs

# run the backend tests
pytest backend/tests
```

## API

All endpoints except `POST /v1/customers` require an `X-API-Key` header.

| Method & path | Purpose |
|---|---|
| `POST /v1/customers` | Sign up a tenant; returns `api_key` (shown once) + provisions a signing key |
| `POST /v1/node-attestors` | Register a node trust anchor (the public key whose signatures prove node provenance) |
| `GET /v1/node-attestors` / `DELETE /v1/node-attestors/{id}` | List / remove node attestors |
| `POST /v1/registration-entries` | Pre-approve an identity: the selectors a workload must attest to receive an `agent_type` + `scopes` |
| `GET /v1/registration-entries` / `DELETE /v1/registration-entries/{id}` | List / remove registration entries |
| `POST /v1/identify` | Attest a signed document and mint a JWT-SVID |
| `POST /v1/challenge` | Issue a one-time PoP challenge for `/validate` or `/authorize` |
| `POST /v1/validate` | Verify a token (signature + expiry + agent status + request-bound PoP) |
| `POST /v1/authorize` | Verify a Biscuit capability token with request-bound PoP and revocation checks |
| `POST /v1/agents/{id}/revoke` | Revoke an agent credential and deny-list its Biscuit revocation IDs |
| `GET /v1/agents` | List agents (filter by `status`, `agent_type`) |
| `GET /v1/agents/{id}` | Fetch one agent |
| `POST /v1/keys/rotate` | Rotate the customer's signing key |
| `GET /v1/jwks.json` | Public keys (JWKS) for offline verification |

### Example

```bash
# 1. sign up
curl -s localhost:8000/v1/customers -d '{"name":"Acme AI"}' \
  -H 'content-type: application/json'
# -> {"customer_id":"...","name":"Acme AI","api_key":"aa_..."}

# 2. register a node trust anchor + a registration entry (admin setup), then
#    POST a signed attestation document to mint a credential
curl -s localhost:8000/v1/identify \
  -H 'X-API-Key: aa_...' -H 'content-type: application/json' \
  -d '{"attestation_document":"<signed-jws>","ttl_seconds":3600}'
```

A workload never self-declares its identity: `agent_type` and `scopes` come from
the matched registration entry, ownership metadata is admin-controlled there,
and selectors are derived only from verified evidence. See
`../identity/identity.md` for the production SPIRE/SPIFFE layout and
`../docs/l1_l2_hardening.md` for workload key custody, PoP, and Biscuit
revocation details.

## Configuration (env vars)

| Var | Default | Notes |
|---|---|---|
| `AGENTAUTH_DATABASE_URL` | `sqlite:///./agents.db` | any SQLAlchemy URL; also holds the hash-chained `audit_events` log |
| `AGENTAUTH_MIN_TTL` | `300` | 5 min |
| `AGENTAUTH_MAX_TTL` | `86400` | 24 h |
| `AGENTAUTH_DEFAULT_TTL` | `3600` | 1 h |
| `AGENTAUTH_TRUST_DOMAIN` | `agentauth.io` | SPIFFE trust domain (and JWT `iss`) |
| `AGENTAUTH_ISSUER` | _(trust domain)_ | override JWT `iss` |
| `AGENTAUTH_RSA_KEY_SIZE` | `2048` | minimum size for the prototype RSA node-attestation trust anchor |
| `AGENTAUTH_CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | dashboard origins |

Design notes live in `../docs/v1-decisions/01-identity-service.md`,
`../docs/v2-decisions/01-identity-attestation.md`, and
`../docs/l1_l2_token_architecture.md`.
