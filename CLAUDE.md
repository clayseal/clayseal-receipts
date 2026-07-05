# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**AgentAuth** is one system for agent **identity** *and* verifiable **execution**:

- **Identity (L1/L2)** — an Auth0-equivalent, multi-tenant identity service that attests agent workloads and issues short-lived, verifiable JWT-SVID credentials and Biscuit capability tokens, with key rotation, JWKS, revocation, and an append-only identity event log.
- **Receipts (L3/L4)** — a runtime that wraps an agent, runs a policy decision, and binds the outcome into a tamper-evident, cryptographically verifiable receipt (ZK / TEE / shadow paths) with a hash-chained audit log and a verifier.

The two layers are joined by one developer surface: `auth.identify(...)` returns a session, and `session.wrap(model, policy=...)` produces a receipting wrapper whose every receipt carries the *attested* identity.

Everything ships as a single installable Python distribution, `agentauth`, with one import namespace:

- `agentauth/identity/` — the SDK: identity client/session, errors, models (was `sdk/python/agentauth`)
- `agentauth/backend/` — FastAPI service: identity router **and** receipt verifier (was `backend/app`)
- `agentauth/receipts/` — receipt runtime, policy engine, audit chain, verifier, MCP, proofs, **dynamic sandbox** (`sandbox_builder.py`, scoping, governors)
- `agentauth-mcp/` — MCP server with mandate + receipts (from `devin/mcp-demo`)
- `benchmarks/` — E2E harness, soundness benchmarks, trajectory corpus
- `demo/` — narrated demos (`poisoned_mcp_demo.py`, sandboxed server)
- `crates/` — Rust ZK/TEE proving core (Halo2 policy circuit, RISC Zero, session folding)
- `dashboard/` — React/TypeScript SPA for managing agents
- `identity/` — SPIRE/SPIFFE deployment manifests for production attestation

Production identity uses SPIRE/SPIFFE attestation (`identity/`) instead of dev API-key JWTs.

## Commands

### Install (one distribution, one venv)
```bash
pip install -e ".[dev]"     # identity + receipts + backend(server) + mcp + verifier + test deps
```

### Tests
```bash
# All Python suites (run from repo root)
pytest                                   # uses [tool.pytest.ini_options] testpaths
pytest python/tests                      # receipts runtime
pytest backend/tests                     # backend (identity + verifier endpoints)
pytest sdk/python/tests                  # SDK + the unified identity->receipt e2e
pytest benchmarks/tests                  # harness smoke + adapter tests (corpus cases skip if absent)
pytest backend/tests/test_identity.py::test_attestation_issues_jwt_svid   # single test

# Rust proving core
cargo test
```

### Lint
```bash
ruff check .          # lint (E, F, I, UP); line-length 100, target py310
ruff format .         # format
```

> Run the three Python suites separately (each boots its own in-process backend / env state); a single `pytest` from root collects all three but they share process-global env, so prefer per-directory runs when debugging.

### Coverage (blind-spot detection)
```bash
# Combine all three suites into one dataset (they run as separate processes),
# then report. Config lives in [tool.coverage.*] in pyproject.toml.
pytest python/tests    --cov=agentauth --cov-branch --cov-report=
pytest backend/tests   --cov=agentauth --cov-branch --cov-append --cov-report=
pytest sdk/python/tests --cov=agentauth --cov-branch --cov-append --cov-report=
coverage report --show-missing           # line + branch coverage, missing lines
coverage html                            # browsable report in htmlcov/
coverage json && python scripts/coverage_summary.py   # ranked least-covered modules

# Changed-lines coverage (how well a diff is tested)
coverage xml && diff-cover coverage.xml --compare-branch origin/main

# Rust: cargo install cargo-llvm-cov; then
cargo llvm-cov --all --summary-only
# Dashboard:
cd dashboard && npm run test:coverage
```
CI (`.github/workflows/ci.yml`) runs all of the above and publishes a blind-spot summary + changed-lines coverage to the workflow run. Reports are non-blocking by default — raise `--fail-under` / `diff-cover --fail-under` to turn them into gates.

### Backend dev server (serves identity + verification)
```bash
uvicorn agentauth.backend.main:app --reload
```

### CLI / verifier
```bash
arctl verify-bundle receipts/<id>.json
arctl explain receipts/<id>.json
arctl serve                              # standalone receipt verifier (shares logic with the backend)
```

### Dashboard
```bash
cd dashboard && npm install
npm run dev        # localhost:5173
npm run typecheck && npm run test
```

### Examples
```bash
python examples/01_quickstart.py         # identity
python examples/shadow_fraud_agent.py    # receipts
python demo/poisoned_mcp_demo.py         # poisoned MCP + Biscuit gate
python -m agentauth.receipts.sandboxed_server   # dynamic sandbox MCP
bash scripts/run_devin_redteam_gate.sh   # Devin PR-gate red-team matrix
```

## Architecture

### The seam (how the layers connect)
Identity is *attested, not declared*: a workload presents a signed attestation document, selectors are derived from verified evidence, and the matching `RegistrationEntry` — not the caller — dictates `agent_type`/`scopes`. The minted JWT-SVID's `sub` is the agent's SPIFFE ID. Default-deny.

`AgentSession.wrap()` (`agentauth/identity/session.py`) turns that attested credential into an `AuthorityBinding` (`agentauth/receipts/authority_binding.py::from_agentauth_credential`) and hands it to `AgentWrapper` as its `default_authority_binding`, so every receipt is bound to the verified identity. A wrapper built directly (no identity) still runs, unbound.

### Identity backend (`agentauth/backend/`)
Multi-tenant: every ORM model in `models.py` has a `customer_id`; every query filters by tenant; `X-API-Key` resolves the tenant. Key modules: `identity.py` (RS256 JWT-SVID issue/validate, per-customer keys, rotation, JWKS, revocation), `attestation.py` (node + workload attestation, selectors), `capabilities.py` (Biscuit tokens, PoP), `audit.py` (append-only JSONL identity event log), `errors.py` (machine `code` + `message` + `suggestion`). Routers: `routers/identity.py` and `routers/verifier.py` (public `POST /v1/verify`, `GET /v1/version`).

### Receipts runtime (`agentauth/receipts/`)
`AgentWrapper` (`wrapper.py`) runs the policy engine, records the `DecisionResult`, and builds an `ExecutionProof` in modes shadow/recommend/bounded_auto/prove. `export.py` builds/verifies receipt bundles (v1/v2); `audit.py` is the hash-chained execution log with RFC 6962 inclusion/consistency proofs and witness quorum; `verifier_server.py` is the standalone verifier (logic shared with the backend router).

### SDK surface (`agentauth/__init__.py`)
`from agentauth import AgentAuth, AgentSession, AgentWrapper, Policy, build_receipt_bundle, ...` — one import for both layers. Sub-namespaces `agentauth.identity` / `agentauth.receipts` / `agentauth.backend` remain for advanced use.

## Configuration

Identity backend settings are env vars (see `agentauth/backend/config.py`): `AGENTAUTH_DATABASE_URL`, `AGENTAUTH_MIN_TTL`/`MAX_TTL`/`DEFAULT_TTL` (5m/24h/1h), `AGENTAUTH_TRUST_DOMAIN` (also JWT `iss`, default `agentauth.io`), `AGENTAUTH_CORS_ORIGINS`. The identity event log is a hash-chained `audit_events` table in the database (see `agentauth/backend/audit.py`), not a flat file.

Receipts runtime/partner settings come from `config/partner.yaml` (see `config/partner.example.yaml`): `policy_path`, `audit_db`, `mode`, certificate paths, `model_provenance_hash`, principal. Dashboard base URL defaults to `localhost:8000` (`VITE_AGENTAUTH_BASE_URL`).

## Test Fixtures

`backend/tests/conftest.py` builds an in-process FastAPI app with a fresh in-memory SQLite DB and a test tenant per test. `sdk/python/tests/conftest.py` runs the same backend over real HTTP. `python/tests` exercises the receipt runtime directly. Do not mock the database in backend tests.
