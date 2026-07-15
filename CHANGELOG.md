# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Folded in swappable receipt authorization providers for native Clay Seal
  session authorizers, OPA, Cedar, OpenFGA, Casbin, and user-defined callables.
- Added a lightweight provider conformance kit and real-policy tests for the
  Rippling-style bonus authorization fixture.

## [0.5.2] - 2026-07-15

### Fixed

- Documented the GitHub tag install path until `clayseal-receipts` is published
  on PyPI.
- Removed self-referential optional extras so editable installs do not try to
  resolve `clayseal-receipts` from PyPI.

## [0.5.1] - 2026-07-15

### Changed

- Renamed the public Python distribution from `agentauth-receipts` to
  `clayseal-receipts`. The Python import path remains `agentauth.receipts` for
  compatibility.
- Updated public install docs, CI wheel smoke tests, optional-extra error
  messages, and repository URLs for `clayseal/clayseal-receipts`.

## [0.5.0] - 2026-07-14

### Added — production hardening (multi-instance deployment)

- **Standalone release packaging**: `clayseal-receipts` now ships the small
  `agentauth.core` contract layer it needs directly, so the public package no
  longer depends on a private `agentauth-core` repository. Optional L2
  capability checks remain lazy and fail closed only when L2-specific leases,
  budgets, or commit tokens are actually used.
- **Production guardrail** (`agentauth/receipts/environment.py`): `AGENT_RECEIPTS_ENV=production`
  refuses to start when any soundness escape hatch is set (`AGENT_RECEIPTS_ALLOW_STUB`,
  `ALLOW_UNSIGNED_CERTIFICATE`, `ALLOW_UNSIGNED_CHECKPOINT`, `REQUIRE_BUNDLE_SIGNATURES=0`),
  implies `REQUIRE_PROVER`, forces strict partner-config validation, and hard-fails the
  silent `FULL_ZK→SHADOW` downgrade. Enforced across the producing SDK, `arctl`, and verifier.
- **Managed/stable signing key**: `AGENT_RECEIPTS_SIGNING_KEY_PATH` loads one durable Ed25519
  key (shared `key_id` across replicas); `AGENT_RECEIPTS_REQUIRE_STABLE_SIGNER=1` (implied in
  production) refuses to start without it. Honors `AGENT_RECEIPTS_REQUIRE_KEY_ENCRYPTION`.
- **Configurable audit store**: `AGENT_RECEIPTS_AUDIT_DB` resolution accepts `sqlite://` URLs
  and fails closed on remote SQL URLs; production refuses an ephemeral/relative store unless
  `AGENT_RECEIPTS_AUDIT_STORE_ACK=1`. Documents the single-writer, shared-store model.
- **Identity binding enforcement**: `require_identity_binding` partner-config key +
  `AGENT_RECEIPTS_REQUIRE_IDENTITY_BINDING`; `verify_receipt_bundle(..., require_identity_binding=)`
  and any `min_assurance_tier` request now reject authority-unbound bundles
  (`authority_unbound`). Producing `AgentWrapper(require_identity_binding=True)` fails closed
  on unbound runs. `arctl verify-bundle --require-identity-binding`.
- **Verifier `/entries` hardening**: rate limiting extended to the SCITT transparency write
  path; in production the write path requires `AGENT_RECEIPTS_TRANSPARENCY_SINGLE_WRITER=1`.

### Changed

- `Dockerfile` pins base images by digest, runs as a non-root user, and no longer bakes
  `config/partner.yaml` (producers must mount/inject a real config).
- `VERSION` corrected to `0.5.0` (aligned with `pyproject.toml`/`_version.py`).

## [0.4.0] - 2026-07-05

### Added

- **Three-repo architecture** — this package is layer 3 (receipts + verification). Depends on:
  - [agentauth-identity](https://github.com/pberlizov/clayseal-identity) v0.4.0
  - [agentauth-capabilities](https://github.com/pberlizov/clay-seal-capabilities) v0.4.0
- Cross-provider receipt wrapping via `agentauth.receipts.integration.wrap_with_identity_session()`.
- `docs/DEV_GUIDE.md` — comprehensive developer guide for the full stack.
- GitHub Actions CI for Python and Rust test suites.
- `scripts/layer_install_smoke.sh` — verifies pip install from pinned git tags.

### Changed

- Top-level `from agentauth import Identity, AgentWrapper` exports live in this repo only.
- `AuthorityBinding` re-exported from `agentauth.core.authority_binding` (shared with L2).
- `VERSION`, `_version.py`, and `pyproject.toml` aligned at **0.4.0**.
- `RELEASE.md` updated for three-layer release process.

### Removed

- 163 committed `__pycache__` artifacts (v0.3.1 cleanup).

## [Unreleased — evidence plane (pre-split)]

### Added — evidence plane (ZK binding + signing)

- Halo2 policy proof now **binds the committed output and policy** into its public inputs
  (`commitment_to_field`); editing a receipt's `output_hash` / `policy_commitment` after
  proving fails verification. (Circuit id bumped; superseded by `policy_range_v3`.)
- Ed25519 signing module (`agentauth.receipts.signing`): `SigningKey`, `generate_keypair`,
  `load_or_create_key`, and envelope-level `sign_bundle` / `verify_bundle_signatures`.
- Audit log hardening: optional per-record Ed25519 signatures, `verify_signatures()`, and a
  signed Merkle `signed_checkpoint()` / `verify_checkpoint()` that detects a full-chain rewrite.
- `cryptography` runtime dependency; `keys/signing/` private keys git-ignored.

### Changed

- Trust model docs updated with output-binding, signature, and checkpoint guarantees.

## [0.2.1] - 2026-05-29

### Added — deployment hardening (pre design partner ship)

- `arctl preflight` go/no-go checks (config, policy, writable dirs, prove readiness)
- `scripts/partner_preflight.sh` deployment gate
- HTTP verifier: optional API key auth, rate limiting, body size cap, `GET /ready`
- Stable agent identity via `persist_certificate` (load/create JSON cert)
- `PartnerConfig` strict mode, env overrides (`AGENT_RECEIPTS_*`)
- [docs/deployment.md](docs/deployment.md), `config/partner.production.example.yaml`, `config/env.example`
- `partner_factory.build_agent_from_config()` for integrations
- Structured logging via `AGENT_RECEIPTS_LOG_LEVEL`

## [0.2.0] - 2026-05-29

### Added — design partner readiness

- HTTP verifier service (`POST /v1/verify`, `GET /health`, `GET /v1/version`) via `arctl serve`
- Partner onboarding guide ([docs/design_partner.md](docs/design_partner.md))
- Partner operations runbook ([docs/partner_runbook.md](docs/partner_runbook.md))
- Receipt bundle export (`clayseal-receipts.receipt-bundle.v1`) and `arctl verify-bundle`
- `arctl` CLI: `doctor`, `export-audit`, `show-config`, `redact`, `serve`
- Partner YAML config (`config/partner.example.yaml`) and `examples/partner_pilot.py`
- `scripts/bootstrap.sh` and `scripts/partner_smoke.sh`
- `scripts/scaffold_policy.py` for custom policy YAML from schema constraints
- `arctl redact` for sharing receipts without PII
- Docker image and `docker-compose.yml` (verifier + optional MCP profile)
- [RELEASE.md](RELEASE.md) pinning instructions for pilot deployments

### Changed

- MCP server supports stdio, SSE, and streamable HTTP transports
- `ReceiptedMcpClient` supports prove + composed proofs on live MCP
- Python tooling CLI renamed to **`arctl`** (Rust binary remains **`clayseal-receipts`**)

## [0.1.0] - 2026-05-29

### Added

- Rust core: certificates, audit chain, proof envelopes
- Python SDK: `Policy`, `AgentWrapper`, operating modes
- Halo2 `policy_range_v1` circuit and CLI prove/verify
- MCP integration: gateway, delegation, live server
- EZKL fraud head path and logical composed verification

[0.2.0]: https://github.com/clayseal/clayseal-receipts/compare/v0.1.0...v0.2.0
[0.2.1]: https://github.com/clayseal/clayseal-receipts/compare/v0.2.0...v0.2.1
[0.5.0]: https://github.com/clayseal/clayseal-receipts/compare/v0.4.0...v0.5.0
[0.5.1]: https://github.com/clayseal/clayseal-receipts/compare/v0.5.0...v0.5.1
[0.5.2]: https://github.com/clayseal/clayseal-receipts/compare/v0.5.1...v0.5.2
[0.1.0]: https://github.com/clayseal/clayseal-receipts/releases/tag/v0.1.0
