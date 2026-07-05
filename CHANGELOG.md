# Changelog

All notable changes to this project are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

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
- Receipt bundle export (`agent-receipts.receipt-bundle.v1`) and `arctl verify-bundle`
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
- Python tooling CLI renamed to **`arctl`** (Rust binary remains **`agent-receipts`**)

## [0.1.0] - 2026-05-29

### Added

- Rust core: certificates, audit chain, proof envelopes
- Python SDK: `Policy`, `AgentWrapper`, operating modes
- Halo2 `policy_range_v1` circuit and CLI prove/verify
- MCP integration: gateway, delegation, live server
- EZKL fraud head path and logical composed verification

[0.2.0]: https://github.com/pberlizov/agent-receipts/compare/v0.1.0...v0.2.0
[0.2.1]: https://github.com/pberlizov/agent-receipts/compare/v0.2.0...v0.2.1
[0.1.0]: https://github.com/pberlizov/agent-receipts/releases/tag/v0.1.0
