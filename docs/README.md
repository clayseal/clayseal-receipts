# Clay Seal documentation

Clay Seal is one modular system for agent **identity** (L1), dynamic
**capabilities** (L2), and verifiable **execution receipts** (L3). The current
repositories are independently installable as `agentauth-core`,
`agentauth-identity`, `agentauth-capabilities`, and `agentauth-receipts`, with
the compatibility import namespace `agentauth.*`.

Start with the [repository README](../README.md) for the developer surface and
[DEV_GUIDE.md](DEV_GUIDE.md) for the layer 3 integration path.

This index catalogs everything under `docs/`. New to the project? Start with
[architecture.md](architecture.md), then [trust_model.md](trust_model.md),
[decision_model.md](decision_model.md), and [PRIVACY.md](PRIVACY.md).

## Architecture & core model

- [architecture.md](architecture.md) — system architecture and the L1–L4 layering.
- [l1_l3l4_boundary.md](l1_l3l4_boundary.md) — the seam between attested identity and the receipts runtime (`AuthorityBinding`).
- [decision_model.md](decision_model.md) — the L3 decision objects (decision / authority / action / approval / budget) that appear on receipts.
- [execution_context.md](execution_context.md) — the L3 execution context: actors, actions, side-effect levels, resource refs.
- [trust_model.md](trust_model.md) — what a receipt does and does not prove; output-binding, signature, and checkpoint guarantees.
- [assurance_taxonomy.md](assurance_taxonomy.md) — assurance levels and trust tiers emitted on receipts.
- [inference_and_composition.md](inference_and_composition.md) — EZKL inference proofs and composition with the policy proof.
- [roadmap.md](roadmap.md) — what is implemented and what is planned.

## Identity and capabilities (L1/L2)

- [l1_l2_token_architecture.md](l1_l2_token_architecture.md) — token architecture decision (JWT-SVID + capability tokens).
- [l1_l2_hardening.md](l1_l2_hardening.md) — workload-key hardening for the identity backend.
- [l1_l2_sota_assessment.md](l1_l2_sota_assessment.md) — state-of-the-art assessment for agent identity and capability authorization.

## Receipts (L3/L4) & verification

- [receipt_bundle_v2.md](receipt_bundle_v2.md) — the v2 receipt bundle format and v1→v2 migration.
- [backward_compatibility.md](backward_compatibility.md) — compatibility guarantees across bundle versions.
- [dynamic_planning.md](dynamic_planning.md) — dynamic sandbox backlog (DP-1…DP-45) and implementation status.
- [http_verifier.md](http_verifier.md) — the standalone HTTP verifier (`arctl serve`, `POST /v1/verify`).
- [policy_language.md](policy_language.md) — the v0 policy language.
- [witnessing.md](witnessing.md) — checkpoint witnessing and anti-equivocation.
- [tlog_tiles.md](tlog_tiles.md) — tile-based static transparency-log export.
- [scitt.md](scitt.md) — SCITT-aligned receipts (COSE / RFC 6962).
- [tee_attestation.md](tee_attestation.md) — TEE quote verification (Nitro / TDX / CC).
- [PRIVACY.md](PRIVACY.md) — receipt-layer data minimization, retention, exports, and production controls.

## Integration & interop

- [framework_integrations.md](framework_integrations.md) — optional adapters for LangChain and plain-function agent tool frameworks.
- [mcp_integration.md](mcp_integration.md) — receipting MCP tool calls (`ReceiptedMcpGateway`).
- [mcp_live_server.md](mcp_live_server.md) — the live MCP server pilot (`ReceiptedMcpClient`, transports).
- [otel_genai_mapping.md](otel_genai_mapping.md) — mapping receipts onto the OpenTelemetry GenAI semantic conventions.
- [compliance_mapping.md](compliance_mapping.md) — SIEM/compliance field mapping (ECS, OTel, CEF).

## Partner & operations

- [design_partner.md](design_partner.md) — the design-partner integration guide.
- [partner_runbook.md](partner_runbook.md) — operations runbook: escalation, retention, redaction, health checks.
- [deployment.md](deployment.md) — deployment guide (preflight, verifier, Docker).

## Strategy & research

- [open_standard_strategy.md](open_standard_strategy.md) — strategy for an open evidence-plane standard.
- [state_of_the_art.md](state_of_the_art.md) — survey of verifiable agent-execution evidence.
- [landscape_research.md](landscape_research.md) — competitive and standards landscape.
- [combined_corpus_sota_review.md](combined_corpus_sota_review.md) — combined-corpus review of approaches against the SOTA.
- [arch-review.md](arch-review.md) — architecture review notes (consolidated from repo root).

## v1 product specs (historical)

Early product specs preserved for reference; superseded by the docs above for current architecture.

- [v1-specs/about.md](v1-specs/about.md)
- [v1-specs/dev-experience.md](v1-specs/dev-experience.md)
- [v1-specs/service.md](v1-specs/service.md)

## Decision records (ADRs)

Point-in-time architecture decisions; preserved as written.

- [v1-decisions/01-identity-service.md](v1-decisions/01-identity-service.md) — Piece 1: backend foundation + identity service.
- [v2-decisions/01-identity-attestation.md](v2-decisions/01-identity-attestation.md) — Piece v2.1: identity from declared to attested.

## Backlogs

- [l3_l4_backlog.md](l3_l4_backlog.md) — L3/L4 receipts-runtime backlog.
- [sota_backlog.md](sota_backlog.md) — evidence-plane state-of-the-art backlog.
- [security_issues_backlog.md](security_issues_backlog.md) — tracked security findings and their status.
- [devin_redteam_index.md](devin_redteam_index.md) — Devin red-team scripts and scenario index.
