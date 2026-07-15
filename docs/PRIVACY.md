# Clay Seal Receipts Privacy and Data Handling

This document describes the data handled by Clay Seal Receipts, the layer that
records verifiable evidence of autonomous-agent execution. It is developer
guidance for privacy and security review, not a customer-specific legal privacy
policy.

## Data This Layer Handles

Receipts can contain the richest data in the Clay Seal stack, including:

- Agent IDs, tenant IDs, human or service principals, identity evidence, and
  capability context.
- Policy names, policy hashes, policy decisions, violation details, and
  enforcement modes.
- Tool names, resource references, input commitments, output hashes, and model
  metadata.
- Optional prompts, tool arguments, model outputs, red-team traces, and
  benchmark records if the integrator chooses to include them.
- Receipt IDs, audit-log checkpoints, signatures, public-key IDs, and verifier
  reports.
- Export payloads sent to SIEM, GRC, telemetry, or partner verification systems.

Do not put sensitive raw payloads into receipts unless the verification use case
requires it. Prefer commitments, hashes, redacted fields, or external references.

## Secrets

Treat the following as secrets:

- Bundle signing keys, KMS credentials, and verifier API keys.
- Live bearer tokens, identity credentials, and commit tokens.
- Raw prompts, tool inputs, model outputs, source code snippets, and business
  records when they contain user, employee, financial, or regulated data.
- Exporter credentials for OCSF/SIEM, OpenTelemetry, Vanta, Drata, SCITT, or
  custom sinks.

## Storage and Retention

Receipts are useful because they are durable, but durable evidence must be
intentional. Before production:

- Define which fields are included in receipt bundles for each workflow.
- Define retention periods for receipts, audit logs, verifier requests, and
  exported telemetry.
- Enable signed bundles and signed audit checkpoints.
- Encrypt receipt storage at rest.
- Separate development/demo receipts from production evidence.
- Delete or redact raw prompts and outputs when hashes satisfy the verifier.

## Data Minimization Patterns

- Store `sha256` commitments for large or sensitive payloads.
- Store a policy version and hash instead of a full policy when the verifier can
  fetch the policy from a controlled registry.
- Redact secrets before wrapping tools or exporting receipts.
- Use field-level allowlists for exporters.
- Avoid forwarding receipt bundles to third-party services unless the partner or
  customer has approved that destination.

## Production Controls

- Set `AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=1`.
- Require identity binding for production partner configs.
- Configure trusted signer public-key allowlists.
- Use API keys, mTLS, rate limits, and body-size caps for the HTTP verifier.
- Run outbound exporter calls through explicit allowlists.
- Review `docs/trust_model.md`, `docs/deployment.md`, and
  `docs/http_verifier.md` before launch.

## Compatibility and Branding

The product brand is Clay Seal. Package names and import paths currently remain
`clayseal-receipts` and `agentauth.receipts` for compatibility.
