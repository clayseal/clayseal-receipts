# OpenTelemetry GenAI mapping (SOTA-13)

Maps a receipt's evidence onto OpenTelemetry **GenAI** semantic conventions so receipts drop into
existing agent-observability / SIEM pipelines without translation. Implemented in
[`agentauth/receipts/otel.py`](../agentauth/receipts/otel.py)
(`receipt_to_otel_attributes` / `receipt_to_otel_log_record`). See the OTel
[GenAI agent spans](https://opentelemetry.io/docs/specs/semconv/gen-ai/gen-ai-agent-spans/) and
[attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/).
Client spans left experimental status in early 2026; agent/framework spans are still experimental
but stable through 2026 — so we track them but keep our own evidence under a stable namespace.

## Crosswalk

| Receipt field | OTel GenAI attribute | Notes |
|---------------|----------------------|-------|
| (constant) | `gen_ai.system` = `agent_receipts` | identifies the producer |
| action (tool execution) | `gen_ai.operation.name` = `execute_tool` | receipts are tool-execution operations |
| `action.action_name` | `gen_ai.tool.name` | |
| `action.action_category` | `gen_ai.tool.type` | |
| `certificate.agent_id` / `authority.authority_id` | `gen_ai.agent.id` | |
| `certificate.display_name` / `authority.agent_type` | `gen_ai.agent.name` | |
| `decision.session_id` / `authority.session_id` | `gen_ai.conversation.id` | |

## No GenAI equivalent → `agent_receipts.*` namespace

OTel GenAI has no slot for our authority, decision, assurance, or integrity evidence — the very
things that make a receipt *verifiable* rather than just observable. Forcing them into `gen_ai.*`
would be dishonest, so they're namespaced:

| Receipt field | Attribute |
|---------------|-----------|
| `action.resource_type` / `resource_ref` | `agent_receipts.action.resource_type` / `.resource_ref` |
| `action.side_effect_level` | `agent_receipts.action.side_effect_level` |
| `authority.authority_version` / `owner` / `proof_of_possession` | `agent_receipts.authority.*` |
| `decision.outcome` / `policy_satisfied` | `agent_receipts.decision.*` |
| `assurance.tier` | `agent_receipts.assurance.tier` |
| `schema` / `execution_proof.proof_id` / `policy.commitment` | `agent_receipts.receipt.*` / `.policy.commitment` |

## Status & follow-ups

- **Done:** the attribute crosswalk + a log-record shape, tested in
  [`test_otel.py`](../python/tests/test_otel.py) against a real receipt bundle.
- **Follow-ups:** emit tool I/O as OTel **events** (`gen_ai` events) and the proof/checkpoint as a
  span link; a real OTLP exporter (gated on the `otel` extra); and align with SOTA-4's existing
  SIEM/OTel *export* so capture and export share one schema. Honor `OTEL_SEMCONV_STABILITY_OPT_IN`
  for dual-emission when the agent-span conventions churn.
