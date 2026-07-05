# Architecture

Agent Receipts sits **above** OAuth 2.1 / MCP and **below** application code. It does not replace identity providers or tool authorization; it adds verifiable execution receipts.

## Layer 0 — Use existing infrastructure

| Concern | Technology |
|---------|------------|
| Agent auth & tool access | OAuth 2.1, MCP |
| ZK inference (small models) | EZKL, zkPyTorch |
| ZK proof system | Halo2 (recursive composition) |
| Large-model inference attestation | Intel TDX, AMD SEV, NVIDIA confidential computing |
| Audit persistence | Hash-chained log (SQLite local, object store cloud) |

No blockchain, consensus, or gas fees.

## Layer 1 — Core objects

### AgentCertificate

Binds in one artifact:

- `agent_id`
- `model_provenance_hash` — hash of weights + version metadata
- `policy_commitment` — hash of canonical policy document
- `principal` — human/org hierarchy and scope
- validity period + issuer signature (PKI later)

### PolicyDocument

Formal constraints compiled to software checks today, arithmetic circuits later.

v1 tiers (see [policy_language.md](policy_language.md)):

- **Structural** — numeric ranges, required fields
- **Schema** — typed output shape
- **Tool trace** — bounded-window tool calls authorized by capability tokens
- **Semantic (approx)** — blocklists / length caps only with weakened guarantees

### ExecutionProof

Per consequential action:

- Inference attestation (ZK or TEE quote)
- Policy conformance attestation
- Certificate + context + output hashes
- Single verification entry point for callers

### DecisionResult

Per consequential action, Agent Receipts now also tracks an explicit lower-layer decision object:

- decision outcome
- policy satisfaction
- violations
- obligations
- recommended action
- authority version
- session identifier

This is the main seam between static authorization and richer stateful authority control. See [decision_model.md](decision_model.md) for approval, obligations, budget effects, and execution gates. Migration notes: [backward_compatibility.md](backward_compatibility.md).

### ExecutionContext

Execution context captures the externally meaningful runtime boundary for a consequential action:

- structured action metadata
- authority context
- input reference
- touched resources
- optional authorization transport metadata

The goal is to standardize authority-bearing actions and evidence boundaries without standardizing internal agent cognition or topology. See [execution_context.md](execution_context.md).

## Layer 2 — Circuits (research core)

Two composed circuits, one verifier-facing proof:

1. **Inference** — private weights/input → public output (EZKL path)
2. **Policy** — private output + policy → public `policy_satisfied` (**novel**)

**TEE hybrid:** TEE attests inference; ZK proves policy on attested output. Same `ExecutionProof` envelope.

## Layer 3 — Authority hierarchy

```
Root Model Authority (future third-party)
        ↓
Operator Authority (enterprise issuer)
        ↓
Agent Instance (deployment certificate)
        ↓
Delegated Agent (scope can only decrease)
```

v0 uses operator-issued dev certificates.

## Layer 4 — Decision and evidence layer

This is where `agent-receipts` focuses most of its value:

- `DecisionResult` / `DecisionRecord` for non-binary outcomes
- `ExecutionContext` for authority-aware action semantics
- `ExecutionProof` for cryptographic or operator-signed evidence (proof bytes only)
- `EvidenceSummary` + `assurance` for honest trust tiers without overloading the proof object
- `ReceiptBundle` with `decision`, `authority`, `action`, `evidence`, and `assurance` blocks
- `AuditChain` for append-only lineage
- `PolicyEngine` seam (default: `YamlPolicyEngine`) for future OPA/Cedar adapters
- `ReservationCallback` hook for budget reservation decisions (`budget_reservation_required`)

Verifier surfaces: `arctl verify-bundle`, `arctl explain`, HTTP `POST /v1/verify` with structured `issues[]`.

## Layer 5 — Audit chain persistence

Append-only records: `execution_proof_hash`, action, authorization context, `prev_hash`, `record_hash`. Tampering breaks the tail.

## Layer 6 — Developer interface

Python `AgentWrapper` + `Policy.from_yaml` + `ReceiptedMcpGateway` for MCP tools. Modes:

| Mode | Behavior |
|------|----------|
| `shadow` | Log proofs; no crypto verification latency |
| `recommend` | Surface abstain recommendations on violation |
| `bounded_auto` | Force abstain output on policy violation |

Open-source SDK; paid cloud for PKI, verification keys, compliance exports (future).
