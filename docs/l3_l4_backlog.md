# L3/L4 Backlog

This backlog covers the lower layers that belong inside `clay-seal-receipts`, starting from **L4 evidence/receipts** and then moving down into **L3 decision semantics and stateful authority context**.

This document is intentionally detailed. It is meant to guide implementation sequencing, scoping decisions, and division of responsibility with any partner or collaborator working on upper-layer identity and delegation primitives.

## Scope

This backlog is for work that belongs inside `clay-seal-receipts`.

It **does** include:

- evidence-grade receipt objects
- decision result semantics
- authority versioning
- session and execution context references
- obligations and approval-state representation
- budget metadata and budget-effect recording
- stateful authorization context references
- replayable verification and auditability
- verifier UX and API surfaces for the above

It **does not** include:

- provider-side model attestation internals
- prompt provenance beyond references or commitments
- SPIFFE issuer infrastructure
- external token exchange infrastructure
- provider-native secure enclaves
- universal subagent topology modeling
- hosted identity lifecycle management

## Layer definitions

For this backlog, use the following layer meanings:

- **L4**: Evidence, receipts, verification, auditability, replayability, trust semantics
- **L3**: Decision semantics, stateful authority context, obligations, approvals, budget-aware action control

## Design rules for this backlog

1. Stay below the model-provider boundary.
2. Standardize authority-bearing actions, not internal cognition.
3. Prefer explicit references over speculative semantics.
4. Record more context than we immediately enforce if the data is cheap and durable.
5. Add structured metadata before building heavy orchestration.
6. Keep default behavior simple and backward-compatible where possible.
7. Make every new concept appear in receipts and verifier output.

## Status markers

Use these markers on backlog and roadmap items so parallel agents avoid duplicate work:

| Marker | Meaning |
|--------|---------|
| `[ ]` | Not started |
| `[>]` | **Being worked on** — do not pick up |
| `[~]` | Partial / in progress |
| `[x]` | Done |

When you start an item, change it to `[>]` and add your track name in the parallel-tracks table. When finished, mark `[x]` and remove the in-progress flag.

## Current status

**Last updated:** 2026-06-19

### Coordination convention

When an agent actively takes a backlog item, mark it in this document immediately so other contributors do not pick it up in parallel.

Use these status markers:

- `[ ]` not started
- `[~]` partially complete / landed in pieces
- `[>]` being worked on right now by a named owner
- `[x]` complete

For active items, include an owner note inline, for example:

- `### L3-7: Add budget effect recording [>] *(being worked on — codex/lower-layers)*`
- `### X-4: Documentation refresh [>] *(being worked on — claude/evidence-plane)*`

### Parallel tracks

| Track | Owner | Items |
|-------|-------|-------|
| **L3 foundation** | done | L3-1, L3-3, L3-5, L3-9, X-4, X-5 `[x]` |
| **Compat & outcomes** | done | X-1 `[x]`, L3-2 `[x]` |
| **First sprint** | paused | *(other agent on different work)* |
| **Evidence & verifier** | done | L4-1 `[x]`, L4-5–L4-8 `[x]`, X-2 `[x]`, X-3 |
| **Lineage & replay** | done | L4-3, L4-4, L3-6, L3-12, L3-13, L3-14 |
| **Decision & approval** | done | L3-7 `[x]`, L3-4/8 `[x]`, bounded_auto execution gate |
| **Roadmap M1** | done | `policy_range_v3` required-field in-circuit `[x]` |
| **Roadmap M3** | stub | TEE quote ingestion stub |

### Already implemented in the repo

- `ExecutionProof`, `AuditChain`, `ReceiptBundle`, MCP tool-call receipts
- verification APIs (`verify_receipt_bundle`, HTTP `/v1/verify`)
- `policy_satisfied`, `policy_violations`, `recommended_action`
- `DecisionOutcome`, `authority_version`, `session_id`, `obligations`
- `DecisionResult` embedded in `RunResult` / MCP `ToolCallResult`; obligation rollup on `evidence` (L3-1, L3-5)
- `ExecutionContext` / `AuthorityContext` with dict compat (L3-3) — [execution_context.md](execution_context.md)
- Structured action classification on receipts and audit (L3-9)
- L3 foundation test matrix: `test_l3_foundation.py` (X-5)
- `AssuranceLevel` / `assurance` block on receipts (L4-6)
- Structured verifier `issues[]` with error codes (L4-5)
- `explain_receipt_bundle` + `arctl explain` (L4-7)
- `compact_receipt_bundle`, `export_bundle_for_audience`, `arctl format-bundle` (L4-8 partial)
- Redaction paths for session, actor, budget, evidence refs, v2 sections (X-2)
- `RunResult` / `ToolCallResult` backward-compat shims + `to_legacy_dict()` (X-1)
- Portable `DecisionOutcome` vocabulary + outcome path tests (L3-2)
- `docs/decision_model.md` — L3 decision/budget/approval/context (X-4 partial)
- `AuthorityLineage`, `SessionHandoffArtifact`, `CapabilityBudget`, `EvidenceRefs` (L4-3/4, L3-6, L3-13)
- `rebuild_context_from_bundle`, `compare_stored_decision`, `compare_budget_effects`, `re_evaluate_policy_decision` (L3-14)
- `DecisionRecord`, `EvidenceSummary`, receipt `evidence` block (L4-2)
- `PolicyEngine` / `YamlPolicyEngine`, reservation callback (L3-15, L3-8)
- `ApprovalMetadata`, approval state inference, envelope signature verification
- `re_evaluate_policy_decision`, `auditor_evidence_summary` (L3-14, L4-8)
- Ed25519 `sign_bundle` / audit record signing (evidence plane)
- ZK output+policy commitment binding in the Halo2 policy proof (`commitment_to_field`); tampering a receipt's `output_hash`/`policy_commitment` now fails verification (evidence plane)
- Signed audit Merkle checkpoint (`AuditChain.signed_checkpoint` / `verify_checkpoint`) + per-record signature verification (`verify_signatures`) (evidence plane)
- Receipt bundle **v2** schema, v1 migration, NDJSON export (L4-1, L4-8)
- Halo2 **`policy_range_v3`**: in-circuit required-field presence mask (Roadmap M1)

### Still missing

- Full budget **ledger** integration (reservation callback is a hook only; no external ledger)
- Real TEE quote verification (M3 stub only)
- Research/commercial roadmap items (recursive SNARK, X.509 OIDs, EU AI Act export)

### Roadmap M1: Required-field constraints in-circuit `[x]`

Halo2 circuit **`policy_range_v3`** in `crates/clay-seal-receipts-policy-circuit`:

- Proves numeric range + output/policy binding + required-field presence bitmask (up to 8 fields)
- Envelope fields: `required_fields`, `public_inputs[3]` = `required_presence_mask`
- CLI: `prove-policy --required-field … --output-json …`
- Python `prove_structural_policy` passes policy `output_schema.required` automatically

## Backlog overview

### L4 themes

- receipt schema maturity
- verification and replay semantics
- assurance and trust vocabularies
- session handoff and authority lineage
- evidence export and compliance surfaces

### L3 themes

- decision-result model
- decision context object
- approval and obligation semantics
- budget semantics
- action reservations and compensation metadata
- stateful authority evaluation interfaces

## Suggested implementation order

1. Finish L4 receipt and verification schema maturity
2. Introduce first-class decision-result objects
3. Add first-class execution and authority context objects
4. Add budget metadata and budget-effect recording
5. Add session handoff and authority-transition artifacts
6. Add replay and explainability tools
7. Add minimal approval-state semantics
8. Add optional workflow integration seams

## L4 backlog: evidence and receipts

### L4-1: Formalize the receipt bundle schema v2 `[x]`

Implemented in `receipt_schema.py` and `export.py`. Default export is v2; `migrate_v1_to_v2()` upgrades stored v1 bundles. Verifier accepts both schemas.

Goal:

- make receipts the canonical evidence artifact for externally meaningful actions

Tasks:

- Define an internal schema note for `clay-seal-receipts.receipt-bundle.v2`
- Keep v1 loading support
- Add explicit `decision` block as a required section
- Add explicit `authority` block as a required section
- Add explicit `evidence` block as a required section
- Decide what fields remain duplicated between `execution_proof` and `decision`
- Decide whether `policy_violations` remains top-level or moves under `decision`
- Add schema version migration tests

Proposed new bundle sections:

- `decision`
- `authority`
- `evidence`
- `session`
- `budget` (optional)
- `approval` (optional)

Acceptance criteria:

- a v2 bundle can be serialized and verified
- the verifier can still read v1 bundles
- the repo has explicit tests for v1/v2 compatibility

Files likely touched:

- [export.py](../agentauth/receipts/export.py)
- [verifier_server.py](../agentauth/receipts/verifier_server.py)
- tests under [python/tests](../python/tests)

### L4-2: Split evidence classes from decision classes `[x]`

`DecisionRecord`, `AuthorityContextRef`, `EvidenceSummary` in `evidence.py`. Receipt `evidence` block at export; `ExecutionProof` unchanged.

Goal:

- stop overloading `ExecutionProof` with every future concept

Tasks:

- Introduce `DecisionRecord` dataclass
- Introduce `AuthorityContextRef` dataclass
- Introduce `EvidenceSummary` dataclass
- Decide whether `RunResult` should embed these directly or only at export time
- Keep `ExecutionProof` focused on proof-bound claims and cryptographic material

Acceptance criteria:

- decision semantics can evolve without destabilizing proof serialization
- the internal model is easier to reason about than a single giant proof object

### L4-3: Add authority lineage and transition evidence `[x]`

Implemented in `agentauth/receipts/lineage.py`. Optional `lineage` block on receipt export; verifier cross-checks against `authority` block.

### L4-4: Add session handoff artifact `[x]`

Implemented in `agentauth/receipts/handoff.py`. Optional `handoff` block on export; standalone artifact roundtrip tested.

### L4-5: Add richer verifier output `[x]`

Implemented in `agentauth/receipts/verification.py` and `export.verify_receipt_bundle`. HTTP verifier exposes `issues`, `assurance`, `decision`.

### L4-6: Add assurance summary surface `[x]`

Implemented in `agentauth/receipts/assurance.py`. Emitted on receipts and verifier responses.

### L4-7: Add replay and explainability report format `[x]`

Implemented in `agentauth/receipts/explain.py`. CLI: `arctl explain <bundle.json>`.

### L4-8: Add evidence export modes `[x]`

- [x] compact export (`compact_receipt_bundle`, `arctl format-bundle --compact`)
- [x] redacted export (`arctl format-bundle --redacted`, existing `arctl redact`)
- [x] evidence summary export for auditors (`auditor_evidence_summary`, `arctl audit-summary`)
- [x] NDJSON receipt exports (`write_receipts_ndjson`, `arctl export-ndjson`)

### L3-12: Add authority transition reasons `[x]`

## L3 backlog: decision semantics and stateful authority

### L3-1: Introduce a first-class `DecisionResult` `[x]`

`DecisionResult` carries outcome, violations, obligations, approval, budget effects, authority/session binding. Embedded in `RunResult` and MCP `ToolCallResult` with legacy shims (X-1).

### L3-2: Define a portable decision outcome vocabulary `[x]`

`DecisionOutcome` enum with `supported_values()`; all wrapper/MCP paths set outcome intentionally; tests for allow/deny/allow_with_obligations; `STANDARD_OBLIGATION_TYPES` documented in `decision.py`.

### L3-3: Add `ExecutionContext` / `AuthorityContext` `[x]`

Structured context dataclasses; `AgentWrapper.record()` accepts `ExecutionContext` or legacy dict. Documented in [execution_context.md](execution_context.md).

### L3-4: Add approval-state representation `[x]`

`ApprovalState`, `ApprovalMetadata`, `infer_approval_state()`, wired through `AgentWrapper.record()`.

### L3-5: Add obligation model `[x]`

Structured `Obligation` with summary helpers; `STANDARD_OBLIGATION_TYPES`; rollup on `evidence.obligations`; verifier cross-checks against `decision.obligations`.

### L3-6: Add budget metadata model `[x]`

Read-only `CapabilityBudget` in `agentauth/receipts/budget.py`. Optional `budgets[]` on receipt export.

### L3-7: Add budget effect recording `[x]`

`BudgetEffect`, `BudgetEffectSummary`, `DecisionResult.budget_section()`. v2 `budget` export includes `effects` + `summary`; verifier cross-checks; explain/auditor/replay surfaces; `compare_budget_effects()`. `bounded_auto` mode applies `can_execute()` gate.

### L3-8: Add reservation-required decision path `[x]`

`DecisionOutcome.BUDGET_RESERVATION_REQUIRED`, `ReservationResult`, `ReservationCallback` on `AgentWrapper.record()`. Default no-op hook.

### L3-9: Add action classification `[x]`

`ActionDescriptor` with category, resource ref, side effect level on receipts, audit records, and MCP tool calls.

### L3-10: Add touched-resource tracking `[x]`

On `ExecutionContext`; MCP and wrapper context dicts populate `touched_resources`.

### L3-11: Add authority-bearing actor references `[x]`

`ActorRef` on `AuthorityContext`; full authority dict roundtrip in wrapper `record()`.

### L3-13: Add state snapshot references `[x]`

`EvidenceRefs` in `agentauth/receipts/evidence_refs.py`. Optional `evidence_refs` block on export.

### L3-14: Add replay-oriented APIs `[x]`

`rebuild_context_from_bundle`, `compare_stored_decision`, `re_evaluate_policy_decision` in `replay.py`. CLI: `arctl replay-check`. `AuthorityTransitionReason` enum in `lineage.py`.

### L3-15: Add minimal policy-engine abstraction seam `[x]`

`PolicyEngine` protocol + `YamlPolicyEngine` in `policy_engine.py`. `AgentWrapper` accepts optional custom engine.

## Cross-cutting backlog

### X-1: Backward compatibility plan `[x]`

`RunResult` / `ToolCallResult` property shims, `to_legacy_dict()`, and [backward_compatibility.md](backward_compatibility.md).

### X-2: Redaction support for all new fields `[x]`

`DEFAULT_REDACT_PATHS` covers v1/v2 session, approval, budget, evidence, and full `output`.

### X-3: CLI and verifier parity `[x]`

- HTTP verifier and `verify-bundle` expose `issues`, `assurance`, `decision`, `signatures`
- `arctl explain`, `format-bundle`, `audit-summary`, `replay-check`

### X-4: Documentation refresh `[x]`

Partner + architecture docs; [decision_model.md](decision_model.md), [execution_context.md](execution_context.md), [backward_compatibility.md](backward_compatibility.md), [receipt_bundle_v2.md](receipt_bundle_v2.md).

### X-5: Test matrix expansion `[x]`

`test_l3_foundation.py` plus existing serialization/verifier/replay tests cover L3 dataclasses, receipt roundtrips, approval/budget/action/lineage paths.

## Milestone proposal

### Milestone L4-A: Receipt maturity

Includes:

- L4-1
- L4-2
- L4-5
- X-1
- X-3
- X-5

Outcome:

- stable receipt and verifier semantics

### Milestone L3-A: Decision object foundation

Includes:

- L3-1
- L3-2
- L3-3
- L3-5
- L3-9

Outcome:

- first-class decision semantics and context representation

### Milestone L3-B: Budget and approval semantics

Includes:

- L3-4
- L3-6
- L3-7
- L3-8
- X-2

Outcome:

- receipts can represent approval and budget-aware decisions

### Milestone L4-B: Lineage and replay

Includes:

- L4-3
- L4-4
- L4-7
- L3-12
- L3-13
- L3-14

Outcome:

- authority transition evidence and replay-ready artifacts

### Milestone L3-C: Integration seam

Includes:

- L3-10
- L3-11
- L3-15
- X-4

Outcome:

- a clean lower-layer runtime model that can connect to upper-layer identity and delegation systems

## Recommended first sprint

The best first sprint is:

- L4-1 formal receipt v2 plan
- L3-1 `DecisionResult`
- L3-3 `ExecutionContext` / `AuthorityContext`
- L3-9 structured action metadata
- X-5 focused test expansion

Reason:

- these tasks improve the architecture immediately
- they avoid overcommitting to budgets or approval orchestration too early
- they create stable lower-layer contracts that later L1/L2 work can plug into

## Questions to keep open while implementing

- Should `session_id` be opaque or structured?
- Should `authority_version` be enough, or do we also need a stable `authority_id` immediately?
- Which receipt fields are required versus optional in v2?
- Should obligations stay implementation-specific longer, or standardize early?
- How much budget structure belongs in the repo before a true ledger exists?
- How much approval structure belongs in the repo before workflow integration exists?
- Should handoff artifacts live as standalone files or nested receipt data?

## Definition of done for L4/L3 foundation

The L4/L3 foundation is in a good place when:

- receipts have a stable structure for decisions, authority, and evidence
- non-binary outcomes are first-class
- authority/session lineage is visible
- obligations and approval state are representable
- budgets are at least referenceable and effect-recordable
- the verifier can explain lower-layer semantics cleanly
- the design still avoids taking on provider-side attestation internals
