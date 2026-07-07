# Evidence-Plane SOTA Backlog

Derived from [state_of_the_art.md](state_of_the_art.md). This backlog turns the gap analysis
against the state of the art into actionable items for the **cryptographic evidence plane**
(verifiable inference, proof systems, transparency log, attestation, agentic-commerce binding,
compliance). It complements [l3_l4_backlog.md](l3_l4_backlog.md) (L3 decision semantics / L4
receipt schema) — those items are mostly done; these close the distance to SOTA.

**Last updated:** 2026-06-20

## Status markers

| Marker | Meaning |
|--------|---------|
| `[ ]` | Not started |
| `[>]` | **Being worked on** — do not pick up |
| `[~]` | Partial / in progress |
| `[x]` | Done |

Coordination convention (same as the L3/L4 backlog): when you take an item, change it to `[>]`,
add your track name inline, and register it in the parallel-tracks table. Mark `[x]` when done.

## Parallel tracks

| Track | Owner | Items |
|-------|-------|-------|
| **Evidence plane** | claude/evidence-plane | SOTA-1 `[x]` |
| **Assurance taxonomy** | codex/evidence-plane | SOTA-3 `[x]` |
| **Compliance export** | codex/evidence-plane | SOTA-4 `[x]` |
| **TEE attestation** | codex/evidence-plane | SOTA-2 `[x]` |
| **Witness co-signing** | claude/evidence-plane | SOTA-5 `[x]` |
| **Mandate binding** | codex/evidence-plane | SOTA-6 `[x]` |
| **Session aggregation** | codex/evidence-plane | SOTA-7 `[x]` |
| **Recursive composition** | codex/evidence-plane | SOTA-10 `[x]` |
| **zkVM inference** | claude/evidence-plane | SOTA-8 `[x]` |
| **Confidential compliance** | claude/evidence-plane | SOTA-9 `[x]` |

## Prioritization

Items are ordered by **(credibility gained × differentiation) ÷ effort**. Tier 1 is the
recommended first sprint: high-credibility, mostly in-repo, low cryptographic risk.

| Tier | Items | Theme |
|------|-------|-------|
| **Tier 1 — credibility sprint** | SOTA-1, SOTA-2, SOTA-3, SOTA-4 | CT-parity log, honest attestation, standards alignment, compliance value |
| **Tier 2 — differentiation** | SOTA-5, SOTA-6, SOTA-7 | witness anti-equivocation, mandate binding, session aggregation |
| **Tier 3 — frontier** | SOTA-8, SOTA-9, SOTA-10 | modern zkML, confidential compliance, recursive composition |

---

## Tier 1 — credibility sprint

### SOTA-1: Merkle inclusion + consistency proofs `[x]` *(done — claude/evidence-plane)*

**Pillar:** transparency log. **Effort:** S. **Risk:** low. **Source:** SOTA roadmap #1; CT/RFC 6962, Rekor.

Goal: bring the audit log to Certificate-Transparency parity so a single receipt can be proven
to be in the log, and a log can be proven append-only between checkpoints.

Tasks:
- Add `inclusion_proof(record_hash) -> [Merkle path]` and `verify_inclusion(record_hash, proof, checkpoint)` to `AuditChain` (build over the leaves already hashed by `merkle_root`).
- Add `consistency_proof(old_size, new_size)` and `verify_consistency(old_checkpoint, new_checkpoint, proof)` (RFC 6962 §2.1.2 algorithm).
- Surface both in `arctl` (e.g. `arctl audit-prove --record <id>`, `arctl audit-consistency`).
- Bundle option: embed an inclusion proof + checkpoint reference in the receipt bundle.

Acceptance criteria:
- given a receipt and a signed checkpoint, a verifier confirms inclusion without re-hashing the whole chain
- consistency proof rejects any rewrite of an earlier record (closes the bare-hash-chain gap for non-tip entries)
- tests for inclusion accept/reject and consistency accept/reject

Files likely touched: `agentauth/receipts/audit.py`, `cli.py`, `export.py`, `python/tests/test_signing.py` (or new `test_transparency.py`).

### SOTA-2: Honest TEE attestation path (RATS/EAT) `[x]` *(codex/evidence-plane)*

**Pillar:** verifiable inference / attestation. **Effort:** M. **Risk:** med. **Source:** SOTA roadmap #2; RFC 9334, NVIDIA GPU-CC, Intel TDX, AWS Nitro.

Goal: make the `tee_*` assurance tier real so LLM-scale "ran on model M" provenance has an honest
mechanism that does not require ZK-proving a transformer.

Tasks:
- Implement one real quote verifier (recommend **AWS Nitro Enclaves** attestation document, or **Intel TDX** quote) replacing the M3 stub.
- Express the verified result as a RATS **Entity Attestation Token (EAT)**-shaped claim set; map Attester/Verifier/Relying-Party roles onto our prove/verify/consumer flow.
- Wire to `AssuranceLevel.tee_attested` (real) vs `tee_hybrid_claimed` (asserted); verifier surfaces which.

Acceptance criteria:
- a real (or recorded fixture) TEE quote verifies and yields `tee_attested`; a tampered/absent quote does not
- assurance output distinguishes verified-TEE from claimed-TEE
- docs: how the TEE leg substitutes for ZK inference at LLM scale

Files likely touched: `crates/clay-seal-receipts-composed/src/inference.rs` (or new `tee.rs`), `agentauth/receipts/tee.py`, `assurance.py`, `verification.py`, `docs/trust_model.md`.

### SOTA-3: RATS/EAT alignment + published assurance taxonomy `[x]` *(codex/evidence-plane)*

**Pillar:** attestation / standards. **Effort:** S–M. **Risk:** low. **Source:** SOTA roadmap #3.

Goal: re-express receipts and assurance tiers in standard attestation vocabulary so any
attestation-aware verifier understands us, and publish an ordered trust taxonomy (the field lacks one).

Tasks:
- Map `AssuranceLevel` to an ordered taxonomy: `declared → signed → sender_constrained → workload_attested → tee_attested → zk_policy_proved → zk_execution_proved`.
- Document the RATS role mapping (prover = Attester, verifier = Verifier, evidence consumer = Relying Party) and which receipt fields are EAT claims.
- Emit the tier ordinal in verifier output so consumers can threshold ("require ≥ tee_attested").

Acceptance criteria:
- a single ordered enum/scale is used across receipts and verifier responses
- a spec note (`docs/assurance_taxonomy.md`) defines each tier + its RATS/EAT mapping
- tests assert tier ordering and threshold checks

Files likely touched: `agentauth/receipts/assurance.py`, `verification.py`, `verifier_server.py`, new `docs/assurance_taxonomy.md`.

### SOTA-4: Compliance field mapping + SIEM export `[x]` *(codex/evidence-plane)*

**Pillar:** governance. **Effort:** M. **Risk:** low (no crypto). **Source:** SOTA roadmap #4; EU AI Act / NIST AI RMF audit-field requirements.

Goal: turn receipts into mapped, audit-grade evidence that compliance teams and SIEMs consume directly.

Tasks:
- Define a mapping from receipt fields to control families (EU AI Act logging duties, SOC 2 CC-series, ISO 27001) — a YAML/JSON crosswalk + generator.
- Add a SIEM-native export (OpenTelemetry log records / ECS / CEF) alongside the existing NDJSON.
- Extend `arctl audit-summary` / `export-bundle-for-audience` with a `--profile eu-ai-act|soc2|iso27001` option.

Acceptance criteria:
- one mapped export per supported profile, with required fields (model/system version, policy ref, inputs/sources commitment, machine+human reasoning, integrity protection) present
- a SIEM ingest fixture parses the export
- tests for each profile's required-field completeness

Files likely touched: `agentauth/receipts/export.py`, `explain.py`, `cli.py`, new `docs/compliance_mapping.md`, new `compliance/` crosswalk files.

---

## Tier 2 — differentiation

### SOTA-5: External witness co-signing of checkpoints `[x]` *(done — claude/evidence-plane)*

**Pillar:** transparency log. **Effort:** M. **Risk:** med. **Source:** SOTA roadmap #5; Rekor witness/gossip model. **Depends on:** SOTA-1.

Goal: defeat log split-view/equivocation (a malicious log showing different histories to different
parties) by letting independent witnesses co-sign checkpoints.

Tasks:
- Define a witness protocol: a witness verifies a consistency proof from its last seen checkpoint, then co-signs the new checkpoint.
- Add `add_witness_cosignature(checkpoint, witness_key)` and `verify_checkpoint(..., required_witnesses=N)`.
- Provide a minimal reference witness (HTTP endpoint) and a verifier policy "require ≥ K witness signatures."

Acceptance criteria:
- a checkpoint carries multiple independent signatures; verification can require a quorum
- a witness refuses to co-sign a checkpoint that is not consistent with what it last saw (equivocation caught)
- tests for co-sign accept, quorum threshold, and equivocation rejection

Files likely touched: `agentauth/receipts/audit.py`, `signing.py`, `verifier_server.py`, new `docs/witnessing.md`.

### SOTA-6: Receipt ⇄ signed Mandate binding (AP2-aligned) `[x]`

**Pillar:** decision / agentic commerce. **Effort:** M. **Risk:** low–med. **Source:** SOTA roadmap #6; AP2 Mandates, AuthZEN. **Relates to:** L3 budget/authority work.

Goal: bind a receipt to the signed mandate (spend limit, allowed resources, validity window) that
authorized the action, and prove the action stayed within it — riding the agentic-commerce wave.

Tasks:
- Define a `Mandate` object (signed: spend/scope/validity), reusing `signing.py` and `CapabilityBudget`.
- On receipt creation, reference the mandate id + commitment; on verify, check the action/budget effect is within the mandate.
- Optional ZK: prove "within mandate limit" without revealing the exact amount (links to SOTA-9).

Acceptance criteria:
- a receipt references and verifies against its authorizing mandate; an out-of-mandate action is flagged
- mandate signature verified via `signing.verify`
- tests: in-mandate allow, over-limit reject, expired-mandate reject

Files likely touched: new `agentauth/receipts/mandate.py`, `decision.py`, `budget.py`, `export.py`, `verification.py`.

### SOTA-7: Session-proof aggregation via folding (Nova) `[x]` *(codex/evidence-plane)*

**Pillar:** proof systems. **Effort:** L. **Risk:** med–high. **Source:** SOTA roadmap #7; Nova/MicroNova folding. Realizes the "compress 2,500 receipts" origin goal.

Goal: fold many per-action policy proofs into one session proof to cut verification + storage cost.

Tasks:
- Evaluate a folding library (Nova / a maintained successor) vs an SP1 recursion path for aggregating `policy_range_v3` instances.
- Prototype: fold N policy proofs → one proof verifying "all N satisfied range+binding+required-fields."
- Define a session-proof envelope and CLI (`prove-session`, `verify-session`).

Acceptance criteria:
- one aggregate proof verifies N actions; verify time grows sub-linearly vs N separate proofs
- benchmark vs N independent verifications (use the new `benchmarks` extra)

Files likely touched: `crates/clay-seal-receipts-policy-circuit`, new `crates/clay-seal-receipts-fold` (or SP1 integration), `compose.rs`, `benchmarks/`.

---

## Tier 3 — frontier

### SOTA-8: Modernize the inference path (zkVM / compiler / opML) `[x]` *(done — claude/evidence-plane)*

**Pillar:** verifiable inference. **Effort:** L. **Risk:** high. **Source:** SOTA roadmap #8; zkPyTorch (ePrint 2025/535), SP1, RISC Zero, opML.

Goal: move off raw EZKL for the small policy/classifier heads, and adopt optimistic+ZK for larger
models, so the model-provenance leg reflects the current state of the art.

Tasks:
- Spike: prove the fraud head via an **SP1/RISC Zero zkVM** program (no per-model setup) and via a **zkPyTorch-class** compiler; compare proof size/time/maintainability vs current EZKL.
- For larger models, design an **opML-style** optimistic path with ZK dispute resolution.
- Decide the routing rule: ZK for small heads, TEE (SOTA-2) for LLM-scale, opML for mid.

Acceptance criteria:
- a working non-EZKL inference proof for the fraud head with a documented cost comparison
- a written decision record on ZK-vs-TEE-vs-opML routing by model size

Files likely touched: `crates/clay-seal-receipts-composed/src/inference.rs`, `circuits/`, `scripts/`, `docs/inference_and_composition.md`.

### SOTA-9: Confidential compliance proofs (policy on `y` without revealing `y`) `[x]` *(done — claude/evidence-plane)*

**Pillar:** verifiable inference / privacy. **Effort:** L. **Risk:** high. **Source:** SOTA roadmap #9; "Show Me You Comply Without Showing Me Anything" (arXiv 2510.26576).

Goal: the premium tier — prove a committed policy held over the output without disclosing the output,
for regulated/multi-party settings.

Tasks:
- Extend the policy circuit so the output is a private witness committed via `output_hash`, and the public statement is only "policy satisfied" (we already bind `output_commitment` — make the output itself in-circuit private rather than software-checked).
- Map to the paper's blueprint (Groth16/PLONK compliance proofs); define which policy classes are provable confidentially.

Acceptance criteria:
- a proof that "policy P held on the committed output" verifies without the verifier learning the output
- documented policy classes supported confidentially vs only in software

Files likely touched: `crates/clay-seal-receipts-policy-circuit/src/circuit.rs`, `lib.rs`, `docs/trust_model.md`.

### SOTA-10: Recursive composition (single SNARK over inference ∪ policy) `[x]` *(codex/evidence-plane)*

**Pillar:** proof systems. **Effort:** L. **Risk:** high. **Source:** SOTA roadmap #10; repo roadmap M3 stretch. **Depends on:** SOTA-7/SOTA-8 groundwork.

Goal: replace the current *logical* composition (verify both sub-proofs + hash bindings) with one
recursive proof, so a verifier checks a single artifact.

Tasks:
- Recurse the EZKL inference proof and Halo2 policy proof into one proof (via folding or a zkVM wrapper).
- Preserve the existing binding semantics (output/policy/score) inside the recursion.

Acceptance criteria:
- a single `ComposedProofEnvelope` verifies inference+policy without separately checking each sub-proof
- binding guarantees preserved; tamper tests still fail

Files likely touched: `crates/clay-seal-receipts-composed/`, `crates/clay-seal-receipts-policy-circuit/`, `docs/inference_and_composition.md`.

---

## Tier 4 — combined-corpus standards alignment

From the whole-system review ([combined_corpus_sota_review.md](combined_corpus_sota_review.md)):
the SOTA-1…10 building blocks are strong, but several use bespoke encodings where the field
converged on standards in the last year, and two base-layer primitives have faster successors.
These items adopt the standard envelopes / better primitives. Tracks: claude/evidence-plane.

### SOTA-11: SCITT + COSE-Receipt envelope for receipts/log/proofs `[x]`

**Status:** implemented in `agentauth/receipts/scitt.py`, `scitt_bundle.py`, and
[`docs/scitt.md`](scitt.md) — COSE Signed Statements, COSE Receipts (RFC 9162 inclusion +
consistency), transparent statements, `TransparencyService`, live `AuditChain` as TS, bundle
`scitt` section (CBOR canonical artifact, HPKE confidential payloads), and
`verify_receipt_bundle()` SCITT validation. Tests: `test_scitt.py`, `test_scitt_bundle.py`,
`test_hpke.py`.


**Pillar:** receipts / transparency. **Effort:** M–L. **Risk:** med. **Source:** corpus review §A; SCITT `draft-ietf-scitt-architecture-22`, COSE Receipts `draft-ietf-cose-merkle-tree-proofs-18`.

IETF SCITT standardizes almost exactly what we built by hand: a *Signed Statement* (a claim) becomes a *Transparent Statement* once a *Transparency Service* registers it and returns a *Receipt* — a COSE-signed Merkle inclusion proof carried in the COSE envelope. The proof format is COSE Receipts, CBOR-encoded, with RFC 9162 as the worked example — i.e. the exact inclusion/consistency proofs from SOTA-1, in the standard wire format. Adopting it means re-expressing our receipt bundle as COSE_Sign1/CBOR, our audit log as a Transparency Service, and our SOTA-1 proof as the embedded COSE Receipt (over the RFC 6962 root added in `c2sp.py`). Research focus: read the SCITT architecture + COSE-receipts drafts, look at the `ietf-wg-scitt` reference code and `go-cose`/`pycose` libraries, and decide whether to keep JSON as a projection of the canonical COSE form. This single move unifies receipts (L4) + transparency log (SOTA-1/5) + assurance tiers and folds in finding B2 (SOTA-14).

### SOTA-12: SP1/Plonky3 zkVM port (carries Poseidon2) `[x]`

**Status:** guest + host CLI in [`crates/clay-seal-receipts-sp1/`](../crates/clay-seal-receipts-sp1/) (detached
workspace); `prove_inference_sp1` / `verify_inference_sp1` in composed crate; `--backend sp1` on
main CLI and Python; build/benchmark scripts pin `sp1-sdk` 5.2.4. Measured SP1 prove times still
require a version-locked `sp1up` run — see [sp1_benchmark.md](sp1_benchmark.md).

**Pillar:** verifiable inference / proof systems. **Effort:** M. **Risk:** med. **Source:** corpus review §C/§D; SP1 (Plonky3), a16z zkvm-benchmarks. **Relates to:** SOTA-8.

SOTA-8 runs the inference leg on RISC Zero; 2026 benchmarks put SP1 (on Plonky3) at roughly 5× faster on CPU with the most complete precompile set — notably an ed25519 precompile directly relevant to us (proving our Ed25519-signed receipts/checkpoints inside a zkVM is far cheaper there). Research focus: port the fraud-head guest to SP1, run it against the a16z `zkvm-benchmarks` harness on our actual workload (not the marketing numbers — they're point-in-time), and measure prove time, proof size, and recursion/continuation support for the future session-aggregation path. The same migration makes Poseidon2/Monolith native (finding D — there is no Poseidon2 chip in our Halo2 stack, so it cannot be done standalone), since Plonky3 ships them. Deliverable: a measured RISC-Zero-vs-SP1 comparison on our guest plus a recommendation on whether Plonky3 also becomes the base for richer (non-range) policy circuits.

### SOTA-13: OpenTelemetry GenAI semantic-convention alignment `[x]` *(done — claude/evidence-plane)*

**Status:** `agentauth/receipts/otel.py` + converged `export_siem_otel()` in `compliance.py`
([docs/otel_genai_mapping.md](otel_genai_mapping.md)) — `gen_ai.*` attributes, tool I/O
**events**, OTLP/HTTP JSON shaping (`bundle_to_otlp_resource_logs`), optional
`send_otlp_logs` + `otel` extra. Tests: `test_otel.py`.


**Pillar:** governance / observability. **Effort:** S–M. **Risk:** low (no crypto). **Source:** corpus review §E; OTel GenAI semconv. **Relates to:** SOTA-4.

Our `execution_context` captures action/tool/authority evidence in a bespoke shape; the industry standard for agent traces is now OpenTelemetry's GenAI semantic conventions (tool-use events, reasoning spans, model/agent attributes), which 2026 observability writeups call table stakes. Our SOTA-4 SIEM/OTel export already leans this way, but aligning the *capture* schema — not just the export — means receipts drop into existing observability and SIEM pipelines without translation, and lets a receipt be emitted as a signed OTel log record. Research focus: read the OTel GenAI semconv spec, map each of our evidence/execution-context fields to the standard attribute names, identify gaps in either direction, and decide whether to adopt their attributes natively or maintain a crosswalk. Low crypto, high buyer value.

### SOTA-14: Tile-based static log export `[x]`

**Status:** implemented in `agentauth/receipts/tiles.py` +
`AuditChain.static_log_tiles(origin)` ([docs/tlog_tiles.md](tlog_tiles.md)) — C2SP tlog-tiles
hash tiles, entry bundles, signed checkpoint, CLI `export-tiles` / `verify-tiles`, and
third-party-style monitor verification via `verify_leaf_in_static_log`. Tree unification with
RFC 6962 is done; tests in `test_tiles.py`.


**Pillar:** transparency log. **Effort:** M. **Risk:** low–med. **Source:** corpus review §B2; C2SP `tlog-tiles` / `static-ct-api`, Sunlight. **Depends on:** SOTA-1; **folds into** SOTA-11.

SOTA-1 implemented classic *dynamic* RFC 6962; the ecosystem moved to the Static-CT API / C2SP `tlog-tiles` (the tree served as static, cacheable 256-entry tile files, no dynamic proof endpoints), and Let's Encrypt is shutting down its RFC 6962 logs on 2026-02-28. We already added the C2SP signed-note *checkpoint* + RFC 6962 root (`c2sp.py`); B2 is the remaining piece: serve the log as tiles and migrate our internal inclusion/consistency proofs onto the RFC 6962 hashing so the JSON and C2SP views share one tree (which is why this naturally folds into SOTA-11). Research focus: the C2SP `tlog-tiles` and `static-ct-api` specs, the Sunlight implementation, and Go's `mod/sumdb/tlog` tile layout.

### SOTA-15: WIMSE WIT/WPT + Transaction-Tokens-for-Agents envelopes `[x]` *(done — claude/evidence-plane)*

**Status:** `agentauth/receipts/wimse.py` + [docs/wimse_mapping.md](wimse_mapping.md) —
`issue_wit_from_mandate`, `build_wpt` / `verify_wpt`, `transaction_token_act_chain`,
`mandate_ref_from_envelope`. Tests: `test_wimse.py`.

**Pillar:** identity / authority (L1/L2/L3). **Effort:** M–L. **Risk:** med. **Source:** corpus review §F; [l1_l2_sota_assessment.md](l1_l2_sota_assessment.md); WIMSE drafts, `draft-oauth-transaction-tokens-for-agents`.

The L1/L2 mechanisms are already hardened (EdDSA, `cnf` key-binding, request-bound PoP, revocation, single-use challenges); what's left is standardizing the *wire format*. Our key-bound SVID + request-bound proof are bespoke versions of IETF WIMSE's Workload Identity Token (`draft-ietf-wimse-workload-creds`) and Workload Proof Token (`draft-ietf-wimse-wpt-01`); re-expressing them as WIT/WPT JWTs gives interop with MCP/A2A verifiers. Separately, Transaction-Tokens-for-Agents (`draft-oauth-transaction-tokens-for-agents`) defines an `act` call-chain that propagates identity+authorization through a trust domain — the missing link from L2 delegation to the L3/L4 receipt's authority lineage. Research focus: the three WIMSE drafts and the txn-token-for-agents draft, and how a receipt's lineage maps onto a txn-token `act` chain.

### SOTA-16: *Notarized Agents* reconciliation — additive borrows, not a pivot `[x]` *(done — claude/evidence-plane)*

**Status:** 16a–16e + positioning doc in [trust_model.md](trust_model.md). `owner_hpke_pk`
on mandates; HPKE recipient binding in `scitt_bundle`; `SignerRevocationRegistry` with log
integrated time in `audit.py`; `tool_witness.py`; `mandate_ref` indexing +
`arctl audit-by-mandate`; `witness_divergence` verification hook. Tests: `test_sota16.py`.

**Pillar:** research / evidence-plane hardening. **Effort:** S (research done) + S–M (selective implementation). **Risk:** low. **Source:** corpus review §G; [*Notarized Agents* / Sello](https://arxiv.org/abs/2606.04193) (arXiv 2606.04193, Jun 2026). **Relates to:** SOTA-9, SOTA-11, SOTA-15.

**Research verdict (done).** Sello's thesis is *trust-boundary inversion for observability*: the **called service** signs what it saw, HPKE-seals to the owner, and publishes ciphertext to a witness-cosigned Merkle log. Our thesis is *prove-then-log for compliance*: **ZK policy/inference proofs** plus SCITT transparency-service receipts. The paper compares against [agentreceipts.ai](https://agentreceipts.ai) (Jongerius — agent-signed W3C VCs), **not this repo**. We are **ahead** on the evidence plane (SOTA-9 confidential ZK, composed/zkVM inference, SCITT COSE receipts, CT-class log, tiles, witness cosigning). Sello is **ahead** on receiver-as-primary-signer narrative and token-indexed owner discovery. The models are **complementary** (§8.2 of the paper): self-reported traces vs witnessed tool calls vs our ZK compliance bundle — divergence between them is the anomaly signal.

**Do not implement:** wholesale Sello/Sello-as-primary-receipt, receiver-only signing in place of ZK proofs, or treating HPKE transport privacy as a substitute for SOTA-9 compliance privacy. Do not rebrand as "C2PA for agents."

#### Two confidentiality layers — keep both

| Layer | Mechanism | Hides what | From whom |
|-------|-----------|------------|-----------|
| **Compliance privacy** (SOTA-9) | ZK + Poseidon commitment | Output score `y` | Verifier checking policy |
| **Transport privacy** (SOTA-11) | HPKE seal on canonical CBOR | Full bundle body | Public log / passive observers |

Sello's P2 maps to our `scitt_bundle` HPKE path; SOTA-9 remains the differentiator Sello lacks.

#### Technical decisions to borrow (additive)

| # | Borrow from Sello | Our use | Effort | Depends on |
|---|-----------------|---------|--------|------------|
| **16a** | **`owner_hpke_pk` bound in the authorization token** (JWS claim, anti-substitution) | Services/MCP peers learn the HPKE recipient key from a **verified** mandate/SVID, not from agent-supplied bytes. Enables correct `confidential_recipient_public_key` on export without trust-the-agent. | S | **SOTA-15** (WIT/WPT or txn-token profile) |
| **16b** | **Log-integrated time for key revocation** | Witness and envelope-signer revocation uses the transparency log's integrated time, not signer-asserted timestamps in receipt bodies — bounds backdating after key compromise. | S | SOTA-5 witness registry |
| **16c** | **Optional tool-receiver co-signatures** (Signet-adjacent, not Sello-primary) | MCP/tool endpoint emits a separate COSE_Sign1 over `(action-input-hash, action-output-hash, mandate-ref)`; attached as `signatures[].role = "tool"` or linked SCITT signed statement. Does **not** replace operator ZK bundle. | M | SOTA-11 COSE helpers |
| **16d** | **Token-ref log indexing (P4-lite)** | Audit log index keyed by `SHA-256(mandate_bytes)` or SVID `jti` so an owner reconstructs a session from the log without trusting agent exports. | M | 16a, audit chain |
| **16e** | **Divergence verification hook** | Verifier flag when self-reported bundle claims a tool call but no matching tool co-sign / no log entry at that `token_ref`. Document as best-effort (suppression remains unsolvable). | S | 16c, 16d |
| **16f** | **HPKE suite interop note** (optional) | Sello uses ChaCha20-Poly1305; we implement AES-128-GCM (RFC 9180 §A.1). Add ChaCha suite only if we ingest/emit Sello envelopes — not required for our SCITT path. | S | — |

#### Tasks

- Document positioning + the two-layer confidentiality model in `docs/trust_model.md` (one section; distinguish from agentreceipts.ai by name).
- **16a:** Add `owner_hpke_pk` (base64url X25519) to the mandate/SVID profile; verifier rejects HPKE seal if pubkey ≠ token claim.
- **16b:** Extend witness/signer revocation tables with `revoked_at` compared against checkpoint integrated time in `audit.py` / `verify_checkpoint`.
- **16c:** Define a minimal `ToolWitnessEnvelope` (COSE_Sign1, hashes-only body) and wire optional verification into `verify_receipt_bundle`.
- **16d:** Add optional `mandate_ref` / `token_ref` header on audit records; CLI query `arctl audit-by-mandate --ref <hex>`.
- **16e:** Add verification issue code `witness_divergence` when bundle tool claims ⊄ co-signed witnesses.

#### Acceptance criteria

- positioning doc states clearly: **ZK compliance + SCITT log** is the moat; Sello borrows are **witness-layer add-ons**
- HPKE confidential export rejects recipient keys not bound in the verified mandate (16a)
- revoked witness/signer keys reject receipts whose log integrated time ≥ `revoked_at` (16b)
- at least one test: tool co-sign verifies independently of envelope signature (16c)
- owner can list audit records by mandate ref without re-parsing agent JSON (16d)
- SOTA-9 confidential proofs and SOTA-11 HPKE both remain enabled and documented as distinct layers

#### Files likely touched

`docs/trust_model.md`, `agentauth/receipts/mandate.py`, `agentauth/receipts/scitt_bundle.py`, `agentauth/receipts/audit.py`, `agentauth/receipts/verification.py`, `agentauth/receipts/export.py`, `python/tests/test_scitt_bundle.py`, new `python/tests/test_tool_witness.py` (16c).

**Mark `[x]`** when 16a–16b land (core hardening) and positioning doc is written; 16c–16e can follow as optional witness tier.

---

## Dependencies & sequencing

- **SOTA-5** builds on **SOTA-1** (consistency proofs are the witness protocol's input).
- **SOTA-9** builds on the binding from `policy_range_v3` and informs **SOTA-6**'s ZK option.
- **SOTA-10** is easiest after **SOTA-7** (folding) or **SOTA-8** (zkVM) groundwork exists.
- **SOTA-16** borrows from *Notarized Agents* are additive (16a–16f); **16a** chains to **SOTA-15** for token wire format.
- **SOTA-2** is the pragmatic unlock for LLM-scale provenance and is independent of the ZK items.

## Definition of done for the evidence-plane SOTA push

- the audit log is CT-class: inclusion + consistency proofs + (optional) external witnessing
- attestation tiers are honest, standards-aligned (RATS/EAT), and at least one real TEE verifier exists
- receipts map cleanly to compliance controls and SIEM ingestion
- the model-provenance leg has an honest non-stub path (TEE now; modern zkML/opML next)
- confidential and aggregated proofs exist as premium tiers
