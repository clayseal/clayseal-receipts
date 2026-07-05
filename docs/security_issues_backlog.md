# Security Issues Backlog

This backlog summarizes the current security review across:

- `origin/layer_1` for Layer 1 identity / attestation
- `origin/layer_1` for Layer 2 capability-token issuance / authorization
- `layer_2` for Layers 3 and 4 decisioning, receipts, verifier, and audit

These are the post-integration hardening items to tackle immediately after the
`L1/L2` + `L3/L4` integration lands and the current SOTA implementation pass is
finished.

Severity meanings:

- `P0`: misleading trust or integrity boundary that can let a verifier accept tampered evidence
- `P1`: material security control missing from the main authorization / identity path
- `P2`: important hardening or design gap
- `P3`: prototype shortcut or lower-risk cleanup

## Status markers

Use these markers on security items so parallel agents avoid duplicate work:

| Marker | Meaning |
|--------|---------|
| `[ ]` | Not started |
| `[>]` | **Being worked on** — do not pick up |
| `[~]` | Partial / landed in pieces |
| `[x]` | Done |

When you start an item, change it to `[>]` and add an owner note in the
parallel-tracks table. When finished, mark `[x]` and remove the in-progress
flag.

## Current status

**Last updated:** 2026-06-20 (evidence-plane suite unblock + doc follow-ups)

**Progress:** 62 done `[x]` · 0 partial `[~]` · 0 open `[ ]` (62 tracked)

### Coordination convention

When an agent actively takes a security item, mark it in this document
immediately so other contributors do not pick it up in parallel.

Use these status markers:

- `[ ]` not started
- `[~]` partially complete / landed in pieces
- `[>]` being worked on right now by a named owner
- `[x]` complete

For active items, include an owner note inline, for example:

- `### P0-1: Receipt verification does not bind exported output to the verified proof [>] *(being worked on — codex/evidence-hardening)*`
- `### P1-8: L2 proof-of-possession challenges are replayable [>] *(being worked on — partner/capability-tokens)*`

### Parallel tracks

| Track | Owner | Items |
|-------|-------|-------|
| **L4 integrity** | unassigned | P0-1 `[x]`, P0-2 `[x]`, P0-3 `[x]`, P2-6 `[x]`, P2-7 `[x]` |
| **L3 enforcement** | codex/integration-merge | P1-1 `[x]`, P1-6 `[x]`, P2-26 `[x]`, P3-8 `[x]` |
| **L1 identity hardening** | unassigned | *(P1-2 … P1-5, P2-4, P2-5, P3-2 done)* |
| **L2 capability hardening** | unassigned | *(P1-7, P1-8 done)* |
| **Verifier / ops hardening** | unassigned | *(P2-1 … P2-3, P2-8, P3-1 done)* |
| **SOTA integration / crypto** | unassigned | *(P0-4, P1-9 … P1-21, P2-9 … P2-29, P3-3 … P3-8 done)* |

## SOTA reinspection summary (2026-06-20)

Reinspected the SOTA-1 … SOTA-10 implementation pass for security and integration
gaps. Findings below are **new** relative to the pre-SOTA backlog items (P0-1 …
P3-2). SOTA-9 (confidential compliance proofs) was excluded — in progress elsewhere.

Cross-cutting theme: several SOTA features are **exported and CLI-testable** but
not fully wired into `verify_receipt_bundle()` / `ExecutionProof.verify()`, and
Nova-based paths (SOTA-7 fold, SOTA-10 recursive) prove **binding digests** rather
than re-verifying underlying Halo2/EZKL artifacts at verify time.

Second-pass additions (2026-06-20): MCP gateway trust gaps, composed-proving range
mismatch, certificate/provenance binding at verify time, policy-prover degradation,
and receipt-bundle field binding holes (`policy_satisfied`, `policy.commitment`,
compact export stripping verification inputs).

## P0

### P0-1: Receipt verification does not bind exported `output` to the verified proof `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/proof.py](../agentauth/receipts/proof.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - `ExecutionProof` stores `output_hash` and `context_hash`, but `verify_receipt_bundle()` never recomputes those hashes from the exported `output` or `execution_context`.
  - A receipt can therefore keep a valid proof while swapping in different exported output data.
- Evidence:
  - `ExecutionProof` commits `context_hash` / `output_hash` at [proof.py](../agentauth/receipts/proof.py:75) and [proof.py](../agentauth/receipts/proof.py:186).
  - `verify_receipt_bundle()` verifies proof bytes and some metadata, but never checks exported `output` or `execution_context` against those commitments at [export.py](../agentauth/receipts/export.py:209).
- Repro observed:
  - A valid `full_zk` bundle still verified after replacing `bundle["output"]` locally.
- Fix:
  - Recompute `hash_canonical_json(bundle["output"])` and compare to `proof.output_hash`.
  - Recompute `hash_canonical_json(bundle["execution_context"])` or the canonical context section and compare to `proof.context_hash`.
  - Fail verification on mismatch with dedicated error codes.

### P0-2: Receipt verification does not bind the exported certificate to `certificate_ref` `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/proof.py](../agentauth/receipts/proof.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - The proof stores `certificate_ref`, but the verifier only checks `certificate.policy_commitment`.
  - An attacker can swap the visible certificate identity fields in the bundle without invalidating verification.
- Evidence:
  - `certificate_ref` is stored on the proof at [proof.py](../agentauth/receipts/proof.py:74) and populated from the certificate hash at [proof.py](../agentauth/receipts/proof.py:184).
  - `verify_receipt_bundle()` only compares `cert["policy_commitment"]` with the proof at [export.py](../agentauth/receipts/export.py:331).
- Repro observed:
  - A valid `full_zk` bundle still verified after changing `bundle["certificate"]["principal"]["principal_id"]`.
- Fix:
  - Recompute `certificate_ref_hash(AgentCertificate.from_dict(bundle["certificate"]))` and compare it to `proof.certificate_ref`.
  - Add certificate validity checks and, once available, issuer-signature verification.

### P0-3: Envelope signatures are self-authenticating, not trust-anchored `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/signing.py](../agentauth/receipts/signing.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [docs/trust_model.md](trust_model.md)
- Problem:
  - `verify_bundle_signatures()` trusts the embedded `public_key` from the bundle itself and does not pin signatures to an expected publisher key or trust store.
  - Any attacker can generate a fresh keypair, sign a forged bundle, and get `signatures.valid == true`.
- Evidence:
  - Signature verification reconstructs the public key directly from the signature object at [signing.py](../agentauth/receipts/signing.py:63).
  - Bundle verification treats that result as sufficient at [export.py](../agentauth/receipts/export.py:449).
  - The trust model currently claims forged bundles are mitigated by these signatures at [trust_model.md](trust_model.md:32).
- Repro observed:
  - An attacker-generated key signed a bundle and verification reported `signatures.valid == true`.
- Fix:
  - Require an expected verifier key, certificate chain, or trusted signer registry during verification.
  - At minimum, verify `key_id` matches `public_key` and reject untrusted signer keys.
  - Downgrade or remove the “forged receipt bundle” claim from docs until trust anchoring exists.
- Resolution:
  - `signature_key_id_matches()` binds `key_id` to `public_key`; `verify_receipt_bundle()` requires a trusted signer policy when envelope signatures are present (`require_trust_anchor=True`).
  - Documented in `docs/trust_model.md` (trusted signer env vars and fail-closed behavior).

### P0-4: Recursive composed verification skips sub-proof cryptography (SOTA-10) `[x]`

- Layer: `L4` / proof systems
- SOTA: SOTA-10
- Files:
  - [crates/agent-receipts-composed/src/recursive.rs](../crates/agent-receipts-composed/src/recursive.rs)
  - [crates/agent-receipts-composed/src/compose.rs](../crates/agent-receipts-composed/src/compose.rs)
  - [agentauth/receipts/proof.py](../agentauth/receipts/proof.py)
- Problem:
  - `prove_recursive_composition()` validates Halo2 policy + inference sub-proofs at prove time, but `verify_recursive_composition()` only checks binding metadata and a Nova compressed SNARK over hash bindings.
  - An attacker can embed invalid or stub sub-proofs with self-consistent public fields and a valid recursive SNARK; `verify_composed()` returns true without calling `verify_policy_range()` or `verify_inference_envelope()`.
  - Python `ExecutionProof.verify()` delegates to `verify_composed()` when `composed_proof` is present, so the gap affects the main receipt path.
- Evidence:
  - Prove path calls sub-proof verify at [recursive.rs:278-280](../crates/agent-receipts-composed/src/recursive.rs).
  - Verify path ends at Nova SNARK only at [recursive.rs:319-349](../crates/agent-receipts-composed/src/recursive.rs).
  - `verify_composed()` routes recursive mode to `verify_recursive_composition()` without sub-proof checks at [compose.rs:64-68](../crates/agent-receipts-composed/src/compose.rs).
- Fix:
  - Always call `verify_policy_range()` and `verify_inference_envelope()` inside `verify_recursive_composition()` before accepting the Nova proof (mirror logical composition).
  - Or document recursive mode as “binding-only” and never map it to `composed_proved` assurance tier until sub-proofs are re-checked.
  - Add tamper tests: valid recursive SNARK + invalid policy proof bytes must fail verify.

## P1

### P1-1: L3 policy engine ignores some authority semantics `[x]`

- Layer: `L3`
- Files:
  - [agentauth/receipts/policy_engine.py](../agentauth/receipts/policy_engine.py)
  - [agentauth/receipts/runtime.py](../agentauth/receipts/runtime.py)
  - [docs/l1_l3l4_boundary.md](l1_l3l4_boundary.md)
- Problem:
  - **Landed:** `_authority_violations()` enforces `expires_at`, proof-of-possession for sender-constrained / capability-token authorities, capability scope against actions, `resource_scope`, `min_trust_tier`, `budget_refs`, and `approval_refs`.
- Evidence:
  - Enforcement at [policy_engine.py:86-134](../agentauth/receipts/policy_engine.py).
- Fix:
  - Keep boundary doc aligned with landed checks.
- Resolution:
  - `_authority_violations()` and `_authority_ref_violations()` enforce the full authority semantics listed above.
  - Documented in `docs/l1_l3l4_boundary.md`.

### P1-2: L1 attestation flow allows caller-controlled `owner` `[x]`

- Layer: `L1`
- Files:
  - [agentauth/backend/schemas.py](../agentauth/backend/schemas.py)
  - [agentauth/backend/identity.py](../agentauth/backend/identity.py)
- Problem:
  - The attestation story says identity is proven from trusted evidence and matched registration entries, but `owner` is still accepted from the request and preferred over the registration entry.
- Evidence:
  - `IdentifyRequest` exposes `owner` at [schemas.py](../agentauth/backend/schemas.py:60).
  - `attest()` resolves `owner or entry.owner or "unknown"` at [identity.py](../agentauth/backend/identity.py:324) and [identity.py](../agentauth/backend/identity.py:356).
- Fix:
  - Remove caller-supplied `owner` from attested issuance.
  - If ownership metadata is needed, derive it from the registration entry or a separate trusted admin-side mapping.
- Resolution:
  - `IdentifyRequest` no longer accepts `owner`; `attest()` resolves owner from the matched registration entry only.
  - `test_owner_comes_from_entry_not_identify_request` covers the regression.

### P1-3: L1 attestation documents are replayable until expiry `[x]`

- Layer: `L1`
- Files:
  - [agentauth/backend/attestation.py](../agentauth/backend/attestation.py)
  - [agentauth/backend/identity.py](../agentauth/backend/identity.py)
- Problem:
  - The attestation verifier checks signature and expiry but does not bind the attestation to a nonce, challenge, audience, or one-time-use record.
  - A captured attestation JWT can mint fresh credentials repeatedly until it expires.
- Evidence:
  - Verification is purely `jwt.decode(..., options={"verify_aud": False})` against registered public keys at [attestation.py](../agentauth/backend/attestation.py:139).
  - `attest()` immediately mints a new credential from a verified document at [identity.py](../agentauth/backend/identity.py:324).
- Fix:
  - Add nonce / challenge binding and record attestation `jti` or equivalent to prevent reuse.
  - Bind attestation documents to tenant, audience, and issuance context.
- Resolution:
  - Attestation JWTs must include `jti` and `exp`; verification requires `aud == customer.id`.
  - `AttestationUse` records consumed `jti` values; `record_attestation_use()` rejects reuse before minting.
  - `test_identify_rejects_replayed_attestation_document` covers the regression.

### P1-4: L1 registration matching silently resolves ambiguous identities `[x]`

- Layer: `L1`
- File:
  - [agentauth/backend/identity.py](../agentauth/backend/identity.py)
- Problem:
  - When multiple registration entries match the same selector set, the service deterministically picks one instead of rejecting ambiguity.
  - This can grant the wrong `agent_type`, owner, TTL, or scope based on creation order.
- Evidence:
  - `_match_entry()` sorts matching entries and returns the first one at [identity.py](../agentauth/backend/identity.py:305).
- Fix:
  - Reject ambiguous matches unless exactly one highest-priority rule exists.
  - Add an admin lint/check endpoint for overlapping registration entries.
- Resolution:
  - `_match_entry()` rejects when multiple entries share the best (most specific) match score.
  - `GET /v1/registration-entries/lint` reports equal-specificity overlaps before identify fails.
  - Tests in `backend/tests/test_registration_lint.py`.

### P1-5: L1 signing keys and API keys are stored in plaintext `[x]`

- Layer: `L1`
- Files:
  - [agentauth/backend/models.py](../agentauth/backend/models.py)
  - [agentauth/backend/deps.py](../agentauth/backend/deps.py)
- Problem:
  - Customer API keys are stored as plaintext values and looked up directly.
  - JWT signing private keys are stored as plaintext PEMs in the database.
- Evidence:
  - `Customer.api_key` is a plain indexed string at [models.py](../agentauth/backend/models.py:46).
  - `SigningKey.private_pem` is stored directly at [models.py](../agentauth/backend/models.py:57).
  - `get_current_customer()` compares `X-API-Key` directly against stored plaintext at [deps.py](../agentauth/backend/deps.py:13).
- Fix:
  - Hash API keys with a one-way KDF and compare using constant-time comparison.
  - Move private signing keys to a KMS/HSM or, at minimum, encrypt them at rest with external key material.
- Resolution:
  - API keys are PBKDF2-hashed at rest via `agentauth/backend/api_keys.py`; lookup uses prefix + constant-time verify.
  - JWT and Biscuit root private keys are encrypted via `agentauth/backend/secret_encryption.py` (local AES-GCM, AWS KMS, or GCP KMS).
  - Set `AGENTAUTH_SECRET_ENCRYPTION_PROVIDER` to `local` (default), `aws_kms`, or `gcp_kms`; local mode uses `AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY` (32-byte hex).
  - Tests in `backend/tests/test_signing_keys.py`, `test_biscuit_keys.py`, and `test_secret_encryption.py`.

### P1-6: L2 mandate verification does not bind a grant to the actor that used it `[x]`

- Layer: `L3/L4 integration seam`
- Files:
  - [agentauth/receipts/mandate.py](../agentauth/receipts/mandate.py)
- Problem:
  - `Mandate` includes a `delegate` field, but receipt verification never compares that delegate to the authority or actor that actually produced the receipt.
  - A valid signed mandate can therefore be replayed by the wrong actor as long as action/resource/budget checks still pass.
- Evidence:
  - `Mandate` defines `delegate` at [mandate.py](../agentauth/receipts/mandate.py:29).
  - `check_receipt_against_mandate()` only checks time, action/resource scope, and budget effects at [mandate.py](../agentauth/receipts/mandate.py:174).
  - `verify_bundle_mandate()` never compares mandate subject/delegate against the receipt authority block at [mandate.py](../agentauth/receipts/mandate.py:216).
- Fix:
  - Define the actor-binding field for mandates explicitly.
  - Compare that field against `authority.actor`, `authority.subject_id`, or the finalized L2 authority identity during receipt verification.
  - Fail closed when a mandate is present but no comparable actor identity is available.

### P1-7: L2 capability `constraints` are accepted and persisted but ignored at authorization time `[x]`

- Layer: `L2`
- Files:
  - `origin/layer_1:agentauth/backend/schemas.py`
  - `origin/layer_1:agentauth/backend/models.py`
  - `origin/layer_1:agentauth/backend/capabilities.py`
- Problem:
  - The capability schema and persistence model advertise optional `constraints`, but the Biscuit minting and authorization logic only uses `resource` and `action`.
  - This creates an overgrant risk if callers believe constraints narrow the authorization they are issuing.
- Evidence:
  - `Capability` exposes `constraints` at `origin/layer_1:agentauth/backend/schemas.py:37-45`.
  - Registration entries persist `constraints` as part of capability objects at `origin/layer_1:agentauth/backend/models.py:147-152`.
  - Normalization preserves `constraints` at `origin/layer_1:agentauth/backend/capabilities.py:78-90`.
  - Minting and attenuation emit only `capability(resource, action)` / `allowed_cap(resource, action)` facts at `origin/layer_1:agentauth/backend/capabilities.py:298-305` and `origin/layer_1:agentauth/backend/capabilities.py:331-338`.
- Repro observed:
  - A capability like `{"resource": "db", "action": "read", "constraints": {"rows": 1}}` still authorized a normal `db:read` with no constraint check.
- Fix:
  - Either remove `constraints` from the public capability model until implemented, or encode/enforce them inside the Biscuit facts and authorizer rules.
  - Add explicit tests for every supported constraint kind.
- Resolution:
  - `normalize_capabilities()` and the `Capability` Pydantic model reject any non-empty `constraints` at registration/mint time (fail closed until Biscuit rules exist).
  - Tests in `backend/tests/test_capability_constraints.py` cover API, normalize, and mint paths.

### P1-8: L2 proof-of-possession challenges are replayable on the server authorization path `[x]`

- Layer: `L2`
- Files:
  - `origin/layer_1:agentauth/backend/capabilities.py`
  - `origin/layer_1:agentauth/backend/routers/identity.py`
- Problem:
  - The server-side authorization path verifies that the submitted proof-of-possession matches the submitted challenge and operation, but it does not track nonce use, challenge expiry, or single-use semantics.
  - A captured valid `token + pop` payload can therefore be replayed for the same operation until token expiry.
- Evidence:
  - The PoP message binds keyhash + challenge + operation at `origin/layer_1:agentauth/backend/capabilities.py:224-228`.
  - `issue_challenge()` just returns a random nonce and stores nothing at `origin/layer_1:agentauth/backend/capabilities.py:272-274`.
  - `/v1/challenge` is explicitly stateless at `origin/layer_1:agentauth/backend/routers/identity.py:267-273`.
- Repro observed:
  - Re-submitting the exact same `/v1/authorize` body twice succeeded twice.
- Fix:
  - Decide whether `/v1/authorize` is meant to provide freshness or just offline possession semantics.
  - If freshness matters, store issued challenges with TTL and single-use consumption, or require a signed timestamp / monotonic counter that the server verifies.
  - If it is intentionally replayable, document that clearly and scope it to offline authorization only.
- Resolution:
  - `CapabilityChallenge` persists issued challenges with TTL; `consume_server_challenge()` marks them used on `/v1/authorize` and `/v1/validate`.
  - Replay of the same challenge returns an error before authorization proceeds.

### P1-9: `min_assurance_tier` can be satisfied from stored bundle metadata, not live proof (SOTA-3) `[x]`

- Layer: `L4`
- SOTA: SOTA-3
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [agentauth/receipts/assurance.py](../agentauth/receipts/assurance.py)
- Problem:
  - `verify_receipt_bundle()` builds the assurance object used for tier threshold checks from `stored_assurance_dict(bundle)` when present, not from `assurance_from_proof(proof)`.
  - The self-consistency check compares stored level to that same stored-derived object, so it does not catch tier inflation.
  - A bundle with tampered `assurance.tier` / `assurance.level` can pass `?min_assurance_tier=tee_attested` while only a policy proof (or shadow mode) backs the execution proof.
- Evidence:
  - Assurance selection at [export.py:362-364](../agentauth/receipts/export.py).
  - Threshold uses that `assurance["tier"]` at [export.py:374-391](../agentauth/receipts/export.py).
- Fix:
  - Always compute `expected = assurance_from_proof(proof)` (plus live TEE/composed checks) and use **expected** tier for threshold enforcement.
  - Fail verification when stored assurance level/tier disagrees with recomputed values (hard error, not optional warning).

### P1-10: Mandate signature is not bound to `issuer` identity (SOTA-6) `[x]`

- Layer: `L3/L4`
- SOTA: SOTA-6
- Files:
  - [agentauth/receipts/mandate.py](../agentauth/receipts/mandate.py)
- Problem:
  - `verify_mandate_envelope()` checks Ed25519 over the document but does not compare `signature.public_key` to `mandate.issuer` or any trusted issuer registry.
  - Any keypair can sign a mandate claiming an arbitrary issuer string.
- Evidence:
  - Signature-only check at [mandate.py:133-146](../agentauth/receipts/mandate.py).
- Fix:
  - Resolve issuer → trusted verification method(s) (Layer-1 identity, pinned key, or L2 grant issuer).
  - Reject mandates where signer is not authorized for `issuer`.
  - Related: delegate/subject binding is tracked separately as P1-6.

### P1-11: Embedded audit inclusion proofs are never validated in receipt verification (SOTA-1) `[x]`

- Layer: `L4`
- SOTA: SOTA-1
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [agentauth/receipts/audit.py](../agentauth/receipts/audit.py)
- Problem:
  - Bundles can embed `audit_inclusion` (proof + checkpoint) at export time, and tests verify inclusion manually, but `verify_receipt_bundle()` never calls `AuditChain.verify_inclusion()`.
  - Portable CT-style evidence can be swapped without affecting main receipt verification.
- Evidence:
  - Export embeds inclusion at [export.py:116-127](../agentauth/receipts/export.py).
  - No `verify_inclusion` call in `verify_receipt_bundle()` (mandate check exists; inclusion does not).
- Fix:
  - When `audit_inclusion` is present, require `AuditChain.verify_inclusion(record_hash, proof, checkpoint)` against `audit_record.record_hash`.
  - Combine with P2-6: require trusted log signature or witness quorum on the checkpoint.

### P1-12: Nova session fold proves digest chain only, not Halo2 policy satisfaction (SOTA-7) `[x]`

- Layer: `L4` / proof systems
- SOTA: SOTA-7
- Files:
  - [crates/agent-receipts-session/src/fold.rs](../crates/agent-receipts-session/src/fold.rs)
  - [crates/agent-receipts-session/src/batch.rs](../crates/agent-receipts-session/src/batch.rs)
- Problem:
  - `nova_fold_v1` uses a Poseidon step circuit over action-binding hashes; it does not verify per-action Halo2 `policy_range_v3` proofs inside the fold.
  - `verify_session_fold()` omits `validate_action_ref()` range/mask checks that `verify_session_batch()` performs before SNARK verify.
  - A malicious prover can fold arbitrary action metadata that is internally consistent.
- Evidence:
  - Fold verify at [fold.rs:271-301](../crates/agent-receipts-session/src/fold.rs) vs batch validation at [batch.rs:145-181](../crates/agent-receipts-session/src/batch.rs).
- Fix:
  - Call shared `validate_action_ref()` in fold verify.
  - Document that `halo2_batch_v1` is the full-crypto mode; fold is compression-only unless paired with batch proof bytes.
  - Consider binding fold SNARK to a verified batch artifact hash.
- Resolution:
  - Shared `validate_action_ref()` in `envelope.rs`; fold verify calls it before Nova SNARK verify.
  - Module docs clarify `halo2_batch_v1` is full-crypto; `nova_fold_v1` is compression-only.
  - `fold_rejects_out_of_range_action_metadata` regression test added.

### P1-13: RISC Zero inference verify does not bind `output_hash` or model provenance (SOTA-8) `[x]`

- Layer: `L4`
- SOTA: SOTA-8
- Files:
  - [crates/agent-receipts-composed/src/inference.rs](../crates/agent-receipts-composed/src/inference.rs)
  - [crates/agent-receipts-zkvm/methods/guest/src/main.rs](../crates/agent-receipts-zkvm/methods/guest/src/main.rs)
- Problem:
  - The zkVM guest commits only the fraud score to the journal; verification checks `image_id` and score match but not `output_hash` or `model_provenance_hash` from the envelope.
  - A valid receipt for one output can be replayed against a bundle with a different output commitment.
- Evidence:
  - `verify_inference_risc0()` at [inference.rs:229-263](../crates/agent-receipts-composed/src/inference.rs).
- Fix:
  - Commit `{amount, output_hash, model_provenance_hash, score}` (or their hashes) in the guest journal and verify in the host.
- Resolution:
  - Guest journal commits `(amount, output_hash, model_provenance_hash, score)`.
  - `agent-receipts-zkvm verify` checks all journal fields against envelope; `verify_inference_risc0()` passes bindings through CLI.

### P1-14: EZKL inference verify does not bind envelope commitments (SOTA-8) `[x]`

- Layer: `L4`
- SOTA: SOTA-8
- Files:
  - [crates/agent-receipts-composed/src/inference.rs](../crates/agent-receipts-composed/src/inference.rs)
- Problem:
  - For `InferenceAttestation::Ezkl`, `verify_inference_envelope()` only runs `ezkl verify` on artifact paths.
  - It never checks that `output_hash`, `model_provenance_hash`, `public_score`, or `input_hash` in the envelope match what the proof attests (RISC0 gap is P1-13).
- Evidence:
  - Ezkl branch ends at CLI verify at [inference.rs:304-333](../crates/agent-receipts-composed/src/inference.rs); no post-verify binding checks.
- Fix:
  - After EZKL verify, require envelope fields match witness/public inputs or in-circuit commitments.
- Resolution:
  - `verify_inference_envelope_bindings()` checks `amount`, `input_hash`, `public_score`, `output_hash`, and `model_provenance_hash` consistency after EZKL (and before RISC0) verify.
  - `InferenceProofEnvelope` now stores `amount` for binding checks; regression tests cover score/input_hash mismatch.

### P1-15: Composed proving uses hardcoded policy range `[0,1]`, not deployed policy (SOTA-10) `[x]`

- Layer: `L4`
- SOTA: SOTA-10
- Files:
  - [agentauth/receipts/wrapper.py](../agentauth/receipts/wrapper.py)
  - [agentauth/receipts/compose.py](../agentauth/receipts/compose.py)
  - [agentauth/receipts/prover.py](../agentauth/receipts/prover.py)
  - [crates/agent-receipts-cli/src/main.rs](../crates/agent-receipts-cli/src/main.rs)
- Problem:
  - `AgentWrapper.record()` calls `prove_composed()` without passing `Policy.numeric_ranges`.
  - Composed proofs always prove `min=0, max=1` (CLI defaults) while `prove_structural_policy()` uses the real policy range.
  - A receipt can cryptographically “prove” a wider numeric range than the operator policy enforces.
- Evidence:
  - `prove_composed()` defaults `min_score=0.0, max_score=1.0` at [compose.py:29-30](../agentauth/receipts/compose.py).
  - Wrapper omits range args at [wrapper.py:314-321](../agentauth/receipts/wrapper.py).
  - `prove_structural_policy()` reads `policy.numeric_ranges[0]` at [prover.py:79-99](../agentauth/receipts/prover.py).
- Fix:
  - Thread first `NumericRange` from `Policy` into `prove_composed()`; fail if policy has no numeric range when composed proving is requested.

### P1-16: MCP `arguments_hash` is recorded but never verified in receipt verification (SOTA-5) `[x]`

- Layer: `L4`
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/mcp.py](../agentauth/receipts/mcp.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - MCP auth context stores `arguments_hash`, but `verify_receipt_bundle()` never recomputes `hash_canonical_json(execution_context["input"])` and compares it.
  - Tool-call receipts can swap arguments while keeping a valid proof (amplifies P0-1 context binding gap).
- Evidence:
  - Hash recorded at [mcp.py:179](../agentauth/receipts/mcp.py).
  - No `arguments_hash` check in `verify_receipt_bundle()` ([export.py:231-502](../agentauth/receipts/export.py)).
- Fix:
  - When `authorization.protocol == "mcp"`, require `arguments_hash == hash_canonical_json(execution_context.input)`; add dedicated error code.

### P1-17: Delegation tokens are unsigned and forgeable (SOTA-5) `[x]`

- Layer: `L3/L4`
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/delegation.py](../agentauth/receipts/delegation.py)
  - [agentauth/receipts/mcp.py](../agentauth/receipts/mcp.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - `DelegationToken` is a plain dataclass with no signature/PKI binding (“signed envelope is future PKI”).
  - Any caller can embed a forged delegation chain in MCP `authorization_context`; `verify_delegation_chain()` only checks expiry/scope strings.
- Fix:
  - Sign delegations with issuer key (or L2 grant reference); verify signature and delegate identity before tool execution and during receipt verification.
- Resolution:
  - `sign_delegation()` / `verify_delegation_envelope()`; MCP non-shadow modes require signed envelopes; `verify_receipt_bundle()` validates `execution_context.authorization.signed_delegation` via `_delegation_issues()`.

### P1-18: Receipt verification skips certificate validity, issuer signature, and `agent_id` binding `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [agentauth/receipts/certificate.py](../agentauth/receipts/certificate.py)
- Problem:
  - Verifier checks only `certificate.policy_commitment` against the proof.
  - It does not check cert time window, `issuer_signature`, or that `proof.agent_id` matches `certificate.agent_id`.
  - Expired or unsigned dev certs still verify if commitment matches.
- Fix:
  - Recompute `certificate_ref`, verify issuer signature against trust store, enforce `not_before`/`not_after`, require `proof.agent_id == certificate.agent_id`.
- Resolution:
  - `_certificate_verification_issues()` checks `certificate_ref`, `agent_id`, validity window, and calls `verify_certificate_issuer()`.
  - `sign_certificate()` / issuer trust via `AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS` and `_KEY_IDS`; unsigned certs allowed in dev via `AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE=1` (default).

### P1-19: `model_provenance_hash` is not bound across certificate, wrapper, and proofs at verify time (SOTA-8) `[x]`

- Layer: `L4`
- SOTA: SOTA-8
- Files:
  - [agentauth/receipts/wrapper.py](../agentauth/receipts/wrapper.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [crates/agent-receipts-composed/src/compose.rs](../crates/agent-receipts-composed/src/compose.rs)
- Problem:
  - `AgentWrapper` keeps a separate `model_provenance_hash` used for proving but never compares it to `certificate.model_provenance_hash` at init.
  - Receipt verification does not cross-check certificate vs composed/inference envelope bindings.
- Evidence:
  - Separate fields at [wrapper.py:129-142](../agentauth/receipts/wrapper.py) with no equality check.
  - Composed bindings check inference envelope only ([compose.rs:110-114](../crates/agent-receipts-composed/src/compose.rs)), not certificate block.
- Fix:
  - Fail closed on wrapper init mismatch; during `verify_receipt_bundle()`, require certificate `model_provenance_hash` equals composed/inference envelope value.

### P1-20: Policy prover silently degrades to weaker proof on CLI fallback `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/prover.py](../agentauth/receipts/prover.py)
- Problem:
  - If `prove-policy` fails with `--output-json` / `--required-field`, the code retries without those flags, producing a proof that omits required-field presence constraints.
  - Receipts may claim full structural policy proof while only proving numeric range.
- Evidence:
  - Fallback drops args at [prover.py:111-117](../agentauth/receipts/prover.py).
- Fix:
  - Remove silent fallback; require CLI features for production proving or surface hard error / lower assurance tier when degraded.

### P1-21: `decision.policy_satisfied` is not verified against execution proof `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - `verify_receipt_bundle()` checks `decision.outcome` against `proof.decision_outcome` but never compares `decision.policy_satisfied` to `proof.policy_satisfied`.
  - A bundle can show `policy_satisfied: true` in the decision block while the proof commits `policy_satisfied: false` (or vice versa) and still verify if crypto passes.
- Evidence:
  - Outcome check at [export.py:278-284](../agentauth/receipts/export.py); no `policy_satisfied` cross-check anywhere in verify path.
- Fix:
  - Require `decision.policy_satisfied == proof.policy_satisfied`; optionally fail when proof says unsatisfied but outcome is ALLOW.

## P2

### P2-1: L4 defaults allow stub proof verification paths `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/compose.py](../agentauth/receipts/compose.py)
  - [agentauth/receipts/inference.py](../agentauth/receipts/inference.py)
- Problem:
  - `AGENT_RECEIPTS_ALLOW_STUB` defaults to `"1"` in the Python helpers, which means development stub inference/composed proofs are easy to leave enabled accidentally.
- Evidence:
  - Default stub allowance in composed helper at [compose.py](../agentauth/receipts/compose.py:36).
- Fix:
  - Make stub use opt-in by default in verifier-facing code paths.
  - Surface a hard verification issue when stub proofs are encountered outside explicit development mode.
- Resolution:
  - Verifier-facing helpers default `AGENT_RECEIPTS_ALLOW_STUB` to `"0"`; prove paths still default to `"1"`.
  - `verify_receipt_bundle()` emits `STUB_PROOF_NOT_ALLOWED` when stub attestations are present without opt-in.

### P2-2: L4 verifier authentication is optional and rate limiting is weak `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/verifier_auth.py](../agentauth/receipts/verifier_auth.py)
  - [agentauth/receipts/verifier_server.py](../agentauth/receipts/verifier_server.py)
- Problem:
  - If `AGENT_RECEIPTS_VERIFIER_API_KEY` is unset, the verify endpoint is open.
  - Rate limiting is in-memory and keyed only by apparent client IP, which is not suitable for shared deployments.
- Evidence:
  - Auth only applies when an env var is set at [verifier_auth.py](../agentauth/receipts/verifier_auth.py:35).
  - Rate limiting is in-memory pilot logic at [verifier_auth.py](../agentauth/receipts/verifier_auth.py:47).
- Fix:
  - Default to auth required for `/v1/verify` in deployed mode.
  - Move rate limiting and authentication to a real gateway or shared backend.
  - Use constant-time API-key comparison.
- Resolution:
  - `validate_verifier_bind()` refuses non-localhost binds without `AGENT_RECEIPTS_VERIFIER_API_KEY`; `agent-receipts serve` calls it at startup.
  - `AGENT_RECEIPTS_VERIFIER_REQUIRE_API_KEY=1` enforces auth on localhost too (503 if key unset).
  - Rate limit buckets by API key when present, else client IP; production should still front with a gateway.
  - Constant-time compare via `hmac.compare_digest` (P3-1).

### P2-3: L4 private signing keys are persisted unencrypted on disk `[x]`

- Layer: `L4`
- File:
  - [agentauth/receipts/signing.py](../agentauth/receipts/signing.py)
- Problem:
  - `load_or_create_key()` writes the Ed25519 private key unencrypted and does not set restrictive file permissions.
- Fix:
  - Lock down file mode on creation.
  - Support password-protected local keys or external signer integrations.
- Resolution:
  - New keys are written with mode `0600`; existing keys are tightened on load.
  - Password-protected PEM via `AGENT_RECEIPTS_SIGNING_KEY_PASSWORD` or `load_or_create_key(..., password=)`; `require_encryption=True` refuses unencrypted key creation.

### P2-4: L1 identity audit log is not actually tamper-evident `[x]`

- Layer: `L1`
- File:
  - [agentauth/backend/audit.py](../agentauth/backend/audit.py)
- Problem:
  - The code comments describe a tamper-evident append-only audit log, but the implementation is a plain JSONL append file with no signatures, hash chaining, checkpoints, or fsync guarantees.
- Evidence:
  - Plain append-only write at [audit.py](../agentauth/backend/audit.py:26).
- Fix:
  - Either downgrade the claim in docs/comments or add hash chaining and signing similar to the L4 audit chain.
- Resolution:
  - Each audit record includes `entry_hash` and `prev_hash`; `verify_event_log()` detects tampering and broken chains.
  - Tests in `backend/tests/test_identity.py` cover hash-chain verification.

### P2-5: L1 credentials are bearer-only `[x]`

- Layer: `L1`
- Files:
  - [agentauth/backend/identity.py](../agentauth/backend/identity.py)
  - [docs/l1_l3l4_boundary.md](l1_l3l4_boundary.md)
- Problem:
  - Issued JWT-SVIDs have no proof-of-possession binding, so theft of a token is enough to replay authority until expiry.
  - This is especially important because the L3/L4 boundary already treats PoP as a first-class future concept.
- Evidence:
  - Token claims include no sender-constrained or `cnf`-style binding at [identity.py](../agentauth/backend/identity.py:167).
- Fix:
  - Add a sender-constrained profile in L2 or bind identity credentials to a held key early.
- Resolution:
  - `attest()` rejects attestation evidence without `workload_pubkey_pem`.
  - Every issued JWT includes `cnf.jkt`; `/v1/validate` always requires a fresh PoP challenge signature.
  - Tests cover missing workload key at identify and missing PoP at validate.

### P2-6: Transparency inclusion proofs are accepted without a trusted signed checkpoint `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/audit.py](../agentauth/receipts/audit.py)
- Problem:
  - Inclusion verification currently proves only “this leaf matches this Merkle root,” not “this Merkle root was endorsed by a trusted log identity.”
  - When no audit signing key is configured, `signed_checkpoint()` emits an unsigned checkpoint, and inclusion verification accepts it as long as `count` and `merkle_root` line up.
- Evidence:
  - `signed_checkpoint()` omits `signature` when no key is set at [audit.py](../agentauth/receipts/audit.py:413).
  - `verify_inclusion()` checks only `leaf_hash`, `tree_size`, and `checkpoint["merkle_root"]` at [audit.py](../agentauth/receipts/audit.py:471).
- Fix:
  - Require a valid log signature or pinned witness quorum whenever inclusion proofs are used as portable evidence.
  - Keep unsigned checkpoints for local development only and mark them as non-portable.
- Resolution:
  - `_audit_inclusion_issues()` rejects unsigned checkpoints unless `AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT=1`.

### P2-7: Invalid verifier assurance-tier input returns HTTP 500 instead of a client error `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/verifier_server.py](../agentauth/receipts/verifier_server.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [agentauth/receipts/assurance.py](../agentauth/receipts/assurance.py)
- Problem:
  - A malformed `min_assurance_tier` query causes `parse_trust_tier()` to raise and bubbles out as an internal server error.
  - This is not a trust-boundary break by itself, but it is a reliability and abuse-surface issue for the public verifier.
- Evidence:
  - `/v1/verify` forwards the raw query string at [verifier_server.py](../agentauth/receipts/verifier_server.py:117).
  - `verify_receipt_bundle()` parses it directly at [export.py](../agentauth/receipts/export.py:374).
  - Unknown values raise from `parse_trust_tier()` at [assurance.py](../agentauth/receipts/assurance.py:80).
- Repro observed:
  - `/v1/verify?min_assurance_tier=definitely-not-a-tier` returned HTTP 500.
- Fix:
  - Validate the query parameter and return HTTP 400 with allowed values.
  - Add a regression test for invalid-tier input.

### P2-8: Nitro attestation verification is not yet routinely exercised in this environment `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/tee_nitro.py](../agentauth/receipts/tee_nitro.py)
  - [python/tests/test_tee_nitro.py](../python/tests/test_tee_nitro.py)
  - [pyproject.toml](../pyproject.toml)
- Problem:
  - The new Nitro verification path depends on `cbor2`, but the current local environment did not have that dependency installed, so the Nitro test module did not collect here.
  - That leaves a sensitive new verifier path less validated than the rest of the active SOTA work.
- Evidence:
  - `tee_nitro.py` imports `cbor2` at [tee_nitro.py](../agentauth/receipts/tee_nitro.py:11).
  - Local test collection failed with `ModuleNotFoundError: No module named 'cbor2'`.
- Fix:
  - Make sure the TEE dependency set is included in the standard development/test environment before calling the Nitro path production-ready.
  - Keep this path behind explicit readiness gates until the dependency and tests are consistently exercised.
- Resolution:
  - `cbor2>=5.4` is a core package dependency; `tests/test_tee_nitro.py` collects and passes in the standard Python test environment.

### P2-9: Witness cosignatures are not enforced during receipt verification (SOTA-5) `[x]`

- Layer: `L4`
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [agentauth/receipts/audit.py](../agentauth/receipts/audit.py)
- Problem:
  - Checkpoints may carry `witness_cosignatures`, and `AuditChain.verify_checkpoint(..., required_witnesses=K)` exists, but `verify_receipt_bundle()` never requires a witness quorum when verifying embedded audit evidence.
- Fix:
  - Add verifier parameters (`required_witnesses`, `trusted_witness_keys`, `log_public_key`) and enforce when `audit_inclusion` or checkpoint fields are present.
- Resolution:
  - When audit log trust env is configured, `_audit_inclusion_issues()` calls `checkpoint_trust_issues()` which enforces `AGENT_RECEIPTS_REQUIRED_AUDIT_WITNESSES` and `AGENT_RECEIPTS_TRUSTED_AUDIT_WITNESS_KEYS`.

### P2-10: Reference witness HTTP service has no authentication (SOTA-5) `[x]`

- Layer: `L4` / ops
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/witness.py](../agentauth/receipts/witness.py)
  - [agentauth/receipts/verifier_auth.py](../agentauth/receipts/verifier_auth.py)
- Problem:
  - `POST /v1/witness/cosign` accepts arbitrary checkpoint JSON with no API key, mTLS, or rate limiting.
- Fix:
  - Require operator auth; pin allowed log public keys; rate-limit cosign requests.
- Resolution:
  - `create_witness_app()` wraps with `ApiKeyMiddleware(env_var=AGENT_RECEIPTS_WITNESS_API_KEY)` when that env is set; `Witness` already pins log public keys. Rate limiting remains future ops work.

### P2-11: Compliance / SIEM export equates field presence with integrity (SOTA-4) `[x]`

- Layer: `L4`
- SOTA: SOTA-4
- Files:
  - [agentauth/receipts/compliance.py](../agentauth/receipts/compliance.py)
  - [compliance/soc2.yaml](../compliance/soc2.yaml)
- Problem:
  - `validate_profile_completeness()` checks that mapped fields exist, not that the receipt re-verifies successfully.
  - Shadow receipts can pass profile completeness; SIEM events copy stale `bundle["verification"]["valid"]` from export time.
- Fix:
  - Distinguish “schema complete” vs “cryptographically verified”; require live `verify_receipt_bundle().valid` for integrity-mapped controls.
- Resolution:
  - `export_compliance_mapped()` runs live verification and adds `cryptographically_verified`.
  - SIEM `_base_event_fields()` now runs live `verify_receipt_bundle()`; ECS exports `verification_valid` (live), `verification_issue_count`, and `stored_verification_valid` for audit contrast.

### P2-12: `ComposedBindings.context_hash` is never verified (SOTA-10) `[x]`

- Layer: `L4`
- SOTA: SOTA-10
- Files:
  - [crates/agent-receipts-composed/src/compose.rs](../crates/agent-receipts-composed/src/compose.rs)
- Problem:
  - `verify_bindings()` aligns output/policy/model/score across policy and inference envelopes but never compares `bindings.context_hash` to `ExecutionProof.context_hash` or execution context in the bundle.
- Fix:
  - Bind `context_hash` to the execution proof commitment or remove it from the public binding surface.

### P2-13: Nova session-fold key cache can desync from public params (SOTA-7) `[x]`

- Layer: `L4` / proof systems
- SOTA: SOTA-7
- Files:
  - [crates/agent-receipts-session/src/fold.rs](../crates/agent-receipts-session/src/fold.rs)
  - [crates/agent-receipts-composed/src/recursive.rs](../crates/agent-receipts-composed/src/recursive.rs)
- Problem:
  - When `pp.bin` is regenerated, `recursive.rs` deletes stale `compressed_pk.bin` / `compressed_vk.bin`, but `fold.rs` does not — leading to verify failures or, worse, pk/vk mismatch if circuit templates diverge.
- Fix:
  - Mirror recursive key invalidation in fold path; version key filenames with circuit/schema id.
- Resolution:
  - Session fold and recursive composition store Nova artifacts as `{stem}.{circuit_id}.bin` (`session_step_v1`, `binding_step_v1`).
  - Regenerating public params deletes versioned compressed pk/vk and legacy unversioned filenames.
  - `pp_regeneration_invalidates_stale_compressed_keys` covers the fold path.

### P2-14: Session proofs are not integrated into receipt verification (SOTA-7) `[x]`

- Layer: `L4`
- SOTA: SOTA-7
- Files:
  - [agentauth/receipts/session.py](../agentauth/receipts/session.py)
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
  - [agentauth/receipts/proof.py](../agentauth/receipts/proof.py)
- Problem:
  - Session aggregation is CLI/API-only; receipt bundles have no `session_proof` section and `verify_receipt_bundle()` does not verify aggregated session evidence.
- Fix:
  - Optional bundle field + verify hook; bind session digest to `proof.session_id` and policy commitment.
- Resolution:
  - `session_proof_bundle_section()` embeds session envelopes; `verify_bundle_session_proof()` binds session id, policy commitment, and action refs, then runs `verify_session()` when present.
  - `verify_receipt_bundle()` surfaces failures as `session_proof_invalid`.

### P2-15: Mandate verification is optional and parent-grant chain is unchecked (SOTA-6) `[x]`

- Layer: `L3/L4`
- SOTA: SOTA-6
- Files:
  - [agentauth/receipts/mandate.py](../agentauth/receipts/mandate.py)
- Problem:
  - `verify_bundle_mandate()` returns success when no mandate section exists, even if authority/policy implies grant-required commerce flows.
  - `parent_grant_id` is stored but never validated for attenuation or chain integrity.
- Fix:
  - Policy-driven mandate requirement; parent grant lookup and scope-shrink checks.
- Resolution:
  - Receipt verification now requires a signed mandate for budget-affecting receipts by default, with action-name overrides available through verifier policy env.
  - Parent-grant verification now enforces scope shrink, budget subset, parent/child validity-window containment, and delegate-to-child-issuer linkage.

### P2-16: Nitro `report_data_hash` mismatch is warning-only when `user_data` absent (SOTA-2) `[x]`

- Layer: `L4`
- SOTA: SOTA-2
- Files:
  - [agentauth/receipts/tee_nitro.py](../agentauth/receipts/tee_nitro.py)
- Problem:
  - When callers supply `report_data_hash` but the attestation document lacks `user_data`, verification adds a warning and may still return `valid=True`.
- Evidence:
  - [tee_nitro.py:247-257](../agentauth/receipts/tee_nitro.py)
- Fix:
  - Fail closed when binding hash is requested but not present in the quote.

### P2-17: Audit leaf hash omits critical execution-proof fields (SOTA-1) `[x]`

- Layer: `L4`
- SOTA: SOTA-1
- Files:
  - [agentauth/receipts/audit.py](../agentauth/receipts/audit.py)
- Problem:
  - `execution_proof_hash` / audit leaf derivation omits `context_hash`, `certificate_ref`, `obligations`, and other proof commitments — distinct actions can share the same log leaf.
- Fix:
  - Extend canonical leaf hash to full proof commitment set or store proof digest directly.
- Resolution:
  - `execution_proof_commitment()` / `execution_proof_hash()` hash agent id, certificate ref, context/output hashes, attestation path, policy satisfaction, obligations, created_at, and proof bundle digests on every audit append.

### P2-18: Consistency verification does not require trusted log / witness signatures (SOTA-1 / SOTA-5) `[x]`

- Layer: `L4`
- SOTA: SOTA-1, SOTA-5
- Files:
  - [agentauth/receipts/audit.py](../agentauth/receipts/audit.py)
  - [agentauth/receipts/cli.py](../agentauth/receipts/cli.py)
- Problem:
  - `verify_consistency()` validates Merkle math but not that checkpoints are signed by a trusted log key or co-signed by witnesses (extends P2-6).
- Fix:
  - Require log signature + optional witness quorum on both checkpoints before accepting portable consistency proofs.
- Resolution:
  - `AuditChain.verify_consistency()` now accepts trusted log and witness policy inputs and rejects unsigned or untrusted checkpoints before accepting the Merkle proof.
  - `audit-consistency` now signs the newly emitted checkpoint when `--signing-key` is supplied, and it fails closed under trust policy when the new checkpoint is unsigned or missing witness quorum.

### P2-19: Recursive composition silently coerces bad policy public inputs to zero (SOTA-10) `[x]`

- Layer: `L4`
- SOTA: SOTA-10
- Files:
  - [crates/agent-receipts-composed/src/recursive.rs](../crates/agent-receipts-composed/src/recursive.rs)
- Problem:
  - `policy_step_elements()` uses `parse().unwrap_or(0)` for score and required-field mask when building Nova step inputs.
- Fix:
  - Fail prove on parse errors; never default to zero.

### P2-20: SOTA-8 / SOTA-10 integration gaps in Python product surface `[x]`

- Layer: `L4`
- SOTA: SOTA-8, SOTA-10
- Files:
  - [agentauth/receipts/inference.py](../agentauth/receipts/inference.py)
  - [agentauth/receipts/wrapper.py](../agentauth/receipts/wrapper.py)
  - [agentauth/receipts/compose.py](../agentauth/receipts/compose.py)
- Problem:
  - Python `prove_inference()` has no `--backend risc0` plumbing; RISC0 is Rust-CLI-only.
  - `AgentWrapper` never passes `recursive=True` to `prove_composed()`; recursive composition is not reachable from the default agent path.
  - Verifier-facing Python helpers inherit stub defaults (see P2-1).
- Fix:
  - Expose backend and recursive flags through wrapper/partner config; default verify paths to fail-closed.
- Resolution:
  - `prove_inference(..., backend="ezkl"|"risc0")` forwards `--backend` to the Rust CLI.
  - `AgentWrapper` accepts `prove_recursive` and `inference_backend`; partner YAML/env expose the same knobs.
  - Stub verify defaults were closed in P2-1.

### P2-21: `assurance_from_bundle()` trusts stored assurance for downstream consumers (SOTA-3 / SOTA-4) `[x]`

- Layer: `L4`
- SOTA: SOTA-3, SOTA-4
- Files:
  - [agentauth/receipts/assurance.py](../agentauth/receipts/assurance.py)
- Problem:
  - Compliance mapping and explain paths call `assurance_from_bundle()`, which returns stored `assurance` block fields (`has_composed_proof`, etc.) without re-verification.
- Evidence:
  - [assurance.py:211-228](../agentauth/receipts/assurance.py)
- Fix:
  - Recompute assurance from proof + live verification before compliance/SIEM export.
- Resolution:
  - When `execution_proof` is present, `assurance_from_bundle()` recomputes via `assurance_from_proof()` instead of trusting stored fields.

### P2-22: `ExecutionProof.verify()` short-circuits TEE checks when `composed_proof` is present (SOTA-2) `[x]`

- Layer: `L4`
- SOTA: SOTA-2
- Files:
  - [agentauth/receipts/proof.py](../agentauth/receipts/proof.py)
- Problem:
  - If `bundle.composed_proof` exists, verification returns after composed check and never runs `TEE_HYBRID` quote verification, even when `attestation_path == tee_hybrid`.
- Evidence:
  - Early return at [proof.py:133-139](../agentauth/receipts/proof.py); TEE branch at [proof.py:141-149](../agentauth/receipts/proof.py) is unreachable for composed bundles.
- Fix:
  - Run TEE verification when `attestation_path == TEE_HYBRID` regardless of composed proof presence, or reject `tee_hybrid` + composed as invalid.

### P2-23: `FULL_ZK` path treats inference proof as optional `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/proof.py](../agentauth/receipts/proof.py)
- Problem:
  - For `attestation_path == FULL_ZK`, only `policy_proof` is required; missing `inference_proof` adds no error.
  - Bundles labeled `full_zk` can verify with policy-only crypto.
- Evidence:
  - [proof.py:157-165](../agentauth/receipts/proof.py).
- Fix:
  - Define explicit attestation profiles; fail verification when `full_zk` lacks expected inference/composed artifacts.

### P2-24: MCP gateway executes tools in `shadow`/`recommend` mode despite policy violations (SOTA-5) `[x]`

- Layer: `L4`
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/mcp.py](../agentauth/receipts/mcp.py)
  - [agentauth/receipts/mcp_client.py](../agentauth/receipts/mcp_client.py)
- Problem:
  - `_should_block()` returns `True` only in `bounded_auto`.
  - In `shadow`/`recommend`, policy/delegation violations are logged but handlers still run, causing real side effects while producing “violation” receipts.
- Evidence:
  - [mcp.py:187-192](../agentauth/receipts/mcp.py); handler invoked after violations at [mcp.py:262-276](../agentauth/receipts/mcp.py).
- Fix:
  - Default to block-on-violation for external side-effect tools; gate execution behind explicit `allow_unsafe_execution` in shadow mode.
- Resolution:
  - `_should_block()` blocks non-read-only tools in `shadow`/`recommend` when violations exist; `allow_unsafe_execution=True` opts out.
  - `prove` and other modes log violations but do not block by default.

### P2-25: Reference fraud MCP server exposes tools over HTTP/SSE without authentication (SOTA-5) `[x]`

- Layer: `L4` / ops
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/mcp_server.py](../agentauth/receipts/mcp_server.py)
  - [agentauth/receipts/mcp_client.py](../agentauth/receipts/mcp_client.py)
- Problem:
  - SSE/streamable HTTP transports bind on configurable `--host`/`--port` with no auth, mTLS, or tool ACL.
  - Any network client can invoke fraud tools if exposed beyond localhost.
- Fix:
  - Require auth token/mTLS for non-stdio transports; document non-production scope.
- Resolution:
  - HTTP transports wrap Starlette apps with `ApiKeyMiddleware` when `AGENT_RECEIPTS_MCP_API_KEY` is set; non-localhost binds without a key exit immediately.
  - `McpConnectionSpec.http_headers()` forwards the key to SSE/streamable HTTP clients; documented in `docs/mcp_live_server.md`.

### P2-26: Authority `budget_refs` and `approval_refs` are ignored by L3 engine `[x]`

- Layer: `L3`
- Status: **Done** — `_authority_ref_violations()` enforces `budget_refs` and `approval_refs` against authorization context.
- Files:
  - [agentauth/receipts/policy_engine.py](../agentauth/receipts/policy_engine.py)
  - [agentauth/receipts/runtime.py](../agentauth/receipts/runtime.py)
- Problem:
  - `AuthorityContext` carries `resource_scope`, `budget_refs`, and `approval_refs`, but `_authority_violations()` never evaluates them (extends partially-fixed P1-1).
- Evidence:
  - Fields at [runtime.py:106-108](../agentauth/receipts/runtime.py); `_authority_violations()` stops at capabilities ([policy_engine.py:86-109](../agentauth/receipts/policy_engine.py)).
- Fix:
  - Enforce resource scope against `ActionDescriptor` / `touched_resources`; require budget/approval refs when present.
- Resolution:
  - `_authority_ref_violations()` checks `approval_refs` against authorization `approval_id` and `budget_refs` against `budget_id`.

### P2-27: Session/composition digests use `serde_json::to_string(...).unwrap_or_default()` (SOTA-7 / SOTA-10) `[x]`

- Layer: `L4` / proof systems
- SOTA: SOTA-7, SOTA-10
- Files:
  - [crates/agent-receipts-session/src/envelope.rs](../crates/agent-receipts-session/src/envelope.rs)
  - [crates/agent-receipts-session/src/fold.rs](../crates/agent-receipts-session/src/fold.rs)
  - [crates/agent-receipts-composed/src/recursive.rs](../crates/agent-receipts-composed/src/recursive.rs)
- Problem:
  - On serialization failure, digests hash empty strings instead of failing closed, weakening binding uniqueness.
- Evidence:
  - [envelope.rs:77](../crates/agent-receipts-session/src/envelope.rs); [fold.rs:109](../crates/agent-receipts-session/src/fold.rs); [recursive.rs:121-132](../crates/agent-receipts-composed/src/recursive.rs).
- Fix:
  - Propagate serialization errors; never default digest inputs to `""`.

### P2-28: Exported `policy.commitment` is never verified against execution proof `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - Bundles may include a `policy` section with `commitment`, but `verify_receipt_bundle()` only compares `certificate.policy_commitment` to `proof.policy_commitment`.
  - The visible policy metadata can disagree with the committed proof without failing verification.
- Evidence:
  - Policy embedded at export [export.py:104-111](../agentauth/receipts/export.py); verify only checks certificate at [export.py:353-360](../agentauth/receipts/export.py).
- Fix:
  - When `policy.commitment` is present, require it equals `proof.policy_commitment` and certificate commitment.

### P2-29: `compact_receipt_bundle()` strips fields required for full offline verification `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/export.py](../agentauth/receipts/export.py)
- Problem:
  - Compact export removes `output`, `certificate`, `execution_context`, `signatures`, and `audit_inclusion` — all inputs needed once P0-1/P0-2/P0-3 binding checks land.
  - Partners storing compact bundles cannot fully re-verify integrity even after hardening fixes ship.
- Evidence:
  - Keep-list at [export.py:212-227](../agentauth/receipts/export.py).
- Fix:
  - Either retain verification-critical commitments in compact form (hashes + cert ref) or document compact as non-verifiable archive-only.
- Resolution:
  - Compact export retains `output`, `execution_context`, `certificate`, `signatures`, `audit_inclusion`, `mandate`, and `policy`.

## P3

### P3-1: Verifier auth should use constant-time comparison `[x]`

- Layer: `L4`
- File:
  - [agentauth/receipts/verifier_auth.py](../agentauth/receipts/verifier_auth.py)
- Problem:
  - API keys are compared with `!=`.
- Evidence:
  - Comparison at [verifier_auth.py](../agentauth/receipts/verifier_auth.py:39).
- Fix:
  - Use `hmac.compare_digest`.

### P3-2: L1 node attestor registration barely validates `public_pem` `[x]`

- Layer: `L1`
- File:
  - [agentauth/backend/identity.py](../agentauth/backend/identity.py)
- Problem:
  - Registration accepts anything containing `"BEGIN"` as a public key.
- Evidence:
  - Validation is string-based at [identity.py](../agentauth/backend/identity.py:240).
- Fix:
  - Parse the key material on ingestion and reject invalid or unsupported public keys up front.
- Resolution:
  - `_validate_node_attestor_public_pem()` parses PEM with `load_pem_public_key`, requires RSA keys meeting configured minimum size, and stores canonical SPKI PEM.

### P3-3: `add_witness_cosignature()` bypasses consistency protocol (SOTA-5) `[x]`

- Layer: `L4`
- SOTA: SOTA-5
- Files:
  - [agentauth/receipts/witness.py](../agentauth/receipts/witness.py)
- Problem:
  - Low-level helper signs checkpoint cores without append-only / consistency checks; safe path is `Witness.cosign()` only.
- Fix:
  - Deprecate direct helper or gate behind explicit dev-only flag.
- Resolution:
  - `add_witness_cosignature(..., allow_unsafe=True)` required; default raises with guidance to use `Witness.cosign()`.

### P3-4: TDX attestation path is unimplemented but still reachable (SOTA-2) `[x]`

- Layer: `L4`
- SOTA: SOTA-2
- Files:
  - [agentauth/receipts/tee.py](../agentauth/receipts/tee.py)
- Problem:
  - `tdx_v1` quotes return stub/invalid; callers must not treat hybrid TDX paths as `tee_attested` without explicit blocking.
- Fix:
  - Reject `AttestationPath.TEE_HYBRID` with TDX quotes at export/verify until implemented.

### P3-5: SIEM/compliance exports omit SOTA extension fields (SOTA-4) `[x]`

- Layer: `L4`
- SOTA: SOTA-4
- Files:
  - [agentauth/receipts/compliance.py](../agentauth/receipts/compliance.py)
- Problem:
  - ECS/OTel/CEF mappers omit mandate grant id, TEE/EAT claims, audit inclusion, witness quorum, session proof mode, and recursive composition id.
- Fix:
  - Add optional verified extension block after live re-verification succeeds.
- Resolution:
  - `_verified_extension_fields()` populates `verified_extensions` in compliance records after live verification; covered by `test_siem_exports_include_verified_extension_fields`.

### P3-6: `audit-consistency` CLI reports success when verification was skipped (SOTA-1) `[x]`

- Layer: `L4`
- SOTA: SOTA-1
- Files:
  - [agentauth/receipts/cli.py](../agentauth/receipts/cli.py)
- Problem:
  - Without `--old-checkpoint`, command exits 0 because `verified` defaults to `True`.
- Evidence:
  - [cli.py:150](../agentauth/receipts/cli.py) — `return 0 if out.get("verified", True) else 1`.
- Fix:
  - Default `verified` to omitted; exit non-zero unless verification explicitly ran and passed.

### P3-7: `AgentWrapper` auto-materializes unsigned `dev_certificate` when none is supplied `[x]`

- Layer: `L4`
- Files:
  - [agentauth/receipts/wrapper.py](../agentauth/receipts/wrapper.py)
  - [agentauth/receipts/certificate.py](../agentauth/receipts/certificate.py)
- Problem:
  - Missing cert path silently creates a fresh unsigned dev certificate, easy to ship to production without PKI.
- Evidence:
  - [wrapper.py:147-153](../agentauth/receipts/wrapper.py); `dev_certificate()` explicitly unsigned ([certificate.py:136](../agentauth/receipts/certificate.py)).
- Fix:
  - Require explicit cert in non-shadow modes; fail preflight when `issuer_signature` is absent in production profiles.

### P3-8: Minimum trust tier from authority is never enforced in L3 engine `[x]`

- Layer: `L3`
- Files:
  - [agentauth/receipts/policy_engine.py](../agentauth/receipts/policy_engine.py)
  - [agentauth/receipts/policy.py](../agentauth/receipts/policy.py)
- Problem:
  - Policy or deployment config may require a minimum authority trust tier, but `_authority_violations()` never compares `authority.trust_tier` against policy thresholds (partial P1-1 remainder).
- Fix:
  - Add optional `min_trust_tier` to policy/deployment config and enforce in `_authority_violations()`.
- Resolution:
  - `Policy.min_trust_tier` (YAML + commitment) enforced in `_authority_violations()` via `meets_assurance_threshold()`.

## Recommended order

### Pre-SOTA core

1. ~~`P0-1` receipt output/context binding~~ `[x]`
2. ~~`P0-2` certificate binding and certificate verification~~ `[x]` *(partial — issuer sig still open)*
3. ~~`P0-3` trust-anchored envelope signatures~~ `[x]` *(trust store via env; docs still open)*
4. ~~`P1-1` enforce authority semantics in the L3 policy engine~~ `[x]`
5. `P1-2` through `P1-5` for the L1 identity path
6. `P2-2`, `P2-3`, `P2-8` verifier deployment and local key handling *(P2-1, P3-1 done)*

### SOTA pass (new — after or in parallel with P0 core)

1. **`P0-4`** recursive composed verify must re-check sub-proofs (blocks false `composed_proved` tier)
2. **`P1-9`** recompute assurance for tier thresholds (blocks assurance inflation)
3. **`P1-15` / P1-20`** composed range mismatch + policy-prover degradation (wrong ZK semantics)
4. **`P1-11`** wire audit inclusion into `verify_receipt_bundle()`
5. **`P1-10` / P1-6` / P1-17`** mandate issuer + delegate + delegation signing
6. **`P1-12` / P1-13` / P1-14`** session fold soundness + inference journal/envelope bindings
7. **`P1-16` / P1-18` / P1-19` / P1-21`** MCP args binding + certificate/provenance + policy_satisfied cross-checks
8. **`P2-9` … P2-29`** witness quorum, compliance integrity, TEE/composed interaction, compact export gaps
