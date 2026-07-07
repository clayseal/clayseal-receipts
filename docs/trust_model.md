# Trust model

## What verifiers get

Given an `ExecutionProof` (or full receipt bundle) and the operator-published verification key:

1. The action hash chain entry links to a specific proof.
2. The proof commits to a policy hash and certificate hash.
3. The `assurance` block states an honest trust tier (`shadow`, `policy_proved`, `composed_proved`, etc.).
4. The `evidence.summary` block summarizes proof presence without duplicating bytes.
5. (When wired) Cryptography attests inference + policy — or a **verified** Nitro TEE quote (`nitro_enclave_v1`) + policy in hybrid mode. See [tee_attestation.md](tee_attestation.md).
6. The policy proof **binds the committed output and policy** into its public inputs, so a receipt's `output_hash` / `policy_commitment` cannot be swapped after proving without failing verification.
7. Ed25519 envelope signatures only count as trusted evidence when the verifier is configured with a trusted signer policy; the audit chain exposes a **signed Merkle checkpoint** that detects a full-chain rewrite.

Structured verification returns machine-readable `issues[]` codes (`schema_mismatch`, `decision_mismatch`, `proof_invalid`, …) alongside human `reasons[]`.

Verifiers do **not** need model weights, raw inputs, or raw outputs — only commitments and proofs.

## What verifiers do not get (v0)

- Third-party model training attestation (RMA is future work)
- Semantic guarantees on free-text outputs without approximate policies
- Protection against TEE hardware compromise in hybrid mode

## Threat model summary

| Threat | Mitigation |
|--------|------------|
| Operator publishes fake Agent Card | Certificate + proof bind model/policy hashes |
| Agent exceeds policy | Policy circuit / software check; `policy_satisfied` false |
| Output/policy swapped after proving | `output_hash` + `policy_commitment` bound into the `policy_range_v3` public inputs; verification fails on mismatch |
| Forged receipt bundle | Ed25519 envelope signatures checked against an explicit trusted signer policy (see below) |
| Audit log tampering | Hash chain verification + per-record Ed25519 signatures (`verify_signatures`) |
| Full audit-chain rewrite | Signed Merkle checkpoint (`signed_checkpoint` / `verify_checkpoint`) anchored to the signer's key |
| Stolen OAuth token | OAuth still required; receipts add execution binding |
| TEE compromise (hybrid) | Model provenance weakens; policy ZK still holds over attested bytes |

## Trusted signer policy (envelope signatures)

Receipt bundles may carry one or more Ed25519 envelope signatures over the exported JSON.
Verification is **not** self-authenticating: `verify_receipt_bundle()` reconstructs the
signer's public key from the signature object but only accepts it when the key is pinned
by operator configuration.

Configure at least one of:

| Variable | Purpose |
|----------|---------|
| `AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS` | Comma-separated Ed25519 public keys (hex) allowed to sign bundles |
| `AGENT_RECEIPTS_TRUSTED_SIGNER_KEY_IDS` | Comma-separated stable `key_id` values (sha256 of public key material) |
| `AGENT_RECEIPTS_TRUSTED_SIGNERS` | Legacy alias: comma-separated public keys (optional `ed25519:` prefix) |

Receipt bundle signatures are required by default. A bundle with no `signatures[]`
fails verification with `signature_invalid`; a signed bundle without a trusted signer
policy also fails closed. Each signature must pass `signature_key_id_matches()` so the
embedded `key_id` binds to the claimed `public_key`.

For local demos only, set `AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=0` to inspect
unauthenticated but internally self-consistent bundles.

## Trusted certificate issuers

Agent certificates are also expected to be signed by a trusted issuer:

| Variable | Purpose |
|----------|---------|
| `AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_PUBLIC_KEYS` | Comma-separated Ed25519 public keys (hex) allowed to issue agent certificates |
| `AGENT_RECEIPTS_TRUSTED_CERTIFICATE_ISSUER_KEY_IDS` | Comma-separated issuer `key_id` values |

Unsigned certificates are rejected by default. Set
`AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE=1` only for local shadow-mode development.

## Policy trust-tier gate

Receipt assurance (`assurance.tier`) is derived from verified proof, TEE, or signature
evidence. Policy gating on `policy.min_trust_tier` follows the same fail-closed rule:
caller-supplied authority dictionaries may declare `declared` or `signed`, but higher
tiers are ignored or rejected unless the authority came from verified Clay Seal identity
evidence. In practice, `AuthorityBinding.from_agentauth_credential()` marks the binding
as verified and derives `sender_constrained` from proof-of-possession, presenter key
binding, and a capability grant. Plain JSON cannot set the internal
`evidence_verified` flag.

Related audit-log trust env vars (inclusion / consistency proofs):

- `AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_PUBLIC_KEYS` / `AGENT_RECEIPTS_TRUSTED_AUDIT_LOG_KEY_IDS`
- `AGENT_RECEIPTS_TRUSTED_AUDIT_WITNESS_KEYS` / `AGENT_RECEIPTS_REQUIRED_AUDIT_WITNESSES`
- `AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT=1` — local dev only; unsigned checkpoints are rejected for portable evidence otherwise.

## Honest capability matrix

| Policy class | v0 | Full ZK |
|--------------|----|---------|
| Numeric bounds | Software + Halo2 `policy_range_v3` (range + output/policy binding + required fields) | Partial |
| Required JSON fields | Software + planned circuit | Yes |
| Tool calls authorized by Biscuit capabilities (bounded window) | Planned | Partial |
| No PII in text | Approximate only | No (v1) |

Document approximate policies as `capability: operator_attested` or `semantic_approx`.

## Confidential compliance (SOTA-9)

The transparent `policy_range_v3` circuit exposes the score as a **public input** — a verifier
checking it learns the output value. For regulated or multi-party settings where the output `y`
itself is sensitive, the **confidential** circuit (`policy_range_confidential_v1`) proves the
policy held over `y` **without disclosing `y`**.

How it works:
- The scaled score is a **private witness**; the proof reveals only a Poseidon commitment
  `score_commitment = Poseidon(score, blinding)` (hiding via the random blinding, binding via the
  hash). The range check `min <= score < max` is enforced **in-circuit** on the same committed
  cell, so the proof cannot be satisfied by a different in-range value.
- Public inputs: `score_commitment`, `min`, `max`, `output_commitment`, `policy_commitment`. The
  policy bounds are public (the policy is not secret); the output value is not.
- `prove_policy_range_confidential` / `verify_policy_range_confidential` (and
  `clay-seal-receipts prove-policy-confidential` / `verify-policy-confidential`). The verifier confirms the
  hidden score lies in range and is bound to the published commitment, learning nothing else.

An auditor with the opening `(score, blinding)` can later re-derive the commitment to reveal the
value on a need-to-know basis — commit now, disclose selectively.

### Policy classes: confidential vs software-only

| Policy class | Confidential (in-circuit, hides `y`) | Transparent / software only |
|--------------|--------------------------------------|------------------------------|
| Numeric range on score (`min <= y < max`) | **Yes** — `policy_range_confidential_v1` | `policy_range_v3` (score public) |
| Commitment binding of `y` | **Yes** — Poseidon, hiding + binding | sha256 `output_hash` (no hiding) |
| Required JSON fields present | No — stays a transparent/software check | `policy_range_v3` presence mask |
| Binding score ↔ full output JSON | No — link to `output_hash` stays software (no in-circuit sha256) | software |
| Tool-call capability checks / semantic policies | No | approximate / software |

The confidential variant covers exactly the numeric-range policy class with a hiding commitment;
everything else (required-field presence, full-output binding, semantic checks) remains a
transparent or software check, and is documented as such.

| Threat | Mitigation |
|--------|------------|
| Verifier learns a sensitive output while checking compliance | `policy_range_confidential_v1`: score is a private witness; only a hiding commitment is public |
| Prover proves range for a value other than the committed output | In-circuit Poseidon binds the range-checked cell to the public `score_commitment` |

## Notarized Agents reconciliation (SOTA-16)

[*Notarized Agents* / Sello](https://arxiv.org/abs/2606.04193) inverts the trust boundary for
observability: the **called service** signs what it saw, HPKE-seals to the owner, and publishes
ciphertext to a witness-cosigned Merkle log. **This repository** inverts a different boundary for
**compliance**: ZK policy/inference proofs plus SCITT transparency-service receipts. The paper
compares against [agentreceipts.ai](https://agentreceipts.ai) (agent-signed W3C VCs), not this
codebase. The models are complementary — divergence between self-reported traces, witnessed tool
calls, and our ZK compliance bundle is itself an anomaly signal.

### Two confidentiality layers (keep both)

| Layer | Mechanism | Hides what | From whom |
|-------|-----------|------------|-----------|
| **Compliance privacy** (SOTA-9) | ZK + Poseidon commitment | Output score `y` | Verifier checking policy |
| **Transport privacy** (SOTA-11) | HPKE seal on canonical CBOR | Full bundle body | Public log / passive observers |

Sello's transport privacy maps to our `scitt_bundle` HPKE path; SOTA-9 remains the differentiator
Sello lacks.

### Additive borrows (witness layer)

| Borrow | Our use |
|--------|---------|
| `owner_hpke_pk` in mandate/WIT | Services learn the HPKE recipient from a **verified** mandate, not agent-supplied bytes |
| Log-integrated-time revocation | Signer/witness keys revoked at audit `seq`; backdating after compromise is bounded |
| Tool co-signatures (`role: tool`) | MCP endpoints co-sign input/output hashes; does **not** replace the ZK bundle |
| `mandate_ref` log indexing | Owners reconstruct sessions from the transparency log without trusting agent exports |
| `witness_divergence` | Verifier flags side-effecting tool claims without a matching tool co-sign (best-effort) |

**Moat:** ZK compliance + SCITT log. Sello borrows are witness-layer add-ons, not a pivot.
