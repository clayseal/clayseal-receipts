# Combined-corpus SOTA review — are we using the best approaches?

A whole-system review across the unified corpus: **L1/L2** (agent identity + capability
authorization), **L3/L4** (decision semantics + receipts), and the **evidence plane** (ZK proofs,
transparency log, attestation, confidential/aggregated proofs). It does **not** re-survey the gaps
already closed — [state_of_the_art.md](state_of_the_art.md) (evidence plane, SOTA-1…10 all done)
and [l1_l2_sota_assessment.md](l1_l2_sota_assessment.md) (identity/authz) cover those. Instead it
**stress-tests the specific approaches we *chose*** against the mid-2026 frontier, to find places
where an implemented choice has quietly become the *legacy* option.

**Method.** Read the implemented mechanisms across both branches, then checked each against current
standards drafts, proving-system benchmarks, and 2026 papers (citations inline). Confidence is
called out; "swap" recommendations note migration cost.

## Headline thesis

Our building blocks are individually strong and, in several places, ahead of peers. The systemic
weakness is **encoding, not architecture**: we use bespoke JSON + ad-hoc Merkle/PoP/receipt formats
where the industry has, in the last ~12 months, converged on **standard ones** — and a few
base-layer primitives we picked now have faster or standardized successors.

> **The single highest-leverage move across the whole corpus is to adopt the IETF SCITT + COSE
> "Receipt" model.** It is, almost exactly, the abstraction we built by hand — a *signed statement*
> plus a *transparency receipt* (a COSE-signed Merkle inclusion proof) — and adopting it unifies our
> receipts (L4), our transparency log (SOTA-1/5), and our assurance tiers into one interoperable
> standard that the newest comparable papers and products are *also* converging on.

---

## Cross-corpus scorecard

| Domain | What we implemented | 2026 SOTA | Verdict |
|--------|---------------------|-----------|---------|
| **Receipt / statement format** | bespoke JSON bundle + Ed25519 (`sign_bundle`) | **SCITT** Signed/Transparent Statements + **COSE Receipts** (COSE_Sign1/CBOR) | **Reinventing a standard** |
| **Transparency log checkpoint** | bespoke signed checkpoint (SOTA-1) → **now also C2SP signed-note + RFC 6962 root** | C2SP signed note; tile-based serving | **Checkpoint done; tile-serving open** |
| **Inclusion/consistency proof wire format** | custom Python hashes/JSON (SOTA-1); RFC 6962 inclusion added for C2SP | **COSE Receipts** (`draft-ietf-cose-merkle-tree-proofs`, RFC 9162 profile) | **Right tree; COSE encoding open (finding A)** |
| **Inference zkVM** | **RISC Zero** (SOTA-8) | **SP1 on Plonky3** (~5× faster CPU, most precompiles); Jolt | **Good, not fastest** |
| **Policy proof system** | **Halo2 + pasta/IPA** `policy_range_*` | Halo2 still fine; richer policies → **SP1/Plonky3** | **OK for the narrow class** |
| **Confidential commitment hash** | **Poseidon** (P128Pow5T3) (SOTA-9) | **Poseidon2** (~70% fewer constraints); **Monolith** | **Superseded primitive** |
| **Evidence/trace schema** | bespoke `execution_context` | **OpenTelemetry GenAI** semantic conventions | **Should align** |
| **L1 identity / L2 PoP** | EdDSA JWT-SVID + `cnf`, Biscuit + WPT-style PoP (just hardened) | WIMSE **WIT/WPT**, DPoP | **Hardened; standard wire format still pending** |
| **L3 mandates / call-chain** | `BudgetEffect`/approval; AP2 mandate binding (SOTA-6) | AP2 Mandates; **Transaction-Tokens-for-Agents** (`act`) | **Aligned; add Txn-Token chain** |

---

## Findings & improvements

### A. Adopt SCITT + COSE Receipts for the receipt/transparency layer (highest leverage)

We literally ship "receipts," but as bespoke signed JSON. IETF **SCITT**
([draft-ietf-scitt-architecture-22](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/))
standardizes precisely our model: a **Signed Statement** (the claim) becomes a **Transparent
Statement** once a **Transparency Service** registers it and returns a **Receipt** — a COSE-signed
inclusion proof carried in the COSE envelope's unprotected header. The receipt's proof is a **COSE
Receipt** ([draft-ietf-cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)),
a CBOR encoding of a verifiable-data-structure proof with **RFC 9162 as the worked example** — i.e.
the *exact* Merkle inclusion/consistency proofs we built in SOTA-1, just in the standard wire format.

This isn't theoretical convergence: the freshest comparable work uses this stack. A June-2026
reference implementation "constructs verified JWS authorization tokens, creates receipts with **HPKE
seal and COSE_Sign1 signing**, and submits signed envelopes to **transparency logs**," and **Signet**
(MCP middleware) does bilateral COSE co-signing of response receipts. We are building the same thing
with non-interoperable encodings.

> **A1.** Express the receipt bundle as a SCITT **Signed Statement** (COSE_Sign1/CBOR), our audit
> log as a **Transparency Service**, and our SOTA-1 inclusion proof as the embedded **COSE Receipt**
> (RFC 9162 profile). Keep the JSON view as a convenience projection. This makes our receipts
> verifiable by any SCITT-aware tool and folds SOTA-1/5 into an adopted standard.
> **A2.** Map our `AssuranceLevel` tiers to SCITT's statement metadata so a relying party reads
> assurance from a standard envelope.

### B. Move the transparency log to tile-based / Static-CT (RFC 6962 is being retired)

SOTA-1 implemented **classic, dynamic RFC 6962** (per-request `get-proof-by-hash`-style proofs).
The ecosystem has already moved: the **Static CT API** / C2SP **`tlog-tiles`** serves the tree as
**static, cacheable tiles** (256-entry subtrees) with **no dynamic proof endpoints**, and **Sunlight**
is the reference log. Crucially, **Let's Encrypt is shutting down its RFC 6962 logs on 2026-02-28**
in favor of Static-CT ([EOL plan](https://letsencrypt.org/2025/08/14/rfc-6962-logs-eol),
[C2SP static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md),
[tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md)). Our checkpoint and witness work
(SOTA-1/5) is RFC-6962-flavored; the SOTA is the **C2SP signed-checkpoint ("signed note") format +
tile layout**, which is also what the modern witness/monitor ecosystem speaks (see the IETF
**PLANTS** BoF for where this is heading).

> **B1. [IMPLEMENTED]** Adopt the **C2SP checkpoint (signed-note) format** for the checkpoint so our
> witnesses (SOTA-5) interoperate with the existing witness network instead of a private format.
> Done in [`agentauth/receipts/c2sp.py`](../agentauth/receipts/c2sp.py) +
> `AuditChain.c2sp_checkpoint(origin)`: emits a **standards-correct RFC 6962 Merkle root**
> (domain-separated `0x00`/`0x01` hashing — distinct from our internal hex-concat tree) serialized
> as a signed note (Ed25519, exact note key-id + blank-line-then-signature format), with a matching
> `rfc6962_inclusion_proof`. Covered by `python/tests/test_c2sp.py` (RFC 6962 known-answer vectors +
> note sign/verify/tamper + chain integration).
> **B2.** Still open: a **tile-based static export** (cacheable `tlog-tiles`) alongside the SQLite
> path, and migrating the *internal* inclusion/consistency proofs onto the RFC 6962 hashing so the
> JSON and C2SP views share one tree (folds into finding A).

### C. Inference zkVM: RISC Zero is fine, but SP1 (Plonky3) is the current performance leader

SOTA-8 chose **RISC Zero** — a sound, mature pick that we proved end-to-end. But 2026 benchmarks put
**SP1** (on **Plonky3**, "the fastest ZK proving system") at **~5× RISC Zero on CPU**, with the most
complete precompile set (keccak, sha256, **ed25519**, bn254/bls12-381), and Jolt close behind
([Succinct SP1](https://blog.succinct.xyz/sp1-testnet/),
[Polygon Plonky3](https://polygon.technology/blog/open-source-polygon-plonky3-is-once-again-the-fastest-zk-proving-system),
[a16z zkvm-benchmarks](https://github.com/a16z/zkvm-benchmarks)). The ed25519 precompile matters for
*us* specifically: verifying our Ed25519 receipt/checkpoint signatures *inside* a zkVM (e.g. to prove
"this receipt was in a witnessed checkpoint") is far cheaper on SP1.

> **C1.** Keep RISC Zero as the working baseline; **benchmark an SP1 port** of the fraud-head guest
> and the (future) recursive composition. If the ~5× holds for our workload, SP1 becomes the default
> and Plonky3 becomes the natural base for richer policy circuits (below). *Confidence: directional —
> zkVM benchmarks are point-in-time; validate on our actual guests.*

### D. Confidential commitment: Poseidon2 — but it's coupled to the Plonky3 move, not standalone

SOTA-9's confidential policy circuit commits the private score with **Poseidon** (`P128Pow5T3`).
**Poseidon2** ([ePrint 2023/323](https://eprint.iacr.org/2023/323.pdf)) is the faster successor —
up to **~70% fewer Plonk constraints** via cheaper linear layers — and **Monolith**
([ToSC](https://tosc.iacr.org/index.php/ToSC/article/download/11810/11315/12843)) is faster still.

> **Correction (verified against the code):** Poseidon2 is *only* a drop-in in the **Plonky3** world.
> Our circuit uses **Halo2 + `halo2_gadgets` 0.5 / `halo2_poseidon` 0.1**, which ship **only the
> original Poseidon `Pow5` chip — no Poseidon2 chip exists in that stack**. So this is **not** a
> standalone quick win: it would mean either depending on an unproven third-party Poseidon2 Halo2
> chip (none found for `halo2_proofs` 0.3 / pasta) or hand-writing the Poseidon2 permutation (real
> effort, real risk). The honest path is to land Poseidon2/Monolith **as part of the SP1/Plonky3
> migration (finding C)**, where they're native, rather than hand-roll a chip now.

> **D1.** Defer Poseidon2 to the Plonky3/SP1 track (finding C); do **not** hand-roll a Halo2
> Poseidon2 chip for a marginal proof-size win.

### E. Align the evidence/trace schema to OpenTelemetry GenAI semantic conventions

Our `execution_context` captures action/tool/authority evidence in a bespoke shape. The industry
standard for agent traces is now **OpenTelemetry GenAI semantic conventions** (tool-use events,
reasoning spans), described as "table stakes" for 2026 agent observability
([OTel GenAI](https://opentelemetry.io/blog/2025/ai-agent-observability/)). Our SOTA-4 SIEM/OTel
export already leans this way; aligning the *capture* schema (not just export) means receipts drop
into existing observability/SIEM pipelines without translation.

> **E1.** Map `execution_context` / evidence fields to OTel GenAI semconv attributes; emit receipts
> as (signed) OTel log records in addition to the bundle. High buyer value, no crypto.

### F. L1/L2 and L3 — mostly current, two standard envelopes still pending

L1/L2 were just hardened (EdDSA, `cnf` key-binding, request-bound PoP, revocation, single-use
challenges) per [l1_l2_hardening.md](l1_l2_hardening.md). The remaining SOTA delta is **wire-format
standardization** — express the key-bound SVID + request-bound proof as WIMSE **WIT/WPT** JWTs — and,
at L3, emit/consume **Transaction-Tokens-for-Agents** (the `act` call-chain) so delegation feeds the
receipt's authority lineage. AP2 mandate binding (SOTA-6) is already current. These are tracked there;
they reinforce the same theme as A/B: *adopt the standard envelope, keep the mechanism.*

### G. Competitive / academic frontier (newer than the existing source map)

- **"Notarized Agents: Receiver-Attested Confidential Receipts for AI Agent Actions"**
  ([arXiv 2606.04193](https://arxiv.org/html/2606.04193v1), Jun 2026) — a brand-new, near-identical
  thesis to ours combining **confidential receipts + receiver attestation**. Closest new comparable;
  read before finalizing the confidential-receipt design (intersects SOTA-9 + A).
- **"Clay Seal Receipts" open spec** (Ed25519 + **W3C Verifiable Credentials**) and **Signet** (MCP
  middleware, bilateral COSE co-signing) — the name and category now have other occupants; our
  differentiation must stay the **ZK policy/inference proofs + transparency-service receipts**, not
  "signed JSON." Reinforces adopting COSE/SCITT so we interoperate rather than fork the term.
- Still-valid anchors from [state_of_the_art.md](state_of_the_art.md): *Right to History* (sovereignty
  kernel), *Show Me You Comply…* (confidential compliance), Dapr verifiable execution, SCITT/Sigstore.

---

## Prioritized recommendations

| Priority | Move | Effort | Status |
|----------|------|--------|--------|
| **P1** | (B1) C2SP signed-note checkpoint + RFC 6962 root | M | **Implemented** (`c2sp.py`, 9 tests) |
| **P0** | (A) SCITT + COSE-Receipt envelope for receipts/log/proofs | M–L | Open — the cross-cutting standards alignment; folds in SOTA-1/5 and B2 |
| **P1** | (E) OTel GenAI semconv alignment for evidence | S–M | Open — drops receipts into existing observability/SIEM |
| **P1** | (C) Benchmark an **SP1/Plonky3** port of the zkVM leg | M | Open — ~5× faster + ed25519 precompile; carries Poseidon2 (D) with it |
| **P2** | (D) Poseidon2/Monolith commitment | — | **Folded into C** (no Halo2 Poseidon2 chip exists; not standalone) |
| **P2** | (B2) Tile-based static log export | M | Open — RFC 6962 dynamic logs being retired |
| **P2** | (F) WIMSE WIT/WPT + Txn-Tokens-for-Agents envelopes | M–L | Open — standard wire formats for hardened L1/L2/L3 mechanisms |
| **P2** | (G) *Notarized Agents* additive borrows (16a–16f) | S–M | **Research done** — witness co-sign, token-bound HPKE, log-integrated revocation; see SOTA-16 |

**Net.** We are *not* behind on architecture — in several pillars we're ahead. We are behind on
**adopting the standard encodings the field converged on in the last year** (SCITT/COSE receipts,
Static-CT/C2SP logs, OTel GenAI) and on **two base-layer primitives with faster successors** (SP1/
Plonky3, Poseidon2). The P0/P1 items are mostly *re-expression and primitive swaps*, not redesigns,
and they convert "strong but bespoke" into "strong and interoperable" — which is what turns this from
a good implementation into the category standard.

---

## References

- SCITT — [architecture-22](https://datatracker.ietf.org/doc/draft-ietf-scitt-architecture/) ·
  COSE Receipts — [cose-merkle-tree-proofs-18](https://datatracker.ietf.org/doc/draft-ietf-cose-merkle-tree-proofs/)
- Transparency logs — [C2SP static-ct-api](https://github.com/C2SP/C2SP/blob/main/static-ct-api.md) ·
  [C2SP tlog-tiles](https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md) ·
  [Sunlight](https://sunlight.dev/) · [RFC 6962 EOL](https://letsencrypt.org/2025/08/14/rfc-6962-logs-eol) ·
  [PLANTS BoF](https://datatracker.ietf.org/doc/bofreq-westerbaan-pki-logs-and-tree-signatures-plants/)
- Proof systems — [SP1 testnet](https://blog.succinct.xyz/sp1-testnet/) ·
  [Plonky3 (Polygon)](https://polygon.technology/blog/open-source-polygon-plonky3-is-once-again-the-fastest-zk-proving-system) ·
  [a16z zkvm-benchmarks](https://github.com/a16z/zkvm-benchmarks) · [Jolt FAQ](https://a16zcrypto.com/posts/article/faqs-on-jolts-initial-implementation/)
- Hashes — [Poseidon2 (ePrint 2023/323)](https://eprint.iacr.org/2023/323.pdf) ·
  [Monolith (ToSC)](https://tosc.iacr.org/index.php/ToSC/article/download/11810/11315/12843) ·
  [Poseidon2 in Plonky3](https://hackmd.io/@sin7y/r1VOOG8bR)
- Agent evidence — [Notarized Agents (arXiv 2606.04193)](https://arxiv.org/html/2606.04193v1) ·
  [OTel GenAI observability](https://opentelemetry.io/blog/2025/ai-agent-observability/)
- See also: [state_of_the_art.md](state_of_the_art.md), [l1_l2_sota_assessment.md](l1_l2_sota_assessment.md),
  [landscape_research.md](landscape_research.md)
</content>
