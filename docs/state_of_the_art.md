# State of the Art: Verifiable Agent Execution Evidence

**Last updated:** 2026-06-19

## Purpose

[landscape_research.md](landscape_research.md) maps the **identity / authorization / policy (L1–L3)** market — who is acting, what they may do, which PDP decides. This document covers the part that is Agent Receipts' actual technical moat: the **cryptographic evidence plane (L4)** — *proving what actually happened*. It assesses the state of the art for each primitive we depend on, places our current implementation against it, and proposes concrete improvements.

We are building, in the literature's emerging vocabulary, a **"sovereignty kernel" / verifiable agent execution layer**: cryptographic receipts that bind an agent's action to an authorized model, a committed policy, and a tamper-evident history. As of mid-2026 this is a *named, academically-articulated category* (see [Right to History](#a-direct-comparables-closest-systems-to-ours)) but has **no dominant production implementation** — the opportunity is real and still open.

## TL;DR gap assessment

| Pillar | What SOTA looks like | Where we are | Gap |
|--------|----------------------|--------------|-----|
| **Verifiable inference** ("ran on model M") | zkML proving GPT-2 / 13B-param LLMs; zkVMs (SP1, RISC Zero, Jolt); TEE+GPU attestation (NVIDIA CC) | EZKL path for a tiny ONNX fraud head; **stub by default** | **Largest gap.** Our headline "model provenance" claim is unproven without EZKL; no LLM-scale path; no TEE adapter |
| **Policy proofs** | Halo2/Plonkish + folding/recursion (Nova, SP1) for aggregation | Halo2 `policy_range_v3`: range + output/policy binding + required-field mask | Solid for structural policies; no recursion/aggregation; narrow policy class |
| **Tamper-evident log** | Merkle transparency logs w/ signed checkpoints, **inclusion + consistency proofs**, witnessing/gossip (Rekor/Trillian, CT 2.0) | Hash chain + signed Merkle checkpoint + per-record signatures | Missing inclusion/consistency proofs and external witnessing; no log-equivocation defense |
| **Attestation & trust tiers** | RATS (RFC 9334) roles + EAT; layered assurance taxonomy | `AssuranceLevel` enum; Ed25519 receipt/audit signatures | No RATS/EAT alignment; no TEE quote verification (stub); tiers not mapped to a standard |
| **Decision / authority / budgets** | AP2 signed *Mandates*; AuthZEN AARP; XACML obligations | `DecisionResult`, obligations, budget effects, approval state | Strong vs peers; no signed mandate model; budget ledger is a hook only |
| **Compliance mapping** | EU AI Act / NIST-aligned, machine+human audit fields | Receipts + explain + auditor summary | No formal control-to-field mapping or certified export |

**One-line read:** our *evidence-plane architecture is at or ahead of the published state of the art*, but our *verifiable-inference leg is far behind it* and our *transparency log is missing the proofs that make CT-class logs trustworthy against a malicious log operator*.

---

## 1. Verifiable inference — proving "this ran on model M"

This is the pillar where the field has moved fastest and where we are furthest behind.

### State of the art (2025–2026)
- **The "zkML singularity" (H2 2025):** zkML crossed from research toy to production infrastructure for *meaningful* models.
  - **Lagrange DeepProve-1** — first production-ready zkML to prove a **full GPT-2 (124M)** inference. ([Lagrange](https://www.lagrange.dev/deepprove))
  - **zkPyTorch** (Polyhedra, Mar 2025) — compiles PyTorch → ZK circuits directly; **VGG-16 (138M) in ~2.2s**, claims **1000×+ over baseline EZKL**. ([IACR ePrint 2025/535](https://eprint.iacr.org/2025/535))
  - **zkLLM** — verifies a **13B-param** model inference in **<15 min** with a **<200 kB** proof. ([arXiv 2404.16109](https://arxiv.org/pdf/2404.16109))
  - **NANOZK** — layerwise ZK proofs for verifiable LLM inference. ([arXiv 2603.18046](https://arxiv.org/pdf/2603.18046))
- **Two architectural camps:**
  1. **Model-specific circuits** (EZKL/Halo2, zkCNN, zkPyTorch): smallest proofs, but per-model setup. **This is the camp we are in.**
  2. **zkVMs** — run inference as a normal Rust program inside **SP1** (Succinct), **RISC Zero**, or **Jolt** (a16z); general-purpose, **no per-model trusted setup**, easier to maintain as models change. The emerging default for flexibility.
- **Optimistic + ZK hybrids:** **opML / zk-OPML** — assume-correct then prove-on-dispute; scales to large models cheaply. ([Springer zk-OPML](https://link.springer.com/article/10.1007/s44443-026-00573-1))
- **Decentralized/publicly-verifiable inference:** **VeriLLM** ([arXiv 2509.24257](https://arxiv.org/pdf/2509.24257)), Fortytwo swarm inference ([arXiv 2510.24801](https://arxiv.org/pdf/2510.24801)).
- **TEE alternative (the pragmatic LLM-scale path):** **NVIDIA GPU Confidential Computing** gives each GPU a hardware-fused device identity + Device Identity Certificate and attests via **RATS**; pairs with **Intel TDX / AMD SEV-SNP** CPU enclaves. This is how you get "ran on model M at scale" *today* without ZK-proving a transformer. ([NVIDIA GPU-CC demystified, arXiv 2507.02770](https://arxiv.org/pdf/2507.02770))

### Where we are
- EZKL export for one small ONNX fraud head; **inference falls back to a hard-coded stub** when the `ezkl` binary is absent (the common case), so the model-provenance pillar is asserted, not attested. Composition is *logical* (verify both sub-proofs + hash bindings), not a single recursive proof.

### Gap & implication
- We are ~1 generation behind on framework (still raw EZKL/Halo2; the field moved to zkPyTorch-class compilers and zkVMs) and we have **no LLM-scale story at all**. Realistically, LLM-scale provenance should come from **TEE attestation (RATS/EAT)**, not ZK, with ZK reserved for the small classifier/policy heads where it's cheap.

---

## 2. Policy proofs & proof systems

### State of the art
- **Plonkish / Halo2** remains a mainstream production choice (it's what EZKL uses). Our circuit is idiomatic here.
- **Folding / recursion is the scaling unlock:** **Nova** ([ePrint 2021/370](https://eprint.iacr.org/2021/370.pdf), [microsoft/Nova](https://github.com/microsoft/Nova)) reduces checking N steps to checking one; **MicroNova** (IEEE S&P 2025) adds cheap on-chain verification; broader survey in [awesome-folding](https://github.com/lurk-lab/awesome-folding). This is the standard way to **aggregate a session of receipts into one proof** — directly relevant to "compress 2,500 receipts" from our origin brainstorm.
- **zkVMs** (SP1 on Plonky3 STARKs; Jolt on sumcheck + Lasso lookups) are now credible for general computation, including continuations/recursion.
- **Reality check:** [*SoK: Understanding zk-SNARKs — the gap between research and practice*](https://arxiv.org/pdf/2502.02387) (2025) documents how far benchmark claims sit from deployable systems — useful sober reading before over-investing.

### Where we are
- `policy_range_v3`: in-circuit numeric range + **output/policy commitment binding** (closes the audit's output-swap finding) + **required-field presence bitmask**. Honest, working, but a **narrow policy class** (numeric bounds + field presence). No recursion/aggregation. Composition is logical, not recursive.

### Gap & opportunity
- Two clean wins: (1) a **folding/Nova layer to aggregate per-action receipts into one session proof** (the storage-compression goal); (2) broaden the policy circuit toward **bounded-window tool-trace / LTL-style** policies (our own roadmap's v2/v3). zkVM (SP1) is the lower-effort route to richer policies than hand-writing Halo2 gates.

---

## 3. Tamper-evident transparency log

This is where a small, high-credibility improvement is available.

### State of the art
- **Certificate Transparency** (RFC 6962; **CT 2.0 = RFC 9162**) is the reference design: a Merkle tree whose **Signed Tree Head (checkpoint)** is published, with **inclusion proofs** (this entry is in the log) and **consistency proofs** (the log only ever appended — never rewrote history).
- **Trillian** generalizes CT into a reusable verifiable log; **Sigstore Rekor** builds on it to provide signed checkpoints + inclusion/consistency proofs for software signatures. ([Rekor](https://docs.sigstore.dev/logging/overview/), [Sigstore security model](https://docs.sigstore.dev/about/security/))
- **Defense against a malicious log operator** comes from **external witnesses + gossip** (independent parties co-sign checkpoints so the log can't show different histories to different people — *split-view/equivocation* defense).
- **Trend:** the ecosystem is moving to **tile-based static logs** (Sunlight / `tlog-tiles`) for cheap, scalable, serverless transparency; Let's Encrypt is sunsetting classic RFC 6962 logs. ([Let's Encrypt RFC 6962 EOL](https://letsencrypt.org/2025/08/14/rfc-6962-logs-eol))
- Academic: [VAMS](https://arxiv.org/pdf/1805.04772) (verifiable auditing of confidential-data access), [TAP](https://arxiv.org/pdf/2210.11702) (transparent + privacy-preserving data services).

### Where we are
- Hash-chained SQLite log + **signed Merkle checkpoint** (`signed_checkpoint`/`verify_checkpoint`) + **per-record Ed25519 signatures** (`verify_signatures`). The checkpoint detects full-chain rewrite. This is already CT-*shaped* and ahead of typical "append-only DB" audit logs.

### Gap & opportunity (high ROI, low effort)
1. **Inclusion proofs** — given one receipt, prove it's in the log under a published checkpoint (today we can only re-hash the whole chain). Pure Merkle-path code over the leaves we already hash.
2. **Consistency proofs** — prove checkpoint N+k is an append-only extension of checkpoint N (closes the "rewrite earlier records" gap our bare hash chain still has for non-tip entries).
3. **External witness co-signing** — let a third party co-sign checkpoints to defeat split-view. This is the single most credibility-enhancing audit feature and directly mirrors Rekor.

---

## 4. Attestation, signatures & trust tiers

### State of the art
- **RATS (RFC 9334)** is the umbrella architecture: roles = **Attester → Verifier → Relying Party**; topologies = **Passport** and **Background-Check**; evidence carried as **EAT (Entity Attestation Token)**. Everything attestation-shaped (TEE quotes, GPU-CC, even our signed receipts) can be expressed in this vocabulary.
- TEE concretes: **Intel TDX**, **AMD SEV-SNP**, **AWS Nitro Enclaves**, **NVIDIA GPU-CC**, **Azure Attestation**.
- Provenance analogues that won as *product categories*: **Sigstore** (keyless signing + transparency), **in-toto** (attestations of what/who/order), **SLSA** (provenance assurance levels), **SCITT** (IETF: interoperable supply-chain transparency + accountability). The lesson: *signed metadata + an assurance-tier vocabulary + verification tooling = a category.*

### Where we are
- `AssuranceLevel` enum (`shadow`, `operator_signed`, `policy_proved`, `composed_proved`, `tee_hybrid_claimed`); Ed25519 receipt + audit signatures; TEE path is a **stub** (no real quote verification).

### Gap & opportunity
- Map our receipts and assurance tiers onto **RATS roles + EAT** so any verifier already speaking attestation understands us. Implement **one real TEE quote verifier** (Nitro or TDX) to make `tee_hybrid` honest. Adopt an explicit, ordered trust taxonomy (`declared → signed → sender-constrained → workload-attested → TEE-attested → ZK-policy-proved → ZK-execution-proved`) — the field still lacks a common one, so publishing a credible one is differentiating.

---

## 5. Decision semantics, authority & agentic commerce

### State of the art
- **Agentic payments made "signed mandates" mainstream (late 2025):** **AP2** (Google + Coinbase, on A2A/MCP, 60+ orgs) defines a **Mandate** — a *cryptographically signed, tamper-proof contract* stating spend limits, allowed merchants, validity. **x402** (HTTP 402 stablecoin settlement; Cloudflare/Stripe/AWS/Google/Visa/Circle). **Web Bot Auth** (Cloudflare + IETF) integrated into **Visa TAP / Mastercard Agent Pay** for payment-time agent verification. ([AP2 guide](https://www.cobo.com/post/ap2-protocol-complete-guide-to-agent-payments-for-web3-developers-2026), [Cloudflare agentic commerce](https://blog.cloudflare.com/))
- **Non-binary authorization:** OpenID **AuthZEN AARP** (approval-oriented), legacy **XACML obligations/advice**, workflow substrates (Temporal/Camunda) for resumable approvals — all covered in our landscape doc.

### Where we are
- `DecisionResult` (rich outcome vocabulary), structured `Obligation`s, `BudgetEffect`s, `ApprovalState`, `CapabilityBudget`, authority lineage + session handoff. This is **ahead of most peers** on decision/authority modeling.

### Gap & opportunity
- We model budgets and approvals but don't yet **sign a mandate** the way AP2 does, nor reconcile a receipt against the mandate that authorized it. A **"receipt ⇄ mandate" binding** (prove the action stayed within a signed spend/scope mandate) is a natural, timely feature given AP2's traction, and connects our L3 budget work to a standard the payments industry is adopting.

---

## 6. Compliance & governance mapping

### State of the art
- **EU AI Act** and **NIST AI RMF** are driving concrete audit-field requirements: model/system versions, prompts/policy definitions, inputs+sources, machine- *and* human-readable reasoning, downstream effects, and **integrity protection** — logged at a level that "cannot be altered after the fact." ([Kiteworks tamper-evident audit + SIEM](https://www.kiteworks.com/regulatory-compliance/ai-agent-audit-trail-siem-integration/), [Kognitos 2026 checklist](https://www.kognitos.com/blog/ai-audit-trail-requirements-2026-checklist/))
- Content/asset provenance analogue: **C2PA / Content Credentials** for media; the same "signed provenance manifest" pattern is migrating toward AI outputs.

### Where we are
- Receipts + `arctl explain` + auditor evidence summary + redaction. We produce the *substance* most checklists ask for.

### Gap & opportunity
- No **formal mapping** from receipt fields to specific EU AI Act / SOC 2 / ISO 27001 controls, and no **SIEM-native export**. Compliance teams want mapped evidence, not raw JSON — a high-value, low-crypto productization.

---

## A. Direct comparables (closest systems to ours)

| System | What it is | Overlap with us | What we can learn / where we lead |
|--------|------------|-----------------|-----------------------------------|
| **"Right to History: A Sovereignty Kernel for Verifiable AI Agent Execution"** ([arXiv 2602.20214](https://arxiv.org/pdf/2602.20214)) | Academic framework: Merkle execution logs + signatures + RFC 6962 accumulators + ZK policy + eBPF/Linux-audit capture; EU AI Act/GDPR aligned | **Almost identical thesis to ours.** Validates the category | They emphasize OS-level (eBPF) capture and "sovereignty"; we lead on a working ZK policy circuit + composed proofs. Adopt their inclusion-proof/accumulator rigor |
| **"Show Me You Comply Without Showing Me Anything"** ([arXiv 2510.26576](https://arxiv.org/pdf/2510.26576)) | ZK software auditing for AI: prove policy compliance **without revealing** inputs/outputs/weights (Groth16/PLONK), EU AI Act framing | This is exactly our **premium ZK tier** vision | Concrete blueprint + benchmarks for confidential compliance proofs; informs our "prove policy P held without exposing y" |
| **Dapr 1.18 Verifiable Execution** ([DEV writeup](https://dev.to/thecybersidekick/dapr-118s-verifiable-execution-the-trust-layer-autonomous-ai-agents-on-kubernetes-have-been-147b)) | Runtime extends crypto API into **signed execution traces, attested tool invocations, tamper-evident state transitions** for EU AI Act | **Closest OSS infra competitor.** Same primitives, embedded in a popular runtime | Distribution via a runtime is powerful; our edge is ZK policy proofs + a verifier/standard, not just signed traces |
| **Sigstore / in-toto / SLSA / SCITT** | Signed provenance + transparency for software supply chain | The template our category should copy | Proven that "signed metadata + tiers + verifier tooling + transparency log" becomes a category. We are *in-toto/Rekor for agent actions* |
| **Verifiable evaluations w/ zkSNARKs** ([South et al, arXiv 2402.02675](https://arxiv.org/pdf/2402.02675)) | ZK proofs over model evaluation results | Adjacent: proving properties of model behavior | Technique reuse for proving eval/policy properties on outputs |
| **Guardrails/runtime vendors** — Lakera, Protect AI, HiddenLayer, Prompt Security, Lasso, Patronus, Cisco AI Defense, Bifrost gateway | Real-time AI firewalls; **block** unsafe I/O, produce *audit trails* | Closest commercial neighbors on "what did the agent do" | They **enforce** but produce ordinary (non-verifiable, non-ZK, forgeable) logs. **Our differentiation is cryptographic, verifier-checkable, tamper-evident evidence** — a layer above their audit trails |

---

## B. Prioritized improvement roadmap

Ordered by *(credibility gained × differentiation) ÷ effort*. Each ties to code we have.
Tracked as actionable items (SOTA-1 … SOTA-10) in [sota_backlog.md](sota_backlog.md).
Assurance tier definitions: [assurance_taxonomy.md](assurance_taxonomy.md).
Compliance profiles and SIEM export: [compliance_mapping.md](compliance_mapping.md).

### Tier 1 — High ROI, mostly in-repo, low crypto risk
1. **Merkle inclusion + consistency proofs** on the audit log (extends `signed_checkpoint`). Brings us to CT/Rekor parity; closes the "rewrite earlier record" gap. *Pure Python over hashes we already store.*
2. **Honest TEE path for LLM-scale provenance** — implement one real quote verifier (AWS Nitro or Intel TDX) and wire it as the `tee_attested` tier, expressed as **RATS/EAT**. Makes the model-provenance pillar real at scale *without* ZK-proving a transformer.
3. **RATS/EAT alignment + published assurance taxonomy** — re-express receipts/tiers in standard attestation vocabulary; ship the ordered trust-tier table as a spec contribution. Cheap, high-credibility, category-defining.
4. **Compliance field mapping + SIEM export** — map receipt fields to EU AI Act / SOC 2 / ISO controls; emit OTel/SIEM-native records. High buyer value, near-zero crypto.

### Tier 2 — Medium effort, strong differentiation
5. **External witness co-signing of checkpoints** — defeats log split-view/equivocation; mirrors Rekor's witness model. The strongest single audit-credibility feature.
6. **Receipt ⇄ AP2 Mandate binding** — bind a receipt to the signed mandate (spend/scope/validity) that authorized it; rides the agentic-commerce wave and connects our budget/authority L3 work to an adopted standard.
7. **Session-proof aggregation via folding (Nova)** — fold per-action policy proofs into one session proof; realizes the "compress 2,500 receipts" goal and cuts verification/storage cost.

### Tier 3 — Larger bets, frontier
8. **Upgrade the inference path** — migrate off raw EZKL to a **zkPyTorch-class compiler** or an **SP1/RISC Zero zkVM** for the small policy/classifier heads; adopt **opML-style optimistic+ZK** for anything larger. Reserve ZK for where it's cheap; TEE for the rest.
9. **Confidential compliance proofs** (the [2510.26576](https://arxiv.org/pdf/2510.26576) blueprint) — prove "policy P held on output y" *without revealing y* as the highest-assurance premium tier for regulated/multi-party settings.
10. **Recursive composition** — replace logical inference∪policy composition with a single recursive SNARK (our own roadmap M3 stretch).

---

## C. Annotated source map

### zkML / verifiable inference
- Definitive ZKML guide 2025 — <https://blog.icme.io/the-definitive-guide-to-zkml-2025/>
- zkML "singularity" analysis — <https://academy.extropy.io/pages/articles/zkml-singularity.html>
- EZKL (our current engine) — <https://github.com/zkonduit/ezkl> · benchmarks <https://blog.ezkl.xyz/post/benchmarks/>
- zkPyTorch — <https://eprint.iacr.org/2025/535>
- zkLLM — <https://arxiv.org/pdf/2404.16109>
- NANOZK (layerwise LLM ZK) — <https://arxiv.org/pdf/2603.18046>
- zk-OPML (optimistic+ZK) — <https://link.springer.com/article/10.1007/s44443-026-00573-1>
- VeriLLM (publicly verifiable decentralized inference) — <https://arxiv.org/pdf/2509.24257>
- Verifiable evaluations w/ zkSNARKs (South et al) — <https://arxiv.org/pdf/2402.02675>
- ZKVMs: SP1 (Succinct), RISC Zero, Jolt — <https://a16zcrypto.com/posts/article/faqs-on-jolts-initial-implementation/>

### Proof systems / recursion
- Nova folding — <https://eprint.iacr.org/2021/370.pdf> · <https://github.com/microsoft/Nova>
- awesome-folding — <https://github.com/lurk-lab/awesome-folding>
- SoK: zk-SNARKs research vs practice — <https://arxiv.org/pdf/2502.02387>

### Transparency logs / tamper-evidence
- RFC 6962 Certificate Transparency — <https://www.rfc-editor.org/rfc/rfc6962.html> (CT 2.0 = RFC 9162)
- Sigstore Rekor — <https://docs.sigstore.dev/logging/overview/> · security model <https://docs.sigstore.dev/about/security/>
- Trillian (verifiable log) — <https://github.com/google/trillian>
- Static/tile-based CT + RFC 6962 EOL — <https://letsencrypt.org/2025/08/14/rfc-6962-logs-eol>
- VAMS (verifiable auditing) — <https://arxiv.org/pdf/1805.04772>

### Attestation / TEE / RATS
- RFC 9334 RATS architecture — <https://www.rfc-editor.org/info/rfc9334/>
- NVIDIA GPU Confidential Computing demystified — <https://arxiv.org/pdf/2507.02770>
- Intel TDX — <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html>
- SCITT (IETF supply-chain transparency) — <https://datatracker.ietf.org/group/scitt/about/>

### Agent accountability / direct comparables
- **Right to History (sovereignty kernel)** — <https://arxiv.org/pdf/2602.20214>
- **ZK software auditing for AI ("Show Me You Comply…")** — <https://arxiv.org/pdf/2510.26576>
- Dapr 1.18 verifiable execution — <https://dev.to/thecybersidekick/dapr-118s-verifiable-execution-the-trust-layer-autonomous-ai-agents-on-kubernetes-have-been-147b>
- ZK proofs for AI agent verification & privacy (Zylos) — <https://zylos.ai/research/2026-03-18-zero-knowledge-proofs-ai-agent-verification>

### Agentic commerce / signed mandates
- AP2 protocol guide — <https://www.cobo.com/post/ap2-protocol-complete-guide-to-agent-payments-for-web3-developers-2026>
- x402 vs AP2 comparison — <https://medium.com/@gwrx2005/ai-agents-and-autonomous-payments-a-comparative-study-of-x402-and-ap2-protocols-e71b572d9838>
- Web Bot Auth (Cloudflare + IETF) — <https://stellagent.ai/insights/web-bot-auth-cloudflare-ietf>

### AI governance / compliance / commercial
- Tamper-evident audit + SIEM (Kiteworks) — <https://www.kiteworks.com/regulatory-compliance/ai-agent-audit-trail-siem-integration/>
- AI audit-trail 2026 checklist (Kognitos) — <https://www.kognitos.com/blog/ai-audit-trail-requirements-2026-checklist/>
- AI agent compliance/governance (Galileo) — <https://galileo.ai/blog/ai-agent-compliance-governance-audit-trails-risk-management>
- AI security/guardrails platforms 2026 (General Analysis) — <https://generalanalysis.com/guides/best-ai-security-platforms>

> See [landscape_research.md](landscape_research.md) for the full identity/authorization/policy (L1–L3) market map, and [open_standard_strategy.md](open_standard_strategy.md) for the standard-vs-commercial split.
