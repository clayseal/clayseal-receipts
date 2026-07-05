# Data + evidence backlog

Structured backlog for benchmark corpora, evaluation methods, current performance, and improvement ideas. Demo fixtures (D-01–D-08) at the end.

---

## Interpretation — what our percentages mean

**Read this before citing pass rates.** The harness measures **pipeline plumbing on replay/mock workloads**, not benchmark task success or production safety.

| Metric | What it means | What it does **not** mean |
|--------|---------------|---------------------------|
| **Pass rate (`ok`)** | Adapter-specific check passed + audit chain verified | Agent completed the original MCP-Bench / τ² / SWE task |
| **`policy_satisfied_rate`** | Attached YAML accepted model/tool outputs for that run | Production policy blocks all misuse; cap deny in the wild |
| **`audit_chain_ok_rate`** | Append-only audit hash chain intact after the case | Tamper detection under adversarial load |
| **`export_ok_rate`** | Receipt bundle JSON was produced | Third-party verified at highest assurance tier |
| **`verify_valid_rate`** | Full `verify_receipt_bundle` including TEE/prove tier | Same as pass rate — **not gated by default** |

**Default run config (`bounded_auto`, no TEE):** expect **`verify_valid_rate = 0%`** with reason `tee_hybrid: no tee_quote attached`. That is expected, not a Stage 1 failure. Use `--require-verify` only when testing assurance tier.

**Per-suite pass semantics:**

| Suite | Pass = |
|-------|--------|
| `ulb_fraud` | Stub model ran; fraud policy schema satisfied |
| `ieee_cis_fraud` / `paysim_fraud` / `elliptic_fraud` / `baf_fraud` | Feature-signal stub ran; fraud policy schema satisfied (ARL CSV auto-resolved) |
| `atif_mcp` | Tool calls replayed; zero blocks under permissive MCP policy |
| `bfcl_caps` | Allowed tool OK **and** decoy blocked (only built-in negative test) |
| `tau2_policy` | Golden actions replayed; zero blocks under permissive policy |
| `mcp_bench_tasks` | Extracted tools called under per-task allowlist (mock handlers) |
| `swe_session` | Multi-step `record()` logged; policy + audit OK |
| **`red_team`** | **Controls** block attacks; **baselines** pass; **blind_spots** confirm documented gaps stay open |
| Fraud suites (`ulb_fraud`, `*_fraud`) | Stub model ran; fraud policy schema satisfied; **`label_mismatch_rate`** tracks decision vs ground-truth label (informational) |

**Stage 1 headline we can honestly claim:** public benchmark-shaped inputs → consistent receipt artifacts + audit chain at volume (including **1.27M** full-corpus run). **Not claiming:** fraud AUC, τ² task success, live MCP, or cryptographic verify at tier 3 without prove/TEE tooling.

**For discriminating signal, run `red_team` + `benchmarks/soundness.py` first** — smoke-suite pass rates are expected; soundness and red team separate real mitigations from harness tautologies.

---

**Last benchmark run:** 2026-06-21 (local)

| Run | Command / artifact | Cases | Pass | Headline metrics |
|-----|-------------------|-------|------|------------------|
| **Full corpus E2E** | all 16 suites, `limit=None`, `--no-export` | **1,265,731** | **100%** | audit **100%** · p50 **0.61 ms** · ~19 min wall |
| **Soundness ladder** | `benchmarks/soundness.py --suite all --limit 200` | 1,732 receipts | — | agentauth forgeable **0.013%** · naive **67%** |
| **Red team** | `red_team` (in full run) | 15 | **100%** | control **1.0** · blind_spot **1.0** |
| **Synthetics** | 4 suites (in full run) | 128 | **100%** | tenant/revoke/L1/assurance |

Results: `benchmarks/results/full_suite_all/rollup.json`, `benchmarks/results/soundness_full_run.json`

---

## Note on the fraud model — it is a fixture, not under evaluation

The fraud model and corpora are **workload fixtures** that drive realistic allow/deny
decisions through the receipt pipeline. AgentAuth attests whatever decision a customer's
model makes; **it is not a fraud model**, so the stub's accuracy (precision/recall/AUC) is
*not* a system-quality metric and is deliberately not reported. The only relevant question
is **decision-branch coverage** — does the fixture exercise both allow and deny paths so we
test deny-path receipts too — which `label_mismatch_rate` already proxies (printed as
"Decision-branch coverage" by `run.py`). System quality is measured by tamper-evidence,
proof/identity binding, soundness, interop, and coverage — not by the workload's accuracy.

---

## Identity authenticity, interop conformance, prove-tier (2026-06-21 cont.)

Three system-quality results beyond tamper-evidence.

### Identity seam — facts are now *authenticated*, not just tamper-evident (EV-101)

Tamper analysis on `--with-identity` receipts confirmed the identity fields
(`workload_principal`, `presenter_key_hash`, `attestation_type`, `delegation_chain`)
are already tamper-evident (EV-RT-2 binds them via `context_hash`; detection 0.945).
The gap was **authenticity**: receipts embedded no signed credential, so the facts
weren't tied to anything the issuer attested. Now `build_receipt_bundle(..., identity=…)`
embeds the signed **JWT-SVID + issuer JWKS**, and `verify_receipt_bundle`
(`agentauth/receipts/identity_evidence.py`) verifies the SVID's EdDSA signature offline
and binds its `sub`/`iss`/`cnf.jkt` to the authority block. **Result:** corrupting the
SVID → `signature_invalid`; swapping the SVID for another agent's, or mutating
`workload_principal`/`subject_id`/`issuer`/`presenter_key_hash` → `authority_mismatch`.
Wired into the harness `--with-identity` path; gated by `python/tests/test_identity_evidence.py`
(8 tests). Trust note: the embedded JWKS makes verification self-contained; full trust
still requires pinning the issuer key (`AGENT_RECEIPTS_TRUSTED_IDENTITY_ISSUER_KEYS`,
checked when set) — same model as bundle-signature / audit-log trust anchors.

**At scale (2026-06-21):** `benchmarks/results/ev101_identity_100` — **138/138 pass**
(100 ULB + 38 ATIF) · export **100%** · identity rates **1.0** across
spiffe-in-authority, JWT section, offline identity verify, live `/v1/validate` round-trip ·
`verify_valid_rate` **0%** (no TEE quote; expected at `bounded_auto`).

### External interop — "live interop not asserted" closed

`python/tests/test_interop_conformance.py` verifies our artifacts with an **independent
implementation that re-derives each spec from `cryptography` + `cbor2` primitives and
never calls our own verify code**:

| Artifact | Independent check | Result |
|----------|-------------------|--------|
| C2SP checkpoint (signed note) | raw Ed25519 verify over the note body | accepts valid, rejects body tamper |
| tlog-tiles | from-scratch RFC 6962 tile client folds the root from entry tiles (300 leaves) | root matches the checkpoint |
| SCITT Signed Statement | COSE_Sign1 `Sig_structure` rebuilt + Ed25519 verified | accepts valid, rejects re-packed payload |

This is the in-Python, separate-code-path equivalent of the spec; the Go reference
binaries are the next rung.

### Prove-tier matrix (EV-201/202) — `scripts/prove_tier_matrix.py`

Measured here (Apple Silicon); each backend proves, verifies, and is checked for
**tamper-resistance** (mutate the proof → the verifier must reject). Output:
`benchmarks/results/prove_tier.json`.

| Backend | prove (ms) | verify (ms) | proof bytes | accepts valid | **rejects tampered** |
|---------|-----------:|------------:|------------:|:-------------:|:--------------------:|
| `halo2_policy` (range proof) | 422 | 137 | 8,062 | yes | **yes** |
| `risc0_inference` (fraud head) | 2,871 | 14 | 209,578 | yes | **yes** |
| `sp1_inference` (fraud head) | — | — | — | — | skipped: guest ELF not built (needs `sp1up`; `scripts/sp1_build_fraud_head.sh`) |

The point isn't the absolute numbers (tiny circuits); it's that the proving tiers
**reject tampered proofs** — the soundness property the assurance tiers exist to provide.
EV-203 (TEE-attested verify) remains blocked on hardware.

---

## Adversarial soundness benchmark — empirical proof, not demoware (2026-06-21)

The artifact for "the product does what we say, at scale, and the obvious alternatives
don't." Runs the full single-field tamper battery over real exported receipts and, for
each integrity model in a **contrast ladder**, measures the **false-accept rate** — the
fraction of mutations to *security-load-bearing* fields that the verifier fails to flag.
One seeded, provenance-stamped command: `benchmarks/soundness.py`
(`python3.11 benchmarks/soundness.py --suite all --limit 200 --ulb-sample stratified`),
report at `benchmarks/results/soundness.json`.

**Headline run: 1,732 receipts across all 11 workloads, 363,854 mutations, 284,364
security-relevant tamper trials per verifier.**

| Integrity model (modeled on a real approach) | false-accept | forgeable | 95% upper (forge) |
|-----------------------------------------------|------------:|----------:|------------------:|
| `plaintext_log` — plain structured logging (OpenTelemetry / JSON logs) | 1.000 | 0.988 | 0.988 |
| `signed_payload` — JWS/cosign over the model **response** only ("we sign the output") | 0.944 | 0.932 | 0.932 |
| `hash_chain_log` — append-only hash-chained audit log (immudb / auditd / Trillian-style) | 0.910 | 0.897 | 0.899 |
| `naive_canonical` — sign the proof core, ship display fields ("signed receipt") | 0.681 | 0.669 | 0.671 |
| **`agentauth`** — full binding + authenticated identity + evidence | 0.012 | **0.00013** | **1.8 × 10⁻⁴** |

**Read:** every common integrity model leaks. Plain logging accepts ~all tampers; signing
just the output (`signed_payload`) still accepts **93%**; a hash-chained audit log
(`hash_chain_log`) proves the *logged event* but accepts **90%** of tampers to everything
not in the log record; even a signed receipt binding the proof core (`naive_canonical`)
accepts **67%** — the entire human-facing projection / identity / audit class a dashboard,
SIEM, or auditor reads. AgentAuth accepts **0.013%**, and on *forgeable content*
**1.3 × 10⁻⁴** with a 95% upper bound of **1.8 × 10⁻⁴**. The 38 residual forgeable misses
decompose entirely into explained non-bugs: `execution_proof.bundle.tee_quote.quote_b64`
(only checkable with a TEE — EV-203, blocked on hardware) and the `red_team` suite's
*intentionally* mismatched `policy.commitment` fixtures (already flagged at baseline). On
normal bundles with no TEE claim, forgeable false-accepts are **0**. `signed_payload` and
`hash_chain_log` are independent re-implementations (JWS-over-output; RFC-6962 record
hashing), so they also cross-check AgentAuth's rejections on those classes.

**Prove-mode pass — the stronger "verified valid" framing** (`--mode prove`,
`AGENT_RECEIPTS_ALLOW_STUB=1`, `benchmarks/results/soundness_prove.json`). In
`bounded_auto` the clean baseline is already `verify_valid=false` (no TEE), so
"false-accept" means "the verifier failed to *flag* the tamper." In **prove mode the
clean receipt verifies `valid`**, so false-accept becomes the literal claim **"the
tampered receipt still verified valid."** Over **4,075** security-relevant tampers on
valid-baseline receipts, AgentAuth let **19 (0.47%)** still verify valid — *all* of them
`execution_proof.bundle.composed_proof_b64`, the proof bytes the **stub** prover doesn't
re-check. The prove-tier matrix (EV-201/202) separately shows the **real** Halo2/RISC0
provers reject tampered proof bytes, so with real proving in the loop this residual is
**0**. Net: on a valid baseline, *zero* tampered receipts verify valid once a real prover
is attached.

**Why this is not demoware** (the five things a skeptic demands):
- **Scale** — 284k adversarial trials, not a handful.
- **Diversity** — all 11 public workloads, not one staged scenario.
- **Adversarial completeness** — the full single-field mutation space, residual enumerated.
- **Baseline contrast** — the same battery sinks `plaintext_log` (100%) and
  `naive_canonical` (67%); `naive_canonical` is an *independent* re-implementation of the
  canonical checks, so it also cross-checks AgentAuth's canonical-class rejections.
- **Independent reproduction** — one seeded command, git-commit + environment provenance
  in the report, re-runnable; the C2SP/tiles/SCITT artifacts are independently verified by
  the interop conformance suite above.

Gated by `benchmarks/tests/test_soundness.py` (ladder ordering must hold).

**Identity-forgery variant** (`--with-identity`, 138 receipts, 26,320 security trials,
`benchmarks/results/soundness_identity.json`): plaintext 1.000, signed_payload 0.931,
hash_chain_log 0.885, naive 0.666, **agentauth forgeable 0.016**. The SVID core is bound
(corrupt the token or swap `sub`/`iss`/`cnf.jkt` → rejected; the JWKS key bytes `x` are
bound, so signature forgery is caught). The battery **surfaced — and then drove the fix
of — a real gap**: it found the embedded `identity.expires_at`, `identity.biscuit`, and
`identity.biscuit_root_public_key` shipped unverified. **EV-101b `[x]` implemented**
(`identity_evidence.py`): `identity.expires_at` is now bound to the signed SVID `exp`
(extend the displayed expiry → rejected), and an embedded Biscuit is cryptographically
verified against its root key (forge/corrupt it → rejected). Forgeable residual fell
**0.026 → 0.016**. The remaining misses are non-forgery-vectors: `biscuit_root_public_key`
when no Biscuit is present (dead data — the dev path is JWT-only), and the JWK `kid`/`use`
metadata (the trust-bearing key bytes `x` are bound). The benchmark working as intended:
it found a gap the unit tests didn't, and we closed it.

**What it does NOT prove** (stated plainly, because demoware never volunteers its limits):
the evidence plane is sound and unforgeable; this says nothing about whether the agent's
*decisions* are good — that is the customer's model, not ours.

---

## How to read items

| Field | Meaning |
|-------|---------|
| **ID** | Backlog item (stable reference) |
| **Stage** | 1 evidence plane · 2 identity · 3 assurance · 4 regulator · D demo (later) |
| **Data type** | What the corpus/evidence looks like |
| **Benchmark idea** | What we measure and how |
| **Current perf** | Latest harness numbers (if run) |
| **Improve** | Next engineering steps |
| **Status** | `ready` · `partial` · `blocked` · `planned` · `later` |

**Primary metrics** (Stage 1): `pass_rate`, `policy_satisfied_rate`, `audit_chain_ok`, `export_ok`, latency p50/p95, throughput.  
**Red team metrics** (in `summary.json` → `red_team_metrics`):
- **Category rates:** `control_pass_rate`, `baseline_pass_rate`, `blind_spot_open_rate` (CI fails on control/baseline regression only)
- **Enforcement rates:** `schema_enforcement_rate`, `tool_block_rate`, `cert_scope_enforcement_rate`, `audit_integrity_rate`
- **Counts:** active controls/baselines/blind_spots, skipped cases, unexpected gap closures
- **Breakdowns:** `by_attack_surface`, `by_defense_layer`, `documented_gaps`, `attack_matrix` (per-case expected vs observed)  
**Fraud informational**: `label_mismatch_rate` — fraction of cases where stub decision disagrees with corpus fraud label (does not affect pass/fail).  
**Secondary**: `verify_valid_rate` (assurance tier — expect 0% without TEE/prove), `decoy_blocked_rate`, tool/action replay counts.  
**Not optimizing**: fraud AUC, τ² task success, MCP-Bench agent completion.

---

## Stage 1 — Evidence plane

### EV-001 · High-volume decision receipts (ULB)

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Tabular transactions — CSV, 284,762 rows (`Amount`, `Class`, V1–V28) |
| **Corpus** | `benchmarks/corpus/ulb_creditcard/creditcard.csv` |
| **Harness** | `ulb_fraud` |
| **Benchmark idea** | For each row: stub fraud model → `fraud_decision.yaml` → `agent.run()` → export → verify → audit chain. Track policy satisfaction, audit integrity, latency at N=1k–284k. Optional stratified sample on `Class=1` (fraud is ~0.17% of corpus). |
| **Current perf** | **284,807/284,807 pass** (full corpus, `full_suite_all`) · policy **100%** · audit **100%** · p50 **0.62 ms** · p95 **1.10 ms** · label_mismatch **0.21%** |
| **Improve** | (1) Stratified full-corpus report. |
| **Status** | **ready** |

---

### EV-002 · Real MCP tool-call trace replay (ATIF)

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Agent trajectories — JSON per agent (`trajectory.json`), 38 runnable traces |
| **Corpus** | `benchmarks/corpus/mcp_agent_trajectory_benchmark/` |
| **Harness** | `atif_mcp` |
| **Benchmark idea** | Replay tool calls from ATIF through `ReceiptedMcpGateway` + mock handlers. Measure per-trajectory tool steps, blocked calls, policy satisfaction, receipt export. |
| **Current perf** | **38/38 pass** · policy 100% · avg **2.82 ms** (p50 2.21, p95 6.07, max 13.12) · 3–32 tool calls/trajectory (avg 7.4). |
| **Improve** | (1) `--policy-mode tight` negative replays. (2) Subset by domain for buyer reports. |
| **Status** | **ready** |

---

### EV-003 · Capability allowlist enforcement (BFCL)

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Function-call prompts + ground-truth args — JSONL, 400 `simple_python` cases (+ ~1,500 more categories on disk) |
| **Corpus** | `benchmarks/corpus/gorilla/berkeley-function-call-leaderboard/` |
| **Harness** | `bfcl_caps` |
| **Benchmark idea** | Per case: per-tool allowlist policy → allowed tool succeeds → `decoy_tool` blocked with allowlist violation in receipt. Metric: `decoy_blocked_rate` (target 100%). |
| **Current perf** | **400/400 pass** · decoy blocked **400/400** · avg **1.14 ms** (p50 0.93, p95 2.05). |
| **Improve** | (1) Adapters for other BFCL categories. (2) Multi-server MCP-Bench tasks. |
| **Status** | **ready** (simple_python); **partial** (other BFCL categories) |

---

### EV-004 · Policy-governed tool sequences (τ²)

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Task specs with `evaluation_criteria.actions` — JSON, 2,556 tasks across 5 domains |
| **Corpus** | `benchmarks/corpus/tau2_bench/data/tau2/domains/{mock,airline,retail,telecom,banking_knowledge}/tasks.json` |
| **Harness** | `tau2_policy` (mock, airline, retail wired; telecom/banking on disk) |
| **Benchmark idea** | Replay golden actions through MCP gateway under domain policy YAML. Metrics: actions replayed, blocked count, policy satisfaction. **Not** τ² simulator success rate. |
| **Current perf** | **163+** wired (mock/airline/retail) · telecom/banking via `--tau2-domain all` or explicit list · `--tau2-telecom-tasks small` for smoke |
| **Improve** | Domain-specific policy YAML (optional). |
| **Status** | **ready** (all five domains wired) |

---

### EV-005 · Planned MCP tool chains (MCP-Bench tasks)

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Task descriptions with embedded `Server:tool` references — JSON, 56 single-server tasks |
| **Corpus** | `benchmarks/corpus/mcp_bench/tasks/mcpbench_tasks_single_runner_format.json` |
| **Harness** | `mcp_bench_tasks` |
| **Benchmark idea** | Extract planned tools from task + dependency text → per-task allowlist → mock execute each tool → receipt last call. Metric: runnable task coverage, tools/task, policy pass. |
| **Current perf** | **56/56 pass** · policy 100% · avg **6.24 ms** · 1–41 tools/task (avg 15.1). |
| **Improve** | (1) Multi-server task JSON adapter. (2) Live MCP run (EV-012). |
| **Status** | **ready** (56/56 single-server tasks) |

---

### EV-006 · Long-session step logging (SWE-agent)

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Parquet trajectories — ~80k sessions, 12 shards (`instance_id`, `trajectory`, `exit_status`) |
| **Corpus** | `benchmarks/corpus/swe_agent_trajectories/data/train-*.parquet` |
| **Harness** | `swe_session` |
| **Benchmark idea** | Log up to 12 assistant/tool/user steps via `agent.record()` → session-scoped audit chain → export. Metrics: steps/session, latency vs step count, audit chain over multi-record sessions. |
| **Current perf** | **20/20** default cap · `--swe-shard all` runs all 12 shards in one report |
| **Improve** | Session folding / composed proofs (Stage 3). |
| **Status** | **ready** |

---

### EV-007 · Receipt export + structural verify

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Exported JSON receipt bundles (all suites) |
| **Harness** | All suites with export enabled |
| **Benchmark idea** | `build_receipt_bundle` → `verify_receipt_bundle`. Track `export_ok`, bundle schema completeness, verify reasons. |
| **Current perf** | Export path exercised across all suites; **`verify_valid`: 0%** at `bounded_auto` (no TEE — expected). Prove/identity tiers: see EV-201/EV-101. |
| **Improve** | (1) Split metrics: structural vs assurance-tier verify in buyer docs. (2) Bundle gallery via `benchmarks/demo/generate.py`. |
| **Status** | **ready** (export); **partial** (tier verify) |

---

### EV-008 · Audit chain integrity at volume

| | |
|--|--|
| **Stage** | 1 |
| **Data type** | Fresh SQLite audit DB per case (default); optional `--shared-audit-db` for sequential tests |
| **Harness** | All suites |
| **Benchmark idea** | After each case: `audit.verify_chain()`. At volume: confirm chain never breaks. |
| **Current perf** | **100%** audit_chain_ok on **1.27M** full run · fresh DB per case: ULB 284k in ~19 min (no hang) |
| **Improve** | Tamper injection on audit chain (synthetic). |
| **Status** | **ready** |

---

## Stage 2 — Identity-integrated

### EV-101 · SPIFFE/JWT-SVID in receipt authority

| | |
|--|--|
| **Stage** | 2 |
| **Data type** | Same corpora + AgentAuth attestation (no public joint corpus) |
| **Harness** | `--with-identity` (bootstrap embedded AgentAuth) |
| **Benchmark idea** | Run N cases per suite with identity bound; verify `authority_binding` in bundle; optional `/v1/verify` round-trip against backend. |
| **Current perf** | **138/138 pass** at scale (`ev101_identity_100`: 100 ULB + 38 ATIF) · export **100%** · identity rates **1.0** (spiffe, JWT section, offline verify, live validate) · `verify_valid_rate` **0%** (no TEE). Smoke: **6/6** (ATIF 3 + ULB 3). |
| **Improve** | (1) Full-corpus identity + prove variants. (2) Online invalidation in verify path. |
| **Status** | **ready** |

### EV-101b · L1 hardening synthetics (`synthetic_l1`)

| | |
|--|--|
| **Harness** | `synthetic_l1` — Ed25519 JWT binding, Biscuit mint, PoP, key-rotation grace, JWKS swap |
| **Current perf** | **7/7 pass** |
| **Status** | **ready** |

### EV-203b · Assurance synthetics (`synthetic_assurance`)

| | |
|--|--|
| **Harness** | `synthetic_assurance` — mock Nitro TEE verify, tamper injection at export |
| **Current perf** | **5/5 pass** |
| **Status** | **ready** |

---

### EV-102 · Multi-tenant isolation

| | |
|--|--|
| **Stage** | 2 |
| **Data type** | Synthetic — two API keys / customers |
| **Harness** | `synthetic_tenant` |
| **Benchmark idea** | Same corpus, two tenants; cross-tenant verify must fail. |
| **Current perf** | **`synthetic_tenant` 43/43 pass** (8 hand-crafted + 35 scaled) · cross-tenant validate/revoke/read blocked · SPIFFE paths isolated · bundle JWT cross-validate blocked |
| **Improve** | Cross-tenant receipt bundle verify at scale; online revocation in verify path |
| **Status** | **ready** (synthetic suite) |

---

### EV-103 · Revocation scenarios

| | |
|--|--|
| **Stage** | 2 |
| **Data type** | Synthetic timeline — issue → use → revoke → deny |
| **Harness** | `synthetic_revocation` |
| **Benchmark idea** | Measure deny-after-revoke on subsequent runs; receipt reflects revoked credential. |
| **Current perf** | **`synthetic_revocation` 73/73 pass** (8 + 65 scaled) · control **1.0** · baseline **1.0** · blind_spot **1.0** (offline bundle persists after revoke; live validate fails) |
| **Improve** | Link revoke events into receipt verify; online invalidation metric |
| **Status** | **ready** (synthetic suite) |

---

## Stage 3 — Assurance tiers

### EV-201 · Prove mode + policy ZK (ULB subset)

| | |
|--|--|
| **Stage** | 3 |
| **Data type** | ULB `Amount` column (same CSV) |
| **Harness** | `--mode prove` (not default in suite matrix) |
| **Benchmark idea** | Small-N (10–100): prove latency, proof size, verify pass rate vs bounded_auto. |
| **Current perf** | **100/100 pass** prove + baseline (`ev201_ulb_fraud_100_comparison.json`) · prove latency **415 ms avg** (p50 405 ms, p95 556 ms) · baseline **0.44 ms avg** (p50 0.41 ms) · **~945× slowdown** · proof bytes **9036 avg** · `verify_valid` **1.0** prove vs **0.0** baseline. Smoke N=10: **10/10** (`ev201_prove_10`). |
| **Improve** | (1) Prove at full ULB scale. (2) Real prover integration (non-stub). |
| **Status** | **ready** (N=100 comparison via `ev201_compare.py`) |

---

### EV-202 · Composed inference backends (EZKL / RISC Zero / SP1)

| | |
|--|--|
| **Stage** | 3 |
| **Data type** | ULB amounts + fraud policy thresholds |
| **Corpus** | ULB + `examples/composed_prove_fraud_agent.py` |
| **Benchmark idea** | Matrix: backend × N cases → prove time, verify time, success rate. |
| **Harness** | `--inference-backend {ezkl,risc0,sp1}` + `benchmarks/ev202_compare.py` |
| **Current perf** | Matrix N=5 (`ev202_matrix_5.json`): **ezkl/risc0/sp1 5/5 pass** · verify **1.0** · proof **9051 B** · p50 **661/571/567 ms**. Harness: `--inference-backend` + `ev202_compare.py`. |
| **Improve** | (1) Real zkVM proofs (`ALLOW_STUB=0` + guest builds). (2) SP1 guest ELF build. |
| **Status** | **ready** (harness matrix; real proofs optional) |

---

### EV-203 · TEE-attested verify tier

| | |
|--|--|
| **Stage** | 3 |
| **Data type** | TEE quotes (synthetic or hardware) |
| **Harness** | `synthetic_assurance` (+ hardware path blocked) |
| **Benchmark idea** | With quote attached: `verify_valid_rate` → target >0%. Without: document expected failure reason. |
| **Current perf** | Mock Nitro: **5/5 pass** in `synthetic_assurance`; corpus runs still 0% verify_valid without quote |
| **Improve** | Real TEE path when hardware available. Harness: `--attach-mock-tee` for mock Nitro at scale. |
| **Status** | **partial** (mock synthetics + harness flag; hardware blocked) |

---

## Stage 4 — Regulator / partner evidence

### EV-301 · SIEM / ECS export from receipts

| | |
|--|--|
| **Stage** | 4 |
| **Data type** | ECS JSON fixtures + harness-produced bundles |
| **Corpus** | `compliance/fixtures/ecs_ingest_sample.json` |
| **Benchmark idea** | Transform N receipt bundles → ECS events; validate schema mapping. |
| **Current perf** | Static fixture + **`benchmarks/ev301_ecs_export.py`** over harness receipts |
| **Improve** | ECS schema validation gate in CI. |
| **Status** | **ready** (automation script) |

---

### EV-302 · Control crosswalk coverage

| | |
|--|--|
| **Stage** | 4 |
| **Data type** | YAML crosswalks (SOC2, ISO27001, EU AI Act) |
| **Benchmark idea** | Map receipt fields + policy events to control IDs; report coverage %. |
| **Current perf** | **`benchmarks/ev302_crosswalk.py`** — per-profile complete_rate over N bundles |
| **Improve** | CI `--fail-under` on demo bundles (D-06). |
| **Status** | **ready** (automation script) |

---

## Local corpus mirror (`adaptive-reliability-layer`)

Fraud and tabular datasets already on disk for the sibling project — **no Kaggle re-download needed** for most fraud corpora.

**Root:** `/Users/pberlizov/Documents/GitHub/adaptive-reliability-layer/data/`

| ARL path | Rows | Size | Backlog | Harness |
|----------|------|------|---------|---------|
| `fraud/ieee_cis_full.csv` | 590,540 | 340 MB | **EV-401** | `ieee_cis_fraud` (ARL path auto-resolved) |
| `fraud/raw/train_transaction.csv` | 590,540 | 652 MB | EV-401 (raw) | Kaggle competition original |
| `fraud/raw/train_identity.csv` | 144,233 | 25 MB | EV-401 (join) | Optional identity join |
| `fraud/ieee_cis_sample.csv` | 60,101 | 23 MB | EV-401 (dev) | Smaller smoke subset |
| `fraud/creditcard.csv` | 284,807 | 94 MB | EV-001 (ULB) | Duplicate of `benchmarks/corpus/ulb_creditcard/` |
| `fraud/paysim.csv` | 50,000 | 4.8 MB | EV-401 | `paysim_fraud` |
| `fraud/elliptic_fraud.csv` | 46,564 | 25 MB | EV-401 | `elliptic_fraud` |
| `fraud/baf_base_fraud.csv` | 250,000 | 62 MB | EV-401 | `baf_fraud` |
| `cmapss/*.csv` | 4 FD sets | 52 MB | Sensor ops / non-fraud receipts | Not wired |
| `openml/*.csv` | varies | 15 MB | Tabular drift streams | Not wired |
| `wilds/civilcomments_*` | large | 260 MB | Out of scope (NLP moderation) | — |

**IEEE-CIS note:** ARL's `ieee_cis_full.csv` is a preprocessed export from Kaggle raw under `fraud/raw/`. Override: `AGENTAUTH_CORPUS_IEEE_CIS`.

**Amazon FDB:** bundled ipblock in `benchmarks/corpus/amazon_fdb/` — see EV-402.

---

## Additional corpora

### EV-401 · IEEE-CIS fraud (competition)

| | |
|--|--|
| **Data type** | Kaggle competition CSVs — **already local via ARL** |
| **Local path** | `adaptive-reliability-layer/data/fraud/ieee_cis_full.csv` (+ raw under `fraud/raw/`) |
| **Status** | **ready** — resolves ARL path by default; override with `AGENTAUTH_CORPUS_IEEE_CIS` |
| **Harness** | `ieee_cis_fraud` (+ `paysim_fraud`, `elliptic_fraud`, `baf_fraud`) |
| **Benchmark idea** | Same as EV-001 with richer features + industry-standard fraud benchmark narrative |
| **Current perf (full corpus)** | ieee **590,540** · paysim **50,000** · elliptic **46,564** · baf **250,000** — all **100%** pass in `full_suite_all` · label_mismatch varies by dataset (stub vs features; informational) |
| **Improve** | Per-dataset label_mismatch breakdown; stub tuning optional (not a system metric) |

### EV-402 · Amazon FDB multi-dataset fraud

| | |
|--|--|
| **Data type** | Multiple fraud CSVs via Kaggle |
| **Status** | **partial** — `amazon_fdb` harness wired for bundled **ipblock** (43k test rows, no Kaggle). Other FDB keys overlap ARL suites (`ieee_cis_fraud`, `ulb_fraud`, `paysim_fraud`) or need Kaggle credentials |
| **Harness** | `amazon_fdb` (ipblock today; extend `harness/fdb_corpus.py` for more versioned bundles) |
| **Run** | `python3.11 benchmarks/run.py --suite amazon_fdb --ulb-sample stratified --limit 1000 --no-export` |
| **Current perf** | **43,000** ipblock rows in full corpus run · prior 1k smoke: **1000/1000** · label_mismatch **43.7%** |

### EV-403 · τ² simulator E2E (task success)

| | |
|--|--|
| **Data type** | Live τ² environments |
| **Status** | **later** — out of scope for evidence plane; we replay actions only |
| **Benchmark idea** | Only if we need apples-to-apples with τ² leaderboard (not current goal) |

### EV-RT · Red team suite (synthetic attacks + blind spots)

| | |
|--|--|
| **Stage** | 1 (cross-cutting) |
| **Data type** | Synthetic adversarial cases — no external corpus |
| **Harness** | `red_team` (`harness/adapters/red_team.py`) |
| **Benchmark idea** | Three categories per case: **control** (attack must be blocked), **baseline** (valid path must pass), **blind_spot** (documented gap must remain open). Exit 1 on control/baseline failure; blind_spot failure means we accidentally closed a known gap. |
| **Current perf** | **15/15 pass** · control **1.0** · baseline **1.0** · blind_spots_open **1.0** · schema/tool/cert/audit enforcement **1.0** |
| **Status** | **ready** |

| Case ID | Category | Attack / check | What it proves |
|---------|----------|----------------|----------------|
| `fraud_missing_decision` | control | Omit required `decision` field | Fraud output schema enforced |
| `fraud_score_overflow` | control | `fraud_score > 1.0` | Numeric bounds enforced |
| `fraud_negative_score` | control | Negative `fraud_score` | Numeric bounds enforced |
| `cap_disallowed_tool` | control | Call tool outside allowlist | MCP allowlist blocks |
| `cap_decoy_tool` | control | Allowed tool OK, decoy blocked | BFCL-style negative control |
| `cert_scope_blocks` | control | Tool outside certificate scope | Principal scope enforced |
| `audit_chain_after_block` | control | Blocked tool call | Audit chain survives block |
| `atif_tight_allowlist` | control | ATIF replay with 1/N tools allowed | Real trajectory partial block |
| `fraud_valid_baseline` | baseline | Valid fraud output | Sanity — good path still passes |
| `cert_scope_allows_baseline` | baseline | In-scope tool succeeds | Scope not over-blocking |
| `verify_tier_gap_documented` | blind_spot | No TEE quote at `bounded_auto` | `verify_valid` false is expected |
| `blind_spot_label_mismatch` | blind_spot | Approve with `ground_truth_fraud=1` | Policy ignores labels (ML gap) |
| `blind_spot_permissive_policy` | blind_spot | `rm_rf` under default MCP policy | Permissive policy has no allowlist |
| `blind_spot_no_spiffe_without_identity` | blind_spot | Export without `--with-identity` | Bundle lacks SPIFFE workload_principal |
| `baseline_spiffe_with_identity` | baseline | Export with `--with-identity` | SPIFFE present in authority block |

**Harness fix (2026-06-21):** `apply_agent_policy()` + fresh certificate per case — policy/cert mismatch caused false control failures on first run.

**Improve:** Tight policy mode for `mcp_bench_tasks`; label mismatch breakdown by decision class; trend `red_team_metrics` in CI.

---

## Demo sets (D-01 – D-08)

Curated narrative fixtures for humans (investors, partners, auditors). Generate with:

```bash
python benchmarks/demo/generate.py
```

| ID | Purpose | Source material | Deliverable | Status |
|----|---------|-----------------|-------------|--------|
| **D-01** | 5-minute product demo | ULB row 0 | Receipt + `WALKTHROUGH.md` | **ready** (`demo/generate.py`) |
| **D-02** | MCP live + prove | `examples/mcp_live_prove_client.py` + prove-mode ULB | Composed bundle + live path README | **ready** |
| **D-03** | Partner pilot story | Fixed $2,500 transaction | `partner_pilot_receipt.json` + `STORY.md` | **ready** |
| **D-04** | Capability block demo | BFCL decoy case | Narrative + exported allowed-call receipt | **ready** |
| **D-05** | Identity + receipt | `--with-identity` × 3 ATIF agents | 3 SPIFFE-bound bundles | **ready** |
| **D-06** | Auditor packet | ULB + ATIF + BFCL exports | `auditor_packet_10.zip` + `VERIFY.md` | **ready** |
| **D-07** | Compliance ingest | ECS mapping | `ecs_events.jsonl` (5 events) + sample fixture | **ready** |
| **D-08** | Assurance ladder | Same ULB row × 3 modes | `comparison.json` + shadow/bounded_auto/prove bundles | **ready** |

---

## Harness gaps (open)

| Issue | Fix |
|-------|-----|
| `verify_valid` mixed with Stage 1 pass | Document + optional `--require-verify` flag |
| No p50/p95 in `summary.json` | Extend `_summarize_suite()` |
| Concurrent runs same timestamp overwrite results | Use `--results-dir` always in automation |

---

## Suggested run matrix

```bash
# Discriminating signal (run before citing smoke pass rates)
python3.11 benchmarks/soundness.py --suite all --limit 200 --ulb-sample stratified \
  --results-dir benchmarks/results/soundness

python3.11 benchmarks/run.py --suite red_team \
  --results-dir benchmarks/results/red_team

# Full corpus E2E (local; ~20 min) — CLI --limit is int-only; use run_benchmarks(limit=None)
python3.11 -c "import sys; sys.path.insert(0,'benchmarks'); from pathlib import Path; from harness.runner import run_benchmarks; run_benchmarks(suites=None, limit=None, export_receipts=False, results_dir=Path('benchmarks/results/full_suite_all'))"

# τ² all domains (telecom uses tasks_small.json with --tau2-telecom-tasks small)
python3.11 benchmarks/run.py --suite tau2_policy --tau2-domain all --tau2-telecom-tasks small --limit 200

# SWE all shards in one report
python3.11 benchmarks/run.py --suite swe_session --swe-shard all --limit 50

# Mock TEE at scale (requires AGENT_RECEIPTS_ALLOW_STUB=1 for bounded_auto)
AGENT_RECEIPTS_ALLOW_STUB=1 python3.11 benchmarks/run.py --suite ulb_fraud --limit 10 --attach-mock-tee

# ECS + crosswalk reports from exported receipts
python3.11 benchmarks/ev301_ecs_export.py --results-dir benchmarks/results/stage1_export_sample --profile soc2
python3.11 benchmarks/ev302_crosswalk.py --results-dir benchmarks/results/stage1_export_sample

# SP1 guest build (one-time, needs sp1up)
scripts/sp1_build_fraud_head.sh
```

---

## Remaining priorities

1. **EV-203** — real TEE path when Nitro/NSM hardware is available (mock path: `--attach-mock-tee`)
2. **EV-301/302 CI gate** — optional `--fail-under` in CI over demo bundles
3. **SP1** — run `scripts/sp1_build_fraud_head.sh` and refresh `prove_tier.json` on builders with `sp1up`
