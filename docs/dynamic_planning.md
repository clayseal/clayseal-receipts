# Dynamic sandboxing + monitoring: planning notes

Date: 2026-06-29

This document captures a concrete starting point for **dynamic sandboxing (capability scoping)** and
**behavior monitoring** in an agent runtime, with a focus on a Devin/Cognition-style workflow.

The core goal is to reduce blast radius without pestering users:

- At the start of each goal/task/query, issue a **narrow, short-lived authority lease** that allows
  exactly the work needed for that goal, plus bounded context discovery.
- Continuously observe the agent’s *tool/resource trace* and tighten authority when behavior drifts
  or looks suspicious, while keeping prompts rare (ideally “once per goal”, not per tool call).

This repo already contains the enforcement seams:

- Enforcement boundary: `agentauth/receipts/mcp.py` (`ReceiptedMcpGateway.call_tool*`)
- Dynamic sandbox seam: `agentauth/receipts/sandbox_governor.py`
- Lease fields on authority: `agentauth/receipts/runtime.py::AuthorityContext`
  (`expires_at`, `lease_query_id`, `lease_remaining_calls`, `permit_epoch`, plus `resource_scope`)
- Monitoring seam + contract: `agentauth/receipts/behavior_monitor.py`,
  `agentauth/receipts/monitor_contract.py`

This doc focuses on the **capability scoper** (harder) and a **monitor that tightens** (advisory),
and how to keep both non-LLM at the top and bottom layers.

---

## Principles (non-negotiable)

1) **Enforcement must be deterministic and non-bypassable.**
   - Scoping/monitoring can be heuristic, but the final gate is a tool broker that can actually deny.
   - If an agent has direct filesystem/network access outside the broker, there is no sandbox.

2) **Similarity is not a security gate.**
   - Embedding similarity helps choose initial scope and auto-expand *read* within budgets.
   - Hard gates must still exist for secrets, exfil paths, privileged mutations, bulk scanning, etc.

3) **Monitoring is advisory, never authority-minting.**
   - A monitor can recommend `allow/step_up/deny`.
   - The governor decides enforcement and can only **tighten** unless a trusted step-up occurs.

4) **Minimize user prompts via “goal-scoped approvals” and novelty triggers.**
   - Default: silent.
   - Prompt only on high-risk transitions or repeated drift after tightening.

5) **Protected zones are not “never touch”; they are “explicit-intent only.”**
   - Access is allowed when (and only when) the *human user* explicitly asked for that class of work
     as part of the goal, or explicitly approved an expansion for this goal via a step-up.
   - “Explicit” must be derived from trusted control-plane input (not from tool output text).

---

## System sketch (plain)

**Inputs**
- `goal`: the user’s requested task (ticket/PR/issue description) and optional structured intent.
- `repo snapshot`: codebase state at the start of the goal (commit SHA, diff base).
- `trace`: stream of tool calls (tool name, resource refs, args hash, side-effect level).

**Outputs**
- A *lease scope* enforced at the broker:
  - allowed tool classes (read/write/egress/privileged)
  - allowed resources (`resource_scope` allowlist + protected zones)
  - budgets (calls/files/bytes/unique dirs/domains)
  - novelty triggers (new subsystem/domain/tool class → step-up)
  - permit/commit requirements for high-risk tools

**Control loop**
1) Capability scoper proposes initial scope for the goal.
2) Agent operates within scope; broker enforces.
3) Monitor watches trace; when risk rises, it recommends tightening.
4) Governor applies tightening: stop auto-renewals, reduce budgets, require step-up for novelty,
   bump `permit_epoch` to revoke permits, etc.

---

## Pitch summary (two-phase scoping + monitoring)

We’re building a two-phase system for agent sandboxing and drift monitoring.

Offline (per commit, async): chunk the repo into symbols (each with file+span), attach protected-zone
resource matchers and subsystem tags, build ANN + BM25 indexes over chunk embeddings/text, and build
a dependency graph with global PageRank as a write-risk / blast-radius prior.

At goal start (once per task): retrieve candidates via hybrid search (vector ANN + BM25 fused with
RRF), rerank the shortlist with a custom score that blends dense+sparse relevance, applies a
PageRank-based penalty for **writes** to high-centrality code unless the goal strongly matches, and
excludes protected resources unless explicitly allowed; select top‑k with MMR for coverage; expand
**read** scope via bounded BFS (or seeded personalized PageRank) from the seeds; translate this into
file-level read/write allowlists plus exploration budgets; then mint a short-lived, goal-bound
capability lease (and per-call permits / commit tokens for high-risk actions).

On every tool call (hot path): no vectors/PageRank—only deterministic checks against the lease scope,
budgets, expiry, and permit signatures, plus cheap drift/scan counters. Expensive retrieval reruns
only on new user goals, explicit scope-expansion requests, or monitor-driven tightening; edits can be
handled by incrementally re-chunking only touched files rather than rebuilding the whole index.

---

## V1 technical structure paragraph (verbatim)

> The dependency graph is not built from embeddings. Offline, per commit, we parse the repo with tree-sitter (plus special chunkers for YAML/Terraform/Helm) to extract symbol chunks and structural edges—imports, refs, build-manifest links. Global PageRank on that graph gives a cheap blast-radius / hub-risk prior for write scoping. SCIP (or similar compiler index) is optional: run periodically or on CI to upgrade heuristic cross-file edges to exact refs; day-to-day updates re-parse only changed files and their importers. ANN and BM25 sit on top of this graph as search indexes over chunks, not as the graph itself.
>
> For goal → initial chunk candidates, hybrid retrieval is justified but none of the pieces alone is “best.” BM25 over symbol names, paths, and identifiers catches ticket tokens and exact symbols; ANN (HNSW) over chunk embeddings catches intent when the ticket doesn’t name a symbol; RRF is a simple, robust way to fuse ranks without score calibration (v1 default, not the moat). Raw ripgrep is a weak one-shot ranker but a good third channel for tokens extracted from the goal. Production coding agents often grep iteratively; we use grep for candidate generation, not as the whole system. The quality lever is partner reranking of the shortlist (dense + sparse signals, PageRank write penalty, protected-zone rules)—not fancier fusion. Learned sparse models (e.g. SPLADE-Code) are a v2 evaluation, not a v1 requirement.
>
> Pipeline: tree-sitter graph + PageRank → (ANN + BM25 [+ goal-token rg]) → RRF → partner rerank + MMR → dependency read closure → file-level lease. Hot path stays deterministic scope/budget checks only; vectors and PageRank do not run per tool call.

### V1 clarifications (to avoid over-claiming)

- **Non-bypassable enforcement:** guarantees require a broker/sidecar that mediates FS/net/shell/tooling.
- **Protected zones:** “explicit intent” should authorize *specific resources/domains* (or tight matchers), not broad classes.
- **Dependency writes:** v1 should allow a bounded write-closure over direct dependencies (with caps), not only read-closure.

---

## Resource model (what we can actually enforce)

Everything must become a `resource_ref` at the broker boundary.

- `repo://path/to/file.py` (read/write)
- `mcp://server/tool` (tool identity)
- `net://api.example.com/path` (egress)
- `secrets://…` (logical protected zone; usually backed by paths, env, keychains)

Even if we reason about “semantic chunks”, enforcement ultimately gates on resources (usually paths).

---

## Proposed approach: semantic chunks + dependency closure

### Summary

We index the repo into **semantic chunks** (not files), embed them, and use a custom similarity
metric (partner-supplied) to identify the top-k “most relevant” chunks to the goal.

We then translate “allowed chunks” into enforceable scope by including:

- write access to the files/spans that contain those chunks
- read access to those files + bounded “context discovery”
- read access to a dependency closure rooted at those chunks (imports/build graph)

Monitoring watches which chunks/resources are being touched and computes drift and scanning signals.

### What the scoper is allowed to do automatically (no user prompt)

- Add *read-only* scope for nearby/dependency files within budgets.
- Expand read scope when the agent hits “missing context” patterns (compiler errors, import errors),
  but only within non-sensitive zones and within exploration budgets.

### What always requires step-up (rare prompts)

- First time touching a protected zone (keys/creds/deploy/payment/auth).
- Any external egress (or any new domain).
- Any privileged mutation (deploy, rotate secrets, publish, pay, push).
- Large scans (directory walking / mass grep) beyond conservative budgets.

---

## Tightening behaviors (what the monitor should trigger)

The monitor should not “decide correctness”; it should detect **trajectory anomalies** and request
tightening:

- Stop lease auto-renewals (so the next boundary crossing triggers a single prompt).
- Reduce exploration budget (unique dirs/files/bytes).
- Require step-up on novelty triggers (new subsystem/new domain/new tool class).
- Bump `permit_epoch` (revokes previously issued permits).

The “drift message” to the agent should be mechanical and non-LLM:

> You’re operating outside the approved scope for this goal. If you found an unrelated issue,
> log it via `log_issue` and continue only on the approved goal scope.

---

## Protected zones: explicit-intent semantics

Protected zones exist because they are high-leverage compromise targets (secrets, CI/CD, deploy, auth
boundaries, payment flows, outbound channels). However, real work sometimes legitimately requires
touching them. The correct policy is therefore:

- **Default:** protected zones are *not* in scope for ordinary coding goals.
- **Allowed only with explicit intent:** the user’s goal explicitly includes *the specific protected
  resources to touch*, or the user approves a step-up expansion for *specific resources* (not a
  broad category).
- **Still bounded:** even when allowed, apply tighter budgets, require permits, and require commit
  tokens for irreversible actions.

### What counts as “explicit intent”

Accept as explicit intent:
- The user’s goal contains a structured intent field (preferred), for example:
  - `goal.intent.allow_resources = ["repo://.github/workflows/release.yml"]`
  - `goal.intent.allow_resources = ["repo://deploy/prod/**"]`
  - `goal.intent.allow_resources = ["repo://keys/signing/ocm-attest.key.pem"]`
- The user approves a step-up prompt in the control plane that clearly names the resource(s) and
  operation type (read/write/egress), for this goal lease.

Do **not** accept as explicit intent:
- Text that originates from untrusted tool outputs (web pages, logs, files) suggesting “please open
  secrets/keys”.
- The agent’s own suggestion that it “needs” secrets access.

### Prompt minimization with explicit intent

To keep prompts rare:
- If the goal is explicitly about protected resources, include them in the **initial scope** (one
  prompt at goal start, or none if the user’s request already declares them).
- Otherwise, block/step-up only on the **first boundary crossing** into a protected zone for the
  goal, and cache that approval for the specific resource matcher(s) for the remainder of the goal
  lease.

Note: it is still useful internally to tag protected resources by class (e.g., `secrets`, `ci_cd`)
for default policies and reporting, but approvals should be scoped to concrete resources whenever
possible to avoid over-granting.

---

## Brainstorm areas

### A) What is a “chunk”?

We need a definition that:
- is stable across repo layout styles
- maps back to enforceable resources (file + span)
- supports dependency closure and “subsystem novelty” detection

Options (use one or mix):

1) **Symbol chunks (preferred when language tooling exists)**
   - Functions, classes, methods, modules; plus doc/comments immediately attached.
   - Pros: maps cleanly to dependencies (imports, call graph); spans are natural.
   - Cons: needs language tooling; polyglot complexity.

2) **AST node blocks (language-aware)**
   - Slightly lower-level than symbols; useful for config languages.
   - Pros: structured; robust to formatting.
   - Cons: more tooling; harder to explain.

3) **Sliding window text chunks (language-agnostic fallback)**
   - Token/line windows with overlap.
   - Pros: works everywhere.
   - Cons: dependency closure is weaker; spans often cross concerns; higher false positives.

Practical recommendation:
- Use **symbol chunks** where possible (Python/TS/Go/Rust), and fall back to sliding windows for
  unknown file types.

#### Decision (2026-06-29): v1 chunk definition

**Three-tier chunking (one indexer pass → `RepoChunkIndex` at `repo@sha`):**

1. **Tree-sitter symbol chunks** — Python, TS, JS, Go, Rust  
   Extract named nodes (functions, methods, classes, types, modules/namespaces). Each symbol = one
   chunk with `file_path`, `start_line`, `end_line`, `qualified_name`, `language`.

2. **Special-case chunkers** — infra/config where symbols aren’t enough  
   - YAML: GitHub Actions workflows → job/step blocks; generic YAML → top-level keys  
   - Terraform: resource/data blocks  
   - Helm: chart templates / values sections  
   (Add others as needed; same metadata shape as symbol chunks.)

3. **Fallback sliding windows** — everything else  
   ~120 lines, 24-line overlap; `kind = window`.

**Per-file extras (all tiers):**
- **`file_preamble`** chunk where tree-sitter finds one: imports / package header before first symbol
  (feeds import-graph closure).

**Chunk ID:** `hash(repo_sha, file_path, kind, qualified_name | block_id | window_index)`.

**Edit → chunk:** broker maps changed lines to intersecting chunks; orphan lines → flag + re-index,
  don’t auto-expand scope.

**Embed unit:** symbol/block text (+ qualified name / resource name for config chunks).

**Not v1:** LSP spans, call-graph chunks, cross-file merged chunks.

**v2:** tune tree-sitter query sets per language; more infra chunkers (K8s manifests, Dockerfile stages).

Chunk metadata needed:
- `chunk_id`
- `file_path`, `start_line`, `end_line` (for trace mapping and optional region hints)
- `language`, `kind` (symbol/window/config)
- `subsystem_tags` (derived heuristically: path prefixes, package name, owner)
- `sensitivity_label` (normal / protected / highly_protected)

### B) How do we compute “direct dependencies”?

We want a *safe, deterministic* closure algorithm:

1) **Import graph (fast, good baseline)**
   - Python: `import`/`from` parsing (+ package resolution heuristics).
   - TS/JS: `import`/`require` plus tsconfig path mapping.
   - Go/Rust: module graph from build manifests (`go.mod`, `Cargo.toml`).

2) **Build/test graph**
   - Identify build/test entrypoints and configs needed to run relevant tests.
   - Expand read scope to those config files (read-only) and test directories.

3) **LSP-assisted resolution (higher quality)**
   - When available, ask the language server for “go to definition / references”.
   - Pros: accurate; handles dynamic imports better.
   - Cons: infra heavier; slow; flaky in CI.

Practical recommendation:
- Start with import graph + build manifests, then add LSP as an optional “quality layer”.

#### Decision (2026-06-29): v1 dependency closure

**Level:** L1 file import graph only (not symbol/call graph, not LSP in v1).

**Seed:** top-k semantic chunks → root files `F₀`.

**Closure:**
- **Write:** chunks in `F₀` only (files containing top-k hits). No auto-write on imported deps.
- **Read:** all chunks in `F₀ ∪ F₁`, where `F₁` = direct import targets of `F₀` (one hop).
- **Optional read-only `F₂`:** second import hop for discovery only, behind a budget or step-up (defer if simpler to ship without).
- **Build/test (read-only):** manifest files (`pyproject.toml`, `package.json`, …) + test files that import `F₀` — explicit rule, not an import hop.

**Enforcement mapping:** chunk-grained for similarity/monitoring; closure computed on **files**, then `chunk ∈ allowed ⟺ chunk.file ∈ allowed_files(mode)`.

**Protected zones:** may appear in `F₁`; read can be allowed or step-up per org config, **write never** without step-up.

**Importing a sensitive module (e.g. auth):** default **read yes, write no** unless that chunk/file is in top-k or step-up widens it. Monitor flags edits to low-similarity / high-sensitivity chunks even when read was allowed.

**Limits:** no transitive write closure; hop cap on auto-read; call-graph / symbol-level closure → v2.

### C) Protected zones & high-risk transitions (override similarity)

These rules should be mostly repo-agnostic, with per-org overrides:

Protected zones (never auto-grant; step-up required; sometimes deny):
- credential stores / key material: `keys/`, `.env*`, `*.pem`, `*.key`, `id_rsa`, kubeconfigs
- deployment / infra: `terraform/`, `deploy/`, `helm/`, `k8s/`, CI pipelines
- auth / identity / permissions boundaries: `auth/`, `identity/`, IAM policy files
- payments / exfil channels: webhook handlers, email, slack, outbound HTTP clients

High-risk transitions:
- **Network egress** (especially new domains)
- **Bulk read/scan** (directory walk, `rg` across repo) beyond budget
- **Privileged mutation** (push, deploy, rotate secrets, write to protected zones)
- **Cross-subsystem novelty** (touching a subsystem with low goal similarity)

Practical recommendation:
- Hard-code a conservative baseline + allow org-provided patterns.

---

## Evaluation (how we know it’s working)

User-friction metrics:
- prompts per goal (target: ~0–1)
- “blocked but should have been allowed” rate

Containment metrics:
- prevented secret reads/egress attempts
- prevented bulk scanning beyond budgets

Productivity metrics:
- time-to-first-successful-edit
- test pass rate per goal without step-ups

---

## Next steps (implementation plan)

1) Define a canonical `RepoChunkIndex` artifact (chunks + embeddings + labels + dependency edges).
2) Implement `capability_scope(goal, index) -> scope` as deterministic code:
   - choose top-k chunks
   - add dependency closure
   - apply protected-zone overrides and budgets
3) Implement a drift/scanning scorer over the broker trace:
   - relevance trend
   - novelty rate
   - scan-budget pressure
4) Wire monitor recommendations into governor tightening policy (stop renewals, step-up on novelty).

---

## V1 implementation backlog (comprehensive)

This backlog breaks the v1 structure into implementable work items. Coordination markers:

| Marker | Meaning |
|--------|---------|
| `[ ]` | Not started |
| `[>]` | Being worked on (add an owner note inline) |
| `[~]` | Partial / landed in pieces |
| `[x]` | Done |

When you start an item, change it to `[>]` and add an owner note, for example:
`### DP-7: Build BM25 index [>] *(being worked on — cognition/proto)*`

### Parallel tracks

| Track | Owner | Items |
|-------|-------|-------|
| **Chunking + graph** | cursor/agent | DP-1 … DP-9 |
| **Retrieval + rerank** | cursor/agent | DP-10 … DP-16 |
| **Scoping + policy** | cursor/agent | DP-17 … DP-25 |
| **Enforcement broker** | unassigned | DP-26 … DP-32 |
| **Monitoring + drift** | unassigned | DP-33 … DP-38 |
| **Eval + perf** | unassigned | DP-39 … DP-45 |

### Chunking + graph

### DP-1: Define `RepoChunk` schema + stable `chunk_id` `[x]`

- Shipped: `agentauth/receipts/scoping/models.py`

### DP-2: Implement tree-sitter symbol chunker for core languages `[x]`

- Python: `ast` module. JS/TS: regex-based (functions, arrow consts, classes). Go: regex (func, type). Rust: regex (fn, struct, enum, trait, impl).
- All in `scoping/chunkers.py`; tree-sitter can upgrade regex quality in v2.
- Tests: `python/tests/test_dp2_3_12_chunkers.py::TestJsChunker`, `TestGoChunker`, `TestRustChunker`

### DP-3: Implement special chunkers for infra/config files `[x]`

- YAML: per-top-level-key blocks; GitHub Actions workflows chunked per job.
- Terraform/HCL: per resource/data/module/variable/output block.
- Tests: `python/tests/test_dp2_3_12_chunkers.py::TestYamlChunker`, `TestTerraformChunker`

### DP-4: Add protected-zone labeling pipeline `[x]`

- Shipped: `scoping/labels.py`

### DP-5: Add subsystem tagging pipeline `[x]`

- Shipped: path-prefix heuristics in `scoping/labels.py`

### DP-6: Build structural dependency edges (import/build-manifest graph) `[x]`

- Shipped: `scoping/imports_graph.py` + manifest detection

### DP-7: Compute global PageRank on the dependency graph `[x]`

- Shipped: `scoping/pagerank.py`

### DP-8: Implement incremental updates for changed files `[x]`

- Impl: `agentauth/receipts/scoping/session_overlay.py` — `SessionChunkOverlay`
- Tests: `python/tests/test_dp8_overlay.py`

### DP-9: Optional: integrate compiler index (SCIP/LSIF/LSP) for exact refs `[~]`

- Shipped integration seam: `scoping/reference_edges.py` + `build_repo_chunk_index(..., reference_edges_path=...)`
- Tests: `python/tests/test_scoping.py::test_build_repo_chunk_index_merges_reference_edges`

### Retrieval + rerank

### DP-10: Build ANN vector index over chunk embeddings (HNSW) `[x]`

- Shipped: `scoping/retrieval/ann.py` — `build_ann_index`, optional `HnswAnnIndex`, fallback `CosineAnnIndex`, `HashingEmbedder`
- Wired into pipeline: `capability_scope.py::score_chunks_for_goal()` uses ANN + BM25 + tokens via RRF

### DP-11: Build BM25 (lexical) index over chunk text + identifiers `[x]`

- Shipped: `scoping/retrieval/bm25.py`

### DP-12: Add goal-token extraction + `rg` candidate channel (optional v1) `[x]`

- Token overlap rank in `capability_scope.py`.
- `rg` channel: `scoping/retrieval/rg_channel.py` — `rg_rank_chunks()`, `extract_goal_tokens()`. Graceful when rg unavailable.
- Tests: `python/tests/test_dp2_3_12_chunkers.py::TestRgChannel`

### DP-13: Implement RRF fusion for candidate ranks `[x]`

- Shipped: `scoping/retrieval/rrf.py`

### DP-14: Define partner rerank interface (the “moat seam”) `[x]`

- Shipped: `PartnerReranker` protocol + `DefaultChunkReranker` stub in `scoping/retrieval/rerank.py`

### DP-15: Implement MMR selection for top‑k coverage `[x]`

- Shipped: `scoping/retrieval/mmr.py`

### DP-16: Calibrate default candidate sizes and time budgets `[x]`

- Shipped: calibrated defaults in `scoping/capability_scope.py` (`_DEFAULT_*_CANDIDATES`, `_DEFAULT_SHORTLIST`)

### Scoping + policy

### DP-17: Define goal schema with structured explicit-intent allowlist `[x]`

- Shipped: `scoping/goal.py` (`GoalSpec`, `allow_resources`)

### DP-18: Translate top‑k chunks → file-level write allowlist `[x]`

- Shipped: `build_capability_lease()` in `scoping/capability_scope.py`

### DP-19: Add bounded dependency closure for reads `[x]`

- Shipped: `scoping/closure.py`

### DP-20: Add bounded dependency closure for writes (non-sensitive only) `[x]`

- Shipped: `scoping/closure.py` (direct deps, caps, protected filter)

### DP-21: Add exploration budgets for read-only context discovery `[x]`

- Caps: files/bytes/unique dirs per time window.
- Disable exploration when in tightened mode.
- Impl: `agentauth/receipts/scoping/exploration_budget.py` — `ExplorationBudget`
- Tests: `python/tests/test_dp21_22_24.py::TestExplorationBudget`

### DP-22: Define novelty triggers and thresholds `[x]`

- Triggers: new subsystem, new tool class, new net domain, protected zone attempt.
- Impl: `agentauth/receipts/novelty_monitor.py` — `NoveltyMonitor`
- Tests: `python/tests/test_dp21_22_24.py::TestNoveltyMonitor`

### DP-23: Protected-zone policy: default deny/step-up unless explicitly allowed `[x]`

- Shipped: protected labels + write-seed filtering in closure.
- Broker wiring: `agentauth/receipts/protected_zone_governor.py` — `ProtectedZoneGovernor`
- Tests: `python/tests/test_dp23_30_40.py::TestProtectedZoneGovernor`

### DP-24: “Tighten mode” policy (risk-adaptive) `[x]`

- Actions: stop lease auto-renewal, reduce budgets, require step-up on novelty, bump `permit_epoch`.
- Impl: `agentauth/receipts/tighten_policy.py` — `TighteningGovernor` with persistent mode
- Tests: `python/tests/test_dp21_22_24.py::TestTightenMode`

### DP-25: Export scope decisions as receipt evidence `[x]`

- Ensure scope/patches/blocks appear in receipts for auditability.

### Enforcement broker

### DP-26: Define enforcement boundary and non-bypassability requirements `[~]`

- Decide deployment shape: sidecar proxy vs MCP-only vs hybrid.

### DP-27: Implement deterministic scope checks on the hot path `[x]`

- Check: resource allowlists, budgets, lease expiry/query binding.
- Must be O(1) per tool call.

### DP-28: Implement per-call signed permits for high-risk tools `[x]`

- Bind: query_id, tool, args hash, resource_ref, expiry, epochs.
- Verification at broker boundary.

### DP-29: Implement commit tokens for irreversible actions (two-phase commit) `[x]`

- Require commit token for configured tools/resources.

### DP-30: Implement step-up protocol + scope patch application `[x]`

- Return `step_up_required` with structured request details.
- Apply approved patches to lease state.
- Impl: `agentauth/receipts/step_up.py` — `StepUpRequest`, `StepUpApproval`, `apply_step_up()`
- Tests: `python/tests/test_dp23_30_40.py::TestStepUpProtocol`

### DP-31: Implement revocation epoch / permit epoch bump `[x]`

- Ensure old permits become invalid when tightened.

### DP-32: Add safe default deny behavior for missing authority `[x]`

- Fail closed on critical actions if lease/permit is missing or invalid.
- Impl: `agentauth/receipts/default_deny_governor.py` — `DefaultDenySandboxGovernor`
- Tests: `python/tests/test_drift_scanning_tighten.py::TestDefaultDenySandboxGovernor`

### Monitoring + drift

### DP-33: Define monitor input contract fields required for drift/scanning `[x]`

- Use only trusted telemetry (tool, args hash, resource ref, subsystem tags, lease facts).

### DP-34: Implement drift scorer (relevance trend) `[x]`

- Compute rolling relevance for touched chunks/files; track downward trends.
- Impl: `agentauth/receipts/drift_monitor.py` — `DriftScorer`
- Tests: `python/tests/test_drift_scanning_tighten.py::TestDriftScorer`

### DP-35: Implement scanning scorer (breadth/entropy) `[x]`

- Track unique dirs/files/subsystems; detect rapid spread.
- Impl: `agentauth/receipts/scanning_monitor.py` — `ScanningScorer`
- Tests: `python/tests/test_drift_scanning_tighten.py::TestScanningScorer`

### DP-36: Define tighten triggers from monitor signals `[x]`

- When to disable auto-expansion, stop renewals, bump epochs, require step-up for novelty.
- Impl: `agentauth/receipts/tighten_policy.py` — `evaluate_tighten_triggers`, `TighteningGovernor`
- Tests: `python/tests/test_drift_scanning_tighten.py::TestTightenTriggers`, `TestTighteningGovernor`

### DP-37: Integrate monitor outputs into receipts (non-repudiable trace commitment) `[x]`

- Store `trace_commitment` for monitor inputs.

### DP-38: Add a sidecar monitor integration seam (optional v1) `[x]`

- Keep non-LLM at top/bottom layers; sidecar may be used for heavier monitors.

### Eval + perf

### DP-39: Build a small scenario harness (normal + adversarial) `[x]`

- Normal tasks: typical bugfix/refactor/test update flows.
- Adversarial/drift: scanning, protected-zone probing, egress attempts, novelty jumps.
- Tests: `python/tests/test_dp39_scenario_harness.py` — 19 scenarios (bugfix, refactor, test update, scanning, protected-zone probe, egress, drift, novelty jump, full e2e)

### DP-40: Define success metrics + baselines `[x]`

- Shipped: `agentauth/receipts/ops/goal_metrics.py` (`GoalMetrics`, `GoalMetricBaselines`, `summarize_receipt_bundles`, `evaluate_goal_against_baselines`)
- Tests: `python/tests/test_goal_metrics.py`

### DP-41: Implement performance budgets + instrumentation `[x]`

- Hot path target overhead (ms), cold path goal-scope compute time.
- Shipped: `mcp/mcp.py` — `_PERF_BUDGETS_MS`, per-call `timings_ms` (policy, monitor, governor, tool exec, record, total), `_perf_budget_warnings()` advisory warnings on every `ToolCallResult`.

### DP-42: Add regression tests for protected-zone semantics `[x]`

- Ensure no implicit allow from tool outputs; explicit allow works for specific resources.
- Tests: `python/tests/test_dp42_43_regressions.py::TestProtectedZoneSemantics`
- Also fixed: `labels.py` root-level glob matching for `**/` prefixed patterns.

### DP-43: Add regression tests for bounded dependency-write closure `[x]`

- Ensure direct-dep write allowed within caps; further writes require step-up.
- Tests: `python/tests/test_dp42_43_regressions.py::TestBoundedDepWriteClosure`

### DP-44: Add “tighten mode” tests `[x]`

- Ensure tightening disables auto-expansion and bumps epochs.
- Tests: `test_dp21_22_24.py::TestTightenMode` (persistent mode), `test_drift_scanning_tighten.py::TestTightenTriggers` + `TestTighteningGovernor` (per-action triggers)

### DP-45: Document deployment patterns and threat model `[x]`

- Documented below: **Deployment patterns and threat model (DP-45)**.

---

## Mapping to existing Clay Seal Receipts implementation (so we can test now)

This repo already contains key pieces of the *enforcement* and *monitoring* layers. The “repo
indexing / retrieval / graph PageRank” parts are new work, but we can already run a redteaming-style
case harness to validate the broker semantics (commit tokens, permit epochs, tool-output poisoning
resistance for monitors, etc.).

### What already exists (high-signal DP items)

- **DP-26 `[~]` Enforcement boundary exists; non-bypassability depends on deployment**
  - Enforcement choke point exists at `agentauth/receipts/mcp.py` (`ReceiptedMcpGateway`).
  - “Non-bypassable” still requires running the agent behind a tool broker/sidecar; this repo
    provides the broker logic but cannot enforce your runtime topology by itself.

- **DP-27 `[x]` Deterministic checks on the hot path**
  - `agentauth/receipts/mcp.py` enforces violations/blocks before tool handler execution.

- **DP-28 `[x]` Per-call signed permits (tool permits)**
  - Issuance/verification: `agentauth/receipts/permit.py`
  - Permit checks are enforced in `agentauth/receipts/mcp.py`.

- **DP-29 `[x]` Commit tokens (two-phase commit)**
  - Issuance/verification: `agentauth/receipts/commit.py`
  - Enforced in `agentauth/receipts/mcp.py` for commit-required tools.

- **DP-31 `[x]` Revocation epoch / permit epoch bump**
  - `AuthorityContext.permit_epoch`: `agentauth/receipts/runtime.py`
  - Gateway API: `agentauth/receipts/mcp.py::ReceiptedMcpGateway.revoke_permits`
  - Verified by permits/commit tokens (epoch mismatch blocks).

- **DP-33 `[x]` Monitor input contract (trusted telemetry only)**
  - Contract + trace commitment: `agentauth/receipts/monitor_contract.py`
  - Safe legacy handling: `agentauth/receipts/behavior_monitor.py::evaluate_behavior_monitor`

- **DP-37 `[x]` Monitoring evidence is non-repudiable (trace commitment)**
  - Gateway fills `trace_commitment`: `agentauth/receipts/mcp.py`

- **DP-38 `[x]` Sidecar monitor seam**
  - HTTP sidecar adapter: `agentauth/receipts/sidecar_behavior_monitor.py`

- **DP-44 `[~]` Tighten-mode behavior exists in prototype form**
  - `RuleBasedSandboxGovernor` can suspend lease renewal on suspicious monitor recommendations:
    `agentauth/receipts/sandbox_governor.py`

### Devin/Cognition redteaming case harness (quick test loop)

The harness is a JSONL-driven scenario runner that exercises the MCP broker path.

- Test runner: `python/tests/test_devin_redteaming_backlog.py`
- Default fixture cases: `python/tests/fixtures/devin_redteaming_backlog.jsonl`
- Primarily exercises: DP-27/28/29/31 (broker + permits + commit tokens + epochs) and DP-33/37
  (monitor input contract + trace commitments, via related unit tests).
- Optional env override:
  - `AGENT_RECEIPTS_DEVIN_CASES=/abs/path/to/cases.jsonl`
  - or legacy `AGENT_RECEIPTS_COGNITION_CASES=/abs/path/to/cases.jsonl`

Run:

```bash
cd /Users/pberlizov/Documents/GitHub/clay-seal-receipts-main
pytest -q python/tests/test_devin_redteaming_backlog.py
```

Target a single case:

```bash
cd /Users/pberlizov/Documents/GitHub/clay-seal-receipts-main
pytest -q python/tests/test_devin_redteaming_backlog.py -k poisoned_tool_output_attempts_transfer_without_commit
```

Related unit tests:

- Monitor contract + poisoning resistance: `python/tests/test_monitoring_contract.py`

---

## Live updates (as the agent moves through the repo)

The base index is **frozen at `repo@sha` when the goal starts**. The agent changes files during the
session, so we maintain a **session overlay** on top — do not re-index the whole repo on every edit.

### Two layers

| Layer | When built | Mutability |
|-------|------------|------------|
| **`RepoChunkIndex`** | CI / goal start @ `repo@sha` | Immutable for that SHA |
| **`SessionChunkOverlay`** | During the session | Append + patch only |

### What updates, when

**On read (tool returns file/chunk content):**
- Record chunk in **touched set** (for monitor trajectory).
- Optional **read widen:** if `sim(goal, chunk) ≥ read_threshold` and budgets allow, add chunk/file to
  read scope. No re-embed (base embedding unchanged).

**On write (patch applied):**
1. Re-run chunker on **that file only** → new spans / updated symbol bodies.
2. Re-embed **only affected chunks** in the overlay (same `chunk_id` if same symbol + lines moved slightly;
   new ids for new symbols / orphan spans).
3. Store `content_hash` + embedding in overlay; base index unchanged.
4. If imports changed → recompute **import closure for that file**; new `F₁` files → read scope only
   (same v1 dep rules).

**Goal vector:** fixed for the lease unless the user sends a **new message** or **step-up widen** →
then re-embed goal text and optionally refresh top-k (new lease epoch).

**Monitor inputs (each action):**
- `sim(goal, chunk)` using overlay embedding if present, else base.
- Rolling **touched-chunk sequence** — penalty for many low-sim reads/edits in a row.
- CoT optional, weak; **actions dominate**.

### Scope vs representation

- **Representation update** (re-chunk, re-embed edited file) ≠ **authority widen**.
- Editing an allowed file always updates overlay embeddings; it does not auto-add write access elsewhere.
- Widen still requires: high sim + budget, or step-up, or new signed lease epoch.

### When to rebuild base index

- New commit / `repo@sha` change → full re-index (async if possible; block or pause agent until ready).
- Not on every tool call.

### Minimal overlay record

```yaml
chunk_id: ...
content_hash: ...
embedding: [...]   # partner model
source: overlay    # base | overlay
supersedes: ...    # if chunk_id reused with new content
```

---

## Open questions

### Must decide (blocks build)

1. **Metric contract** — Partner similarity function: inputs, score range, version id committed in lease token.
2. **Embedding lifecycle** — Base at index time @ `repo@sha`; **overlay re-embed on write (per file)**; full re-index on SHA change.
3. **Similarity vs security** — Similarity picks scope only; labels + hard rules (egress, protected zones) always override.

### Decide as we go

Top-k, drift thresholds, read-widen thresholds, CoT weight, step-up UX, OCM wiring, eval suite, broker placement, lease granularity. Pick sensible defaults; tune from pilot.

### Already decided

- **Chunks:** tree-sitter symbols (Py/TS/JS/Go/Rust) + infra chunkers + window fallback.
- **Dependencies:** write on seed files only; 1-hop import read; build/test configs read-only.
- **Edit → chunk:** line intersection; orphan spans flag for re-index.

---

## Deployment patterns and threat model (DP-45)

This section exists to make “non-bypassable enforcement” concrete and to clarify what this system
does (and does not) protect against.

### Threat model (what we’re trying to stop)

- **Prompt injection via untrusted tool output** leading to protected-zone access, egress, or
  unrelated high-blast-radius changes.
- **Goal drift / scope creep** (agent wanders into unrelated subsystems, broad scanning, or
  “cleanup” work).
- **Secret exposure and exfiltration** (reading key material, CI secrets, cloud creds; sending them
  over the network).
- **Accidental blast radius** (wide refactors, deleting data, mutating infra/deploy without intent).

### Non-bypassability requirement (the hard part)

All privileged effects must pass through a deterministic enforcement boundary (the broker). The
system is not a sandbox if the agent can bypass the broker and touch:

- the filesystem (read/write) directly
- network egress (DNS/HTTP/raw sockets) directly
- privileged local capabilities (shell, package managers, git push, cloud CLIs) outside mediation

**Practical checklist:**

- Run the agent in a container / VM / sandbox where raw egress is disabled by default.
- Provide filesystem access only via brokered tools (or mount repo read-only and apply changes via
  a brokered patch tool).
- Route all egress through a brokered proxy tool that enforces domain/path budgets + step-up.
- Treat “shell” as a tool class: either disallow entirely or require explicit, brokered commands
  with tight scopes (cwd allowlist, arg hashing, output size caps).

### Deployment shapes (v1-compatible)

1) **MCP-only broker (tool-only world)**
   - Works when the agent runtime has *no* direct FS/net and everything is a tool call.
   - Failure mode: “hidden bypass” via a tool that itself can access broad FS/net (e.g., a raw
     shell tool with network enabled).

2) **Sidecar broker / proxy (hybrid world)**
   - Agent runs normally, but file/net/shell are routed through a sidecar that enforces leases.
   - Best when you can’t guarantee tool-only execution but can control runtime topology.

3) **Containerized agent with brokered capabilities (recommended)**
   - Put the agent in a locked-down container (seccomp/AppArmor, no raw net, minimal mounts).
   - Expose only brokered tools (FS patching, scoped reads, egress proxy).

### Operational guidance (what to default to)

- **Default deny** for protected zones and egress; require explicit-intent or step-up scoped to
  concrete resources/domains (not broad categories).
- **Budgets over heuristics:** cap exploration (unique dirs/files/bytes/time), then tighten on drift.
- **Tighten on repeated boundary pressure:** when the agent repeatedly hits blocks/novelty triggers,
  stop auto-expansion and force a single step-up decision at the control plane.
- **Audit everything:** include lease decisions, denies, step-ups, and trace commitments in receipts.

### Known limitations (don’t over-claim)

- Similarity/reranking is a *productivity* primitive, not a security primitive.
- Dependency closure is incomplete in dynamic languages and polyglot repos; treat it as a best-effort
  read helper, not a write authority grant.
- If the runtime topology allows bypass (direct FS/net/shell), enforcement guarantees collapse.
