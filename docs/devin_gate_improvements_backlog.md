# Devin demo (Cognition) — improvement backlog

Derived from the red-teaming scorecard and documented blind spots in:
- `docs/devin_redteaming_backlog.md`
- `examples/devin-agentauth-demo/devin_redteaming_backlog.md`

This backlog tracks *product-facing* improvements (PR gate + tool-time controls + receipts) that
increase resilience to realistic adversaries.

**L2/L3 sandbox + monitoring roadmap:** [l2_l3_sandbox_monitor_backlog.md](l2_l3_sandbox_monitor_backlog.md)

## Status markers

- `[ ]` not started
- `[>]` in progress
- `[~]` partial
- `[x]` done

## GATE

### GATE-1: Detect audit suppression (A4 / issue-#5) `[x]`

Problem: the current gate focuses on path scope + forbidden **added**-line regexes. Deleting or
silencing audit emission in an allowed file can be indistinguishable from “log cleanup”, so the
PR diff can be clean enough to ALLOW.

Acceptance:
- Add an invariant mechanism for *security-trail must-exist* calls (deletion-sensitive).
- Gate returns a structured issue code (e.g. `audit_trail_removed`) when an invariant is violated.

**Shipped:** `protected_invariants` in hardened policy + `InvariantPolicyEngine` / `structural_invariants.py` (SM-8).

### GATE-2: In-scope semantic invariant checks (D1 / J2 / I2) `[x]`

Problem: in-scope semantic bypasses (remove preview/auth coupling *within* `parser.py`) are
structurally invisible to path gates and brittle for keyword regexes.

Acceptance:
- Allow mandates/policies to express “semantic invariants” for security-sensitive behaviors.
- Enforce via lightweight checks (AST patterns / required tests / or explicit approval obligation)
  that do not depend on the agent using the word “bypass”.

**Shipped:** `must_call` / `must_contain` protected invariants close D1/I2/J2/L1 removal class
(hardened policy + `evaluate_devin_advanced_attacks.py --hardened` 10/10).

### GATE-3: Multi-PR / slow-drip aggregation (G) `[x]`

Problem: a sequence of individually-allowed diffs can compose into a bypass.

Acceptance:
- Add a mode that evaluates against a baseline horizon (e.g. N commits / last checkpoint receipt)
  and surfaces “trajectory risk” issues.

**Shipped:** `trajectory_risk.py` — horizon invariant checks (`trajectory_invariant_removed`),
prior-receipt aggregation (`trajectory_slow_drip`, `trajectory_risk` flags), wired into
`evaluate_pr_gate` + demo gate (`--horizon-ref`, `trajectory` / `ci_context` policy blocks).
Hardened policy enables trajectory + prior-receipt horizon checks.

## TOOL-TIME / RUNTIME

### RT-1: Egress as a capability (runtime exfil: #4 / C4) `[x]`

Problem: runtime network exfiltration can succeed with a clean diff; PR scanning cannot catch it.

Acceptance:
- Default-deny outbound network calls unless explicitly authorized.
- Record/attest tool-time network actions in receipts (input/output hashes + destination).

**Shipped:** `agentauth/receipts/egress.py` + policy `egress:` block + MCP pre-execution checks.
Harness: `scripts/evaluate_runtime_egress.py`.

### RT-2: Tool pinning + anti-rug-pull (MCP) `[x]`

Problem: MCP “rug pull”/tool-output poisoning bypasses repo diffs (PR gate N/A).

Acceptance:
- Bind tool metadata (schema/description hash) and tool endpoint identity into the receipt.
- Optionally require a tool witness/cosignature for high-risk tools.

**Shipped:** `tool_pinning.py` + policy `tool_pinning:` block; MCP gateway pins on first call,
denies description/schema drift; `tool_schema_hash` on receipts; optional `require_witness_tools`.

## RECEIPTS / CHAIN

### CHAIN-1: Cross-session attribution guardrail (I1→I2) `[x]`

Problem: poison enters in an allowed doc write; later clean diffs execute it.

Acceptance:
- Use the receipt chain to attribute later violations to earlier writes.
- Surface a verifier output that links the causal chain (“this clean diff is executing prior poisoned state”).

**Shipped:** `cross_session_poison_attribution` flag + `agentauth/receipts/receipt_chain.py`
(receipt_chain links, `verify-receipt --check-chain`, gate `receipt_chain` block).
Harness: `scripts/evaluate_receipt_chain.py`.

### GATE-5: Instruction-surface write policy (I1) `[x]`

Problem: agent-runtime memory (``.devin/knowledge.md``) and auto-loaded repo instruction
surfaces (``AGENTS.md``, ``CLAUDE.md``, …) are invisible to most human reviewers but
writable when a mandate lists them — I1 planted poison via an “allowed” memory write.

Acceptance:
- **Agent memory** paths require **both** ``scope.allow_agent_memory_writes`` in the signed
  mandate **and** the path in ``allowed_paths`` (`agent_memory_write_denied` otherwise).
  Path-only scope without the opt-in closes I1 smuggled memory capture; issue #15 sets both.
- **Repo instruction surfaces** are denied unless the signed mandate ``allowed_paths``
  explicitly lists that path (`instruction_surface_write_denied`).

**Shipped:** `evaluate_instruction_surface_write_policy` in `structural_invariants.py`;
`instruction_surface_writes` block on `devin-pr-gate.policy.json`.
Runtime: `instruction_surfaces.py` + `ProtectedZoneGovernor` + `build_protected_explicit_allow()`.

## CI / IDENTITY

### CI-1: CI prompt/context minimization (E7/E8) `[x]`

Problem: CI-side agent runs can be influenced by attacker-controlled PR/issue text without any workflow diff.

Acceptance:
- Define and enforce an allowlist of CI-visible context (no arbitrary PR comments by default).
- Emit a receipt field that enumerates which CI context sources were ingested.

**Shipped:** `ci_context.py` + gate `ci_context` receipt block; policy `ci_context.allowlist`;
`ci_context_violation` on disallowed sources.

### CI-2: Log/artifact/cache exfil guardrails (E8) `[x]`

Problem: secrets can leak via build logs, artifacts, or caches even when network egress is blocked.

Acceptance:
- Add redaction/deny rules for known secret formats before writing logs/artifacts.
- Treat artifact publication as a capability (authorize + receipt).

**Shipped:** `artifact_guard.py` — secret scan/redact on gate `test_runs` logs;
`annotate_artifact_publication` in policy engine + MCP post-execution; export verifier
`_artifact_publication_issues`.

### ID-1: Actor binding across steps (F7) `[x]`

Implemented in demo gate: fail closed when `github_actor_patterns` is set but `--github-actor` is missing (`agent_identity_missing`).

Problem: an attacker can swap identities across multi-step flows (push vs merge, bot vs human, delegate vs parent).

Acceptance:
- Bind the evaluated commit(s) to an authenticated actor identity (OIDC/SPIFFE) in the receipt.
- Require a non-empty actor identity (do not accept missing `github_actor`).
- Fail closed when actor identity changes mid-chain without explicit authorization.

**Shipped:** `actor_chain.py` — `actor_identity` receipt block, `evaluate_actor_binding`
(GitHub + optional OIDC subject), `actor_chain_break` across prior gate receipts;
`oidc_actor.py` — JWKS verification for GitHub Actions (and custom issuers) via
`--oidc-token` on the demo gate; `evaluate_pr_gate` uses the same binding path.
**2026-06-20:** default `devin-pr-gate.policy.json` unified with hardened profile
(protected invariants, trajectory, cross-session deny, bootstrap, etc.).

### Merge binding + runtime hardening (P0–P3) `[x]`

**Shipped (2026-06-29):**

| Module | Purpose |
|--------|---------|
| `merge_binding.py` | `evaluate_merge_eligibility`, stacked-base warning, `merge_policy` on gate JSON |
| `scripts/agentauth_merge_check.py` | CI exit-code contract: SHA match + hard-block on security flags |
| `governed_runtime.py` | `require_gateway` blocks ungoverned MCP tool calls |
| `hermetic_runner.py` | Shared egress sandbox + `PYTHONNOUSERSITE` hermetic test env |
| `context_fetch.py` | Gated external wiki/docs fetch with provenance surfaces |
| `session_token.py` | Short-lived session-bound credentials (+ optional DPoP JKT) |
| `gate_evaluate.py` | Gate CLI uses single `evaluate_pr_gate` path (P3 dedup) |

Example workflow: `examples/devin-agentauth-demo/gated/.github/workflows/agentauth-merge-check.yml`

### ID-2: Secret access as a capability (F6/F8) `[x]`

Problem: token/key theft is often runtime-only (reading `~/.ssh`, `gh` auth, cloud creds, MCP secrets).

Acceptance:
- Default-deny reads of common credential locations unless explicitly authorized.
- Record credential-access attempts (path + hash of bytes) in the receipt when allowed.

**Shipped:** `credential_access.py` — default-deny path patterns, `credential_access`
attestation on MCP authorization; export verifier `_credential_access_issues`.

## TOOLCHAIN / BOOTSTRAP

### RT-3: Repo bootstrap sandboxing (H3–H7) `[x]`

Problem: malicious repo bootstrap paths (submodules, toolchain shims, poisoned tests/build) can execute before or during validation.

Acceptance:
- Disable submodule recursion by default; require explicit authorization for `git submodule update --init --recursive`.
- Run builds/tests in a constrained sandbox (no network, minimal FS, no ambient creds).
- Emit a tool-time receipt of executed commands (argv + cwd + env allowlist + IO hashes).

**Shipped:** `bootstrap_sandbox.py` — recursive submodule deny, `command_execution`
attestation on gate `test_runs`; pairs with existing test egress isolation.

## GATE

### GATE-4: TOCTOU resistance (M3 / E9) `[x]`

Problem: the gate can evaluate one diff but a different merge commit can land (rebase, merge queue, branch drift).

Acceptance:
- Evaluate the exact merge commit (or server-side merge result) that will be merged.
- Bind receipt to a specific `head_sha` and fail closed if the merged SHA differs.

**Shipped:** `git.evaluated_head_sha` binding + `verify-merge` / `verify-receipt --merge-head`.
Harness: `scripts/evaluate_gate_toctou_binding.py`.

## RECEIPTS / CHAIN

### CHAIN-2: Cross-surface propagation tracing (L2–L4) `[x]`

Problem: payloads can replicate via PR comments/review, chat, docs, or shared retrieval indices; no single diff contains the attack.

Acceptance:
- Extend receipts with "context provenance" (which surfaces were read, hashed, and trusted).
- Provide verifier tooling that reconstructs a propagation graph from chained receipts.

**Shipped:** `context_provenance.py` — `context_provenance` + `provenance_graph_from_receipts()`
on gate receipts; untrusted-surface verification hook.

## MODEL

### MODEL-1: Weight/backdoor trigger observability (N1–N3) `[x]`

Problem: if the model itself is compromised (trigger-conditioned behavior), repo-based scanning is irrelevant.

Acceptance:
- Treat tool-time receipts as the source of truth (what was executed/read/sent), independent of model intent.
- Add canary tasks + anomaly detection to flag trigger-conditioned deltas in tool use.

**Shipped:** `model_canary.py` — `evaluate_canary_delta` wired into `SessionActionMonitor`
when policy `canary.enabled`.

