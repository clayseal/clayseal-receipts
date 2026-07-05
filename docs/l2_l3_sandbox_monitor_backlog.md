# L2/L3 dynamic sandbox + action monitoring backlog

Dynamic scope enforcement, per-session action monitoring, and suspiciousness signals
that enhance **L2** (capability containment) and **L3** (decision semantics).

Complements:

- [l3_l4_backlog.md](l3_l4_backlog.md) — L3/L4 receipt foundation (mostly `[x]`)
- [devin_gate_improvements_backlog.md](devin_gate_improvements_backlog.md) — Devin PR gate / runtime gaps
- [l1_l3l4_boundary.md](l1_l3l4_boundary.md) — L1/L2 → L3 authority binding
- README §3.1 — L2.5 behavioral anomaly (proposed)

**Last updated:** 2026-06-20

## Status markers

| Marker | Meaning |
|--------|---------|
| `[ ]` | Not started |
| `[>]` | **Being worked on** — do not pick up |
| `[~]` | Partial / in progress |
| `[x]` | Done |

**Coordination:** when you take an item, change it to `[>]` and add your track name
inline. Register the track in the parallel-tracks table. Mark `[x]` when done.

## Parallel tracks

| Track | Owner | Items |
|-------|-------|-------|
| **Session monitor core** | codex/sandbox-monitor | SM-1–SM-5 `[x]` |
| **L2 dynamic scope** | codex/sandbox-monitor | SM-6 `[x]`, SM-7 `[x]`, SM-15 |
| **Devin gate unification** | unassigned | SM-8, SM-11–SM-14 |
| **L2.5 ML anomaly** | unassigned | SM-9, SM-10, SM-16 `[x]` |
| **Runtime sandbox** | unassigned | SM-17–SM-20 (see also RT-* in Devin backlog) |

---

## Tier 1 — session monitor + L3 integration (done)

**Completed:** 2026-06-20 (codex/sandbox-monitor). See `agentauth/receipts/action_monitor.py`,
`Policy.monitoring`, `DecisionOutcome.ALLOW_WITH_REVIEW`.

### SM-1: Session action monitor + per-session history `[x]`

**Layer:** L3 runtime. **Effort:** S. **Owner:** codex/sandbox-monitor.

Goal: maintain a rolling action history per `session_id` and emit a structured
`MonitoringSignal` (score, flags, reasons) before each receipt is finalized.

Tasks:

- `SessionActionMonitor` in `agentauth/receipts/action_monitor.py`
- `MonitoredAction`, `MonitoringSignal` dataclasses
- Heuristic scorer: side-effect escalation, repeated high-risk tools, pattern breaks

Acceptance:

- two tool calls in one session increment `prior_action_count` on the authority snapshot
- monitor returns higher score when external side-effect follows read-only stretch

### SM-2: `allow_with_review` decision outcome `[x]`

**Layer:** L3. **Effort:** S. **Owner:** codex/sandbox-monitor.

Goal: first-class L3 vocabulary for graduated suspiciousness (Devin gate used a
bespoke receipt field; product enum should match).

Tasks:

- Add `DecisionOutcome.ALLOW_WITH_REVIEW`
- `DecisionResult.requires_review()` helper; `can_execute()` allows review outcomes
- Update [decision_model.md](decision_model.md)

Acceptance:

- receipts export `decision.outcome == allow_with_review`
- explain/verifier surfaces review-required decisions

### SM-3: Policy `monitoring` block + PolicyEngine hook `[x]`

**Layer:** L3. **Effort:** S. **Owner:** codex/sandbox-monitor.

Goal: committed policy controls monitoring thresholds and optional hard-block.

Policy shape:

```yaml
monitoring:
  enabled: true
  review_threshold: 0.5
  block_threshold: null   # optional; bounded_auto hard-deny above this
  sensitive_keywords: ["admin", "secret", "curl", "transfer"]
```

Tasks:

- Extend `Policy.from_dict` / `to_dict`
- `_monitoring_violations()` in `policy_engine.py` when signal attached to context

Acceptance:

- score ≥ `review_threshold` → `allow_with_review` when base policy satisfied
- score ≥ `block_threshold` (when set) → deny in `bounded_auto`

### SM-4: Wire monitor into `AgentWrapper.record()` `[x]`

**Layer:** L3. **Effort:** S. **Owner:** codex/sandbox-monitor.

Tasks:

- Optional `session_monitor` on `AgentWrapper` (default on when policy.monitoring.enabled)
- Attach `monitoring` block to execution `authorization` dict on each record
- Increment `authority.prior_action_count` from monitor state

Acceptance:

- MCP + wrapper tests show monotonic `prior_action_count`
- receipt bundle carries `authorization.monitoring` when enabled

### SM-5: Wire monitor into `ReceiptedMcpGateway` `[x]`

**Layer:** L3 + MCP. **Effort:** S. **Owner:** codex/sandbox-monitor.

Tasks:

- Accept optional `session_id` on gateway (stable per agent session)
- Pass through to `record()`; monitor observes each tool call

Acceptance:

- ATIF-style replay can set `session_id` and get consistent action indices
- bounded_auto + monitoring blocks when `block_threshold` exceeded (test)

---

## Tier 2 — L2 dynamic scope + unified enforcement

### SM-6: Mandate → `AuthorityContext.resource_scope` compiler `[x]`

**Layer:** L2 → L3. **Effort:** M. **Owner:** codex/sandbox-monitor.

Goal: signed human mandate / `human_authorization.v1` path globs compile into
`resource_scope` on the authority snapshot (one grant object, not parallel JSON).

Tasks:

- `compile_mandate_scope(mandate | authorization_envelope) -> list[str]` — `agentauth/receipts/task_scope.py`
- `AgentSession.wrap()` optional `task_mandate=` applies scope before first action
- `AgentWrapper(task_mandate=...)` + PolicyEngine file-path + denied-path checks

Acceptance:

- policy engine denies action when resource ref not in compiled scope
- Devin demo authorization templates round-trip through compiler

### SM-7: Biscuit path-pattern facts for dynamic L2 scope `[x]`

**Layer:** L2. **Effort:** L.

Goal: task-narrowed scope minted into attenuated Biscuit (not external JSON only).

Depends on: lift P1-7 constraint rejection once Datalog rules exist.

Tasks:

- Design `allowed_path("swe_triage/parser.py")` facts + authorizer rules
- `attenuate_biscuit(..., path_patterns=[...])` offline API

Acceptance:

- offline `authorize()` denies out-of-path file action
- tests mirror Devin gate path cases

**Shipped:** `agentauth/biscuit_scope.py` — `allowed_path` / `denied_path` facts on
attenuation; `authorize_biscuit(..., file_path=)` path gate; SDK + backend parity;
`attenuate_for_task_scope` on `AgentSession`.

### SM-8: Devin gate rules as `PolicyEngine` plugin `[x]`

**Layer:** L3. **Effort:** M. **Owner:** codex/sandbox-monitor.

Goal: `protected_invariants`, `build_integrity`, `instruction_hygiene` live in product
policy engine, not only `agentauth_gate.py`.

Tasks:

- `InvariantPolicyEngine` + `agentauth/receipts/structural_invariants.py`
- Share rule helpers between gate script and engine (gate imports product module)

Acceptance:

- `run_devin_pr_through_product.py` uses engine instead of `extra_violations` only

### SM-9: ATIF baseline anomaly scorer (L2.5 v0) `[x]`

**Layer:** L2.5. **Effort:** M. **Owner:** codex/sandbox-monitor.

Goal: isolation-forest (or frequency baseline) over ATIF trajectory features;
attach `anomaly_score` + `model_commitment` to monitoring signal.

Tasks:

- Feature extractor in `agentauth/receipts/action_features.py`
- Offline train script `scripts/train_anomaly_baseline.py`; load weights when
  `AGENT_RECEIPTS_ANOMALY_MODEL` set

Acceptance:

- benchmark report: score distribution on 38 ATIF trajectories
- injected trajectory (shuffle tools) scores higher than control

### SM-10: Policy-gated hard block on anomaly in `bounded_auto` `[x]`

**Layer:** L2.5 + L3. **Effort:** S. **Depends:** SM-3, SM-5.

Goal: configurable `monitoring.block_threshold` blocks tool execution (not just flags).

Status: MCP gateway + `AgentWrapper.run()` pre-check via `pre_execution_violations`
before handler / model execution.

Acceptance:

- red-team case: anomalous sequence blocked in bounded_auto with receipt deny

---

## Tier 3 — Devin / runtime / cross-session (from gate backlog)

These remain in [devin_gate_improvements_backlog.md](devin_gate_improvements_backlog.md);
listed here for L2/L3 roadmap visibility.

| ID | Devin backlog | SM alias | Status |
|----|---------------|----------|--------|
| SM-11 | GATE-1 audit suppression | — | `[x]` protected_invariants in product engine |
| SM-12 | GATE-2 semantic invariants (AST) | — | `[x]` |
| SM-13 | GATE-3 slow-drip / trajectory | — | `[x]` |
| SM-14 | GATE-4 TOCTOU merge SHA | — | `[x]` |
| SM-15 | ID-1 actor binding (full OIDC) | — | `[x]` gate + actor_chain (OIDC subject optional) |
| SM-16 | README §3.1 full L2.5 stream model | — | `[x]` |
| SM-17 | RT-1 egress as capability | — | `[x]` |
| SM-18 | RT-2 MCP tool pinning | — | `[x]` |
| SM-19 | RT-3 repo bootstrap sandbox | — | `[x]` bootstrap_sandbox + gate command attestation |
| SM-20 | CHAIN-1 cross-session attribution | — | `[x]` |
| SM-21 | CHAIN-2 context provenance graph | — | `[x]` |
| SM-22 | CI-1 CI prompt minimization | — | `[x]` |

### SM-11: Audit suppression via protected invariants `[x]`

Implemented in product `InvariantPolicyEngine` / `structural_invariants.py` (SM-8)
and Devin hardened policy.

### SM-19: Repo bootstrap sandboxing `[x]`

`bootstrap_sandbox.py` — submodule deny, command execution attestation on gate
`test_runs`; complements `evaluate_build_integrity` + test egress namespace.

---

## Tier 4 — standards + evidence

### SM-23: Monitoring signal on receipt export `[x]`

Embed `monitoring` under `evidence` / `authorization` in v2 bundles; verifier
cross-checks score against committed policy thresholds.

**Shipped:** `evidence_block_from_run()` embeds `monitoring`; `export.verify_receipt_bundle`
runs `_monitoring_evidence_issues()` against policy commitment thresholds.

### SM-24: WIMSE / txn-token scope envelope (SOTA-15) `[x]`

Standard wire format for dynamic scope grants; see [sota_backlog.md](sota_backlog.md).

### SM-16: README §3.1 L2.5 stream model `[x]`

`stream_model.py` — per-action `stream_features` on `MonitoringSignal` (scope
alignment, sequence position, inter-action timing, feature vector commitment).

### SM-25: EZKL proof of anomaly score (README §3.1 verifiability) `[x]`

`anomaly_proof.py` — recomputable `anomaly_proof` on monitoring signal with
`model_commitment` + feature vector; export verifier `_anomaly_proof_issues`;
optional stub EZKL envelope when CLI available.

---

## Suggested implementation order

1. SM-1 → SM-5 (session monitor wired end-to-end) **← current sprint**
2. SM-6 (mandate compiler) + SM-8 (gate plugin)
3. SM-9 → SM-10 (ML baseline)
4. SM-7 + SM-24 (L2 token scope + standards)
5. RT-* / CHAIN-* via Devin backlog

## Definition of done (sandbox + monitor MVP)

- Every MCP tool call in a session updates action history and `prior_action_count`
- Policy can escalate to `allow_with_review` without bespoke gate JSON
- Monitoring signal appears on receipts and audit authorization context
- Devin gate anomaly flag migrates to same `MonitoringSignal` shape (SM-8 follow-on)
