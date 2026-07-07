# Clay Seal — Architecture Overview

*Prepared for Rippling · verifiable enforcement for agent tool calls*

---

## 1. What Clay Seal is

Clay Seal is one system for agent **identity** and verifiable **execution**. It
wraps an agent's tool calls, makes a policy decision *before* each
side-effecting action, and binds that decision into a tamper-evident,
cryptographically verifiable receipt. It is designed to sit exactly where
Rippling AI already operates: a supervisor over read / RAG / action subagents,
issuing writes through connectors, under staged human approval.

The thesis, in one line: **authorization that is bound to what actually
executes, and provable after the fact.** Not "the model was told the rules"
(promptware), and not "a human clicked approve on a summary" (which binds a
preview, not the payload) — but a cryptographic binding between the authorized
action and the executed one, plus an append-only record you can verify without
trusting us.

Two layers, joined by one seam:

- **Identity (L1/L2).** Agents are *attested, not declared*: a workload
  presents a signed attestation document, selectors are derived from verified
  evidence, and the matching registration — not the caller — dictates the
  agent's type and scopes. The result is a short-lived, verifiable credential
  (JWT-SVID / SPIFFE) with optional proof-of-possession capability tokens.
- **Receipts (L3/L4).** Every wrapped action runs through a policy decision and
  is recorded in a hash-chained audit log, exportable as a standards-based
  transparency receipt.

The seam (`authority_binding.py`) normalizes the attested identity into the
authority context the runtime enforces against — so **every decision is bound
to a verified identity**, its tenant, and its capabilities, never to a
self-asserted one.

---

## 2. Why this shape (grounded in where Rippling's own controls end)

Rippling's public architecture already provides two real layers: permission
inheritance (the AI is scoped to the requesting human's permissions) and
staged human approval ("changes go through whatever approvals your company
requires, the same as if a human made them"). Those are genuine and valuable.
The gap they do not close — by construction — is the space *between* "authorized
in principle" and "bound to what executes":

- A human approves a rendered preview; nothing cryptographically ties that
  preview to the exact payload that runs (TOCTOU).
- Permission inheritance answers *who may act*, not *is this specific action,
  with these exact arguments, the one that was authorized*.
- Neither addresses **aggregate** behavior: a task fragmented across many
  individually-authorized calls to evade a review threshold; the same action
  routed through a less-governed connector; a value moved in excess of the
  requester's real authority.

Clay Seal's controls are designed precisely for that space, and to **compose
with** Rippling's existing layers rather than replace them.

---

## 3. The control model (what actually runs on a tool call)

Every side-effecting tool call passes through a pre-execution decision. The
controls below are the ones that execute; each is independent and composable,
and each contributes to a single allow / step-up / deny outcome that is then
recorded.

**a. Structural policy.** Allowed-tool, numeric-range, and output-schema
checks. The floor.

**b. Commit-token binding (the core primitive).** Before a governed write, the
control plane issues a signed, single-use token bound to the exact tool name,
arguments hash, tenant, authority, and query. The gateway verifies it at the
execution boundary and rejects any mismatch. This is what makes approval
*non-repudiable and payload-exact*: if the agent gets approval for one payload
and then executes a different one — a rounded amount, an extra beneficiary, a
substituted id — the binding fails. Tokens are single-use, closing replay.

**c. Capability leases (goal-scoped least authority).** At query start, from
the *original* request (captured before any retrieved content can bias it), the
runtime derives which tools and which target entities are expected for this
task, and confines the session to them. A write to a tool or entity outside the
lease is refused even with a valid token. This is what catches
connector-substitution (an ungated "legacy" path used in place of the governed
one) and injection that steers an in-scope action at an out-of-scope target.

**d. Cumulative value budget (inherit a budget, not just a yes/no).** The
runtime sums the actual quantity moved (dollars, headcount) across the whole
session against a ceiling that is **a property of the requesting human's own
authority** — the same inheritance principle Rippling already applies to
capabilities, extended to magnitude. It is tool-agnostic: the governed tool and
any legacy connector debit the *same* budget, so the ceiling cannot be evaded
by switching tools. This is what catches aggregate over-authority payouts that
each look individually fine.

**e. Effect supersession (idempotency, done safely).** A correction that
reissues the same logical action under a shared idempotency key *replaces*
rather than *adds*, so legitimate same-session corrections are not mistaken for
accumulation. This is safe against a dishonest agent by construction: a replace
can only ever *reduce* a total, never inflate it.

**f. Session behavior signal.** A per-session monitor scores each action for
suspiciousness (side-effect escalation after a read-only stretch, repetition,
off-task references) and attaches the signal to the receipt as evidence.

**Every one of these decisions is appended to a hash-chained audit log** — so
the enforcement record is itself tamper-evident, not just the individual
receipts.

A note on honesty, because it matters for an architecture review: controls
(c)–(e) are **session-scoped** today (per query), and (b)'s single-use ledger
is in-process. Cross-session durability — reading enforcement state back from
the (already durable) audit chain — is on the roadmap in §5, not claimed as
present.

---

## 4. Verifiable receipts — and why the timing is right

Each decision can be exported as a receipt carrying the policy decision, the
authority binding, and a Merkle **inclusion proof** (RFC 6962) against the
append-only log, with consistency proofs and witness quorum for the log itself.
Receipts are issued as **IETF SCITT** signed statements in **C2SP** checkpoint
format — meaning a third party (an auditor, a customer's compliance team,
Rippling itself) can verify *what an agent did and that it was authorized*
without trusting Clay Seal's word for it.

This is not a bespoke format. As of 2026 the IETF is actively standardizing
exactly this surface — **SCITT** and its reference APIs (SCRAPI), **Agent
Enforcement Receipts**, and the **Verifiable AI Provenance** framework for
high-risk AI decision trails. Clay Seal already emits what those drafts are
defining. The differentiator versus the attestation-only entrants in this space
is that Clay Seal's receipts record an **enforced decision**, not merely an
observation — prevention plus proof, not proof alone.

---

## 5. Roadmap: one decision point

The honest architectural assessment — and the thing we would prioritize for a
production integration — is consolidation. Today the controls in §3 are
individually sound but are evaluated at several points along the call path. The
roadmap is to route all of them through a **single Policy Decision Point
(PDP)**: one evaluator that takes principal, tool, arguments, and context, runs
the declared controls in one explicit order, and returns one typed decision
(`allow` / `step_up` / `deny` / `reserve`) with reasons. The gateway becomes a
thin enforcement point (PEP).

This is the decades-proven PDP/PEP separation from access control, which the
agent ecosystem is now re-adopting; we would shape the interface after
**AuthZEN** (the OpenID PEP↔PDP standard) — the same "align to the emerging
standard" discipline our receipts already follow with SCITT. Three concrete
wins:

- **Legibility and auditability.** A single place computes "the decision," so
  what runs in production is answerable by reading one contract, not tracing a
  call path — and that decision object is exactly what gets SCITT-receipted.
- **Defense in depth.** A standard PEP↔PDP interface lets a *downstream*
  service (a payroll connector, a Rippling backend) run its own PEP against the
  same decision, so a compromised agent runtime cannot self-authorize.
- **Signals become enforcement.** The behavior signal in §3(f) feeds the same
  decision as a step-up escalation, rather than being recorded and ignored.

Alongside it: promote the session-scoped ledgers (§3) to read/write the durable
audit chain for cross-session enforcement, and prune the enforcement surface to
a single documented golden path.

---

## 6. How this maps onto Rippling

- **Permission inheritance → budget inheritance.** The value budget (§3d) is a
  direct, natural extension of the model Rippling already runs — the agent
  inherits not just *what* it may do but *how much* it may move, from the same
  requester authority.
- **Staged approval → payload-bound approval.** The commit token (§3b) makes
  the approval Rippling already stages non-repudiable and exact: what the human
  approved is provably what executes.
- **Connectors → one approval rail.** The lease + shared value budget (§3c/d)
  make a legacy or partner connector carry the same guarantee as the primary
  path, closing the "less-governed side door" without new per-connector work.
- **MCP-native.** The enforcement point wraps MCP tool calls directly; the PDP
  roadmap (§5) aligns with the MCP ecosystem's own recognized need for a
  unified decision point.

The result Clay Seal is aimed at: **loosen the human-in-the-loop-per-action
constraint where the binding underneath can now be trusted** — fewer manual
approvals on what is verifiably in-scope and in-budget, concentrated human
attention on what is genuinely novel or over-threshold, and a verifiable
receipt for every action either way.

---

*This document describes the architecture as built and the near-term roadmap.
Every control in §3 is exercised against a red-team benchmark (attack coverage)
and a paired false-positive benchmark (legitimate work must not be blocked);
we are glad to walk through either.*
