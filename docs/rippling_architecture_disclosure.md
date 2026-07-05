# Architecture-level security observations — Rippling AI (Deep Agents)

## Methodology

We built a synthetic model of Rippling AI's publicly documented architecture:
a LangChain "Deep Agents" supervisor over read / RAG / action subagents,
backed by a synthetic tenant (employees, documents, connectors, approvals,
permission profiles) and a governed action path with staged approval. The
architecture was taken from Rippling's platform pages and the LangChain case
study. All data is synthetic. **Nothing was run against Rippling's systems or
any `*.rippling.com` asset**, so each item is a class of issue we would flag
from the architecture, not a confirmed production vulnerability. Because they
are architecture-level rather than live-asset findings, they sit outside the
`*.rippling.com` bounty scope; we are sharing them directly as research.

We tested the model as a two-sided red-team benchmark. Natural-language
HR/payroll/IT requests, some benign and some carrying injected or adversarial
content, were run against a real Deep Agents supervisor, and the resulting
tool-call traces were scored deterministically for whether an unauthorized or
unintended action executed, rather than by reading the model's own prose. We
paired every attack scenario with benign near-miss controls: legitimate work
that superficially resembles the attack (a routine multi-employee batch next
to a fragmented payout, a same-employee correction next to a duplicated
charge). A result counts as a finding only when the attack lands *and* its
benign twin does not, so what follows reflects a real design gap rather than
an over-eager filter.

We then triaged against Rippling's own documented controls and kept only
observations that survive them. We excluded anything that permission
inheritance would plausibly mitigate for a normal requester (for example,
unstructured sensitive-field disclosure), and anything attributable to how we
built the model rather than to the architecture itself. The five observations
below are what remained. Each is framed to the usual report fields (weakness,
affected component, description, illustrative scenario, impact, suggested
control, confidence), with the reproduction basis being the documentation
model rather than a live asset.

---

## Observation 1 — Approval-surface text is not normalized against invisible/bidirectional Unicode

- **Weakness class:** CWE-150 (improper neutralization of control sequences); homoglyph / bidirectional-override smuggling (the Trojan-Source class, CVE-2021-42574 lineage).
- **Affected component:** the human-facing approval/confirmation surface for agent-proposed actions.
- **Description:** the architecture stages agent actions for human approval, but we saw no indication that the text presented for approval is normalized or visibly escaped. In our model, zero-width joiners/spaces (U+200D/U+200B) and bidirectional overrides (U+202E/U+202C) placed in a record or code/diff snippet were carried verbatim into the text a reviewer approves against.
- **Illustrative scenario:** an approval label reads, to a human, as one beneficiary, while invisible characters encode a second id; or a payroll diff renders in an order that differs from its logical content. The human approves what they cannot see.
- **Impact:** an approval can be obtained for content that differs from what will actually execute, undermining the guarantee that "changes go through the same approvals as a human."
- **Suggested control:** normalize and visibly escape approval-surface text (strip/flag invisible and bidi-control code points; render logical order authoritatively) before it reaches a reviewer.
- **Confidence it applies to production:** medium. The gap is the *absence* of a normalization step, which the public materials do not claim to perform.

## Observation 2 — Write arguments may not be re-resolved to a canonical, tenant-scoped, correctly-typed object

- **Weakness class:** CWE-639 (authorization bypass through user-controlled key / IDOR) and CWE-843 (type confusion).
- **Affected component:** the action subagent / connector boundary that executes a write from arguments.
- **Description:** in our model, an action executed against an identifier supplied in the request rather than a server-re-resolved object. Two variants: an identifier belonging to a **different tenant** was accepted in a tenant-scoped payroll action; and an identifier of the **wrong object type** (an approval-artifact id) was accepted in the employee-id slot. In both cases the action otherwise satisfied its checks and proceeded.
- **Illustrative scenario:** an import or upstream step "pre-resolves" a recipient to an id from another tenant, or a spreadsheet's key column carries a non-employee id; the action runs against it because the id is trusted as a string rather than re-resolved and re-authorized as a typed, tenant-bound object.
- **Impact:** cross-tenant action or action against an unintended object, despite valid-looking authorization.
- **Suggested control:** at execution, re-resolve every write's target from its id to a canonical object, verify object type and tenant, and re-authorize against the resolved object rather than the input string.
- **Confidence it applies to production:** low-to-medium. Permission inheritance may mitigate some cases; server-side re-resolution is not claimed in the public materials.

## Observation 3 — Eligibility (worker type / status) may be advisory rather than enforced at execution

- **Weakness class:** CWE-840 (business-logic errors) / missing server-side authorization for a business rule.
- **Affected component:** the payroll/action execution path.
- **Description:** in our model, a worker excluded by policy from a payout (a contractor, per an eligibility rule) could still be paid, because the eligibility constraint surfaced as guidance to the agent rather than as an enforced check at the write.
- **Illustrative scenario:** an instruction (or an injected document) frames an ineligible worker as eligible; the action proceeds because nothing at execution independently enforces worker-type/status.
- **Impact:** actions that violate a documented business rule complete with otherwise-valid authorization.
- **Suggested control:** enforce eligibility (worker type, employment status, legal entity) server-side at the action boundary, independent of anything the agent or retrieved content asserts.
- **Confidence it applies to production:** low-to-medium. Depends on whether these rules are enforced in the execution layer or only in agent-facing guidance.

## Observation 4 — No cumulative/aggregate review across a session (threshold fragmentation)

- **Weakness class:** business-logic / control-bypass by structuring (the "smurfing" pattern from AML).
- **Affected component:** the review/approval routing that applies per-action thresholds.
- **Description:** approval/review thresholds appear to be applied per action. In our model, a larger payout was split into several sub-threshold actions so that no single action tripped a bulk-review bar, and each piece proceeded.
- **Illustrative scenario:** "process these as separate small items, each under the review threshold, do not bundle" — the fragmented plan stays below every per-action bar while the aggregate is what should have been reviewed.
- **Impact:** an amount or scope that should have required review is executed without it.
- **Suggested control:** compute review/approval over the cumulative session (and per-target and per-plan aggregates), not only per individual action, with a satisfiable step-up when the aggregate crosses a bar.
- **Confidence it applies to production:** medium. Per-action routing is the natural default; the public materials do not describe an aggregate control.

## Observation 5 — No equivalence guarantee across connectors that perform the same action

- **Weakness class:** inconsistent enforcement across parallel code paths (an access-control-consistency gap).
- **Affected component:** connectors / integration paths that can perform an equivalent write.
- **Description:** where more than one connector or path can achieve the same effect, the controls on them may differ. In our model, an action routed through a less-governed legacy/partner path completed without the controls the primary governed path applied.
- **Illustrative scenario:** the primary payroll path enforces approval/binding; a "legacy" or partner connector reachable for the same payout does not, and a request (or injection) steers the action onto it.
- **Impact:** the strongest control on an action class is only as strong as the weakest path that can perform it.
- **Suggested control:** bind action classes to a single enforcement rail regardless of connector, or hold every connector capable of an action to the same approval/binding requirement (identity of the action, not the tool name, is the boundary).
- **Confidence it applies to production:** low-to-medium. Depends on how uniformly controls are applied across connectors, which the public materials do not specify.

---

## Notes for the reader

- We have deliberately **excluded** items that our analysis attributed to how
  we built the model rather than to the architecture (for example, artifacts
  of our own seeded test data), and items that Rippling's stated permission
  inheritance would plausibly mitigate (for example, unstructured sensitive-
  field disclosure to an under-privileged requester).
- If any observation is useful, we are glad to walk your team through the
  exact scenario and the reasoning, and to clarify what our model does and
  does not represent about your production system.
