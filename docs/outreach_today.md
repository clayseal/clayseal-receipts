# Outreach playbook — today

Rippling landed. Use that momentum today in three waves: **close Rippling**, **warm network**, **cold peer targets**. Goal: 8–12 meaningful touches, not 50 spray-and-pray emails.

---

## Proof blocks (reuse everywhere)

Pick one wedge, then one proof line:

| Wedge | One-liner | Proof |
|-------|-----------|-------|
| **HR / payroll / IT agents** | Human approval isn’t enough when the approved payload isn’t what executes. | Synthetic Rippling Deep Agents benchmark: 79 live scenarios, 6 confirmed binding gaps (Unicode smuggling, plan chunking, connector equivalence, chat-as-authorization). Head of Security wants a research collaboration. |
| **Coding agents** | Enterprises won’t grant write access until execution is provably in-scope. | Live Devin red-team: poisoned issues tricked the agent; Clay Seal PR gate denied before merge. ~284k tamper trials, ~0% false-accept vs 67–100% for logging-only baselines. |
| **Platform security** | OAuth/MCP answer who may act; nothing answers what actually happened, cryptographically. | Pre-action capability tokens + hash-chained SCITT/C2SP receipts; open standard for identity/delegation, commercial evidence plane. |

**Ask (pick one per email):** 20-min call · design-partner pilot · joint benchmark on their public architecture · intro to their agent/platform security lead.

**Do not claim:** production pentest of Rippling, named customer deployment, or features marked “Proposed” in README.

---

## Wave 1 — Do first (30 min)

### ☐ Rippling follow-up (send within 24h of call)

**To:** [your contact + anyone they offered to loop in]  
**Subject:** Rippling × Clay Seal — research collaboration next steps

```
Hi [Name],

Thank you again for yesterday — really appreciated the peer-level conversation and your openness on where binding breaks today (approval UI vs execution payload, connector equivalence, session aggregates).

As discussed, I'd love to move forward on a bounded research collaboration. Proposed shape:

1. **Joint eval design (2 weeks)** — We bring the live benchmark harness + scoring; you pick 1–2 production seams to validate (e.g. approval preview binding, single payroll rail across connectors, or Spend/leave-status rules). Synthetic fixture first; your staging only if/when you're comfortable.

2. **Deliverable** — Short joint artifact: what reproduced, what didn't, and a concrete pilot scope for scoped capability tokens + continuous monitoring on one write path.

3. **Commercial path** — Research phase → paid pilot → license, with clear success criteria so we're not drifting into unpaid consulting.

Happy to send a one-page SOW draft or jump on a 30-min working session with [eng/security names] this week.

Best,
[You]
```

### ☐ Ask Rippling for 2 intros (same thread or separate)

```
Two asks if you're open to it:
- Intro to whoever owns Rippling AI agent security / action-agent enforcement on your side
- A second conversation once we've drafted joint success criteria — happy to include LangSmith/eval folks if useful
```

---

## Wave 2 — Warm network (60 min, target 4–6)

People who already trust you: ex-colleagues, investors, security friends, LangChain/YC network, anyone who said "you should talk to X about agents."

**Subject:** Quick intro? Agent security benchmark + Rippling research collab

```
Hi [Name],

Quick update: we built a live red-team harness for agent write paths (commit tokens, MCP gateways, tamper-evident receipts) and ran it against a Rippling-shaped Deep Agents fixture from their public architecture. Their Head of Security wants to explore a research collaboration — the gaps we found are binding/equivalence issues, not raw RBAC bypass.

I'm doing outreach today to teams shipping privileged agents (HR/payroll, IT, coding, finance). Do you know anyone owning agent security or platform identity at [company they might know] who'd take a 20-min peer benchmark conversation?

Happy to share the deck or a one-pager — no vendor pitch, just "here's what broke in our fixture and how we'd validate it together."

Thanks,
[You]
```

**Prioritize intros to:** agent platform security leads, not generic "AI" PMs.

---

## Wave 3 — Cold / semi-warm (90 min, target 5–8)

### Tier A — Same shape as Rippling (agent-native, privileged writes)

| Company | Why | Who to find |
|---------|-----|-------------|
| **LangChain** | Built Rippling's stack; care about eval + production agents | Platform / LangSmith security or solutions |
| **Gusto / Deel / Remote** | Payroll + HR agents, high blast radius | Head of Security, platform eng |
| **Ramp / Brex** | Spend + cards + agents | Security / fintech risk |
| **ServiceNow** | Workflow agents at enterprise scale | AI platform security |
| **Workday** | HR agent narrative | Security architecture |
| **Cognition** | Devin = canonical coding-agent wedge | Security / enterprise trust (if not already active) |

### Tier B — Security buyers who feel agent pain

| Persona | Hook |
|---------|------|
| **CISO / VP Security** at Series C+ with internal AI agents | "Reduce per-action approval load without increasing blast radius" |
| **Head of Platform Security / IAM** | "Third option between full standing permission and human-on-every-write" |
| **Red team / offensive security** | "We'll run our harness on your public agent architecture — you keep all findings" |

### Cold email — HR/payroll agent wedge

**Subject:** Peer benchmark on agent write binding (Rippling-shaped fixture)

```
Hi [Name],

I'm [You] — building Clay Seal: scoped capability tokens + tamper-evident receipts at the MCP/tool boundary (pre-action enforcement, not post-hoc logging).

We modeled a Deep Agents fixture from public materials (supervisor + read/RAG/action subagents, staged approvals) and ran 79 live scenarios against gpt-5.4-mini. Interesting breaks weren't permission bypass — they were binding gaps: Unicode in approval surfaces, session aggregate limits, legacy connector equivalence, chat text treated as authorization.

Rippling's security team is exploring a research collaboration on validating these seams in staging. I'm looking for 2–3 other teams shipping privileged HR/IT/finance agents who want the same peer exercise — synthetic first, your environment only if useful.

Worth 20 minutes this week or next?

[You]
[link to agentauth_onepager or GitHub]
```

### Cold email — coding agent wedge (Cognition-style)

**Subject:** Devin red-team → cryptographic PR gate (design partner)

```
Hi [Name],

Clay Seal sits between an autonomous coding agent and its tools: attested identity, capability leases per task, signed commit tokens bound to exact tool args, hash-chained receipts.

On our Devin-shaped benchmark, poisoned issues tricked live runs; the Clay Seal gate denied before merge. Separate soundness work: ~284k adversarial tamper trials, ~0% false-accept vs 67–100% for logging/signed-receipt baselines.

Looking for one design partner to pilot on a single high-risk path (PR merge, cloud admin, or ticket approval). 20-min call to see if the wedge matches your enterprise blockers?

[You]
```

### LinkedIn DM (short)

```
Hi [Name] — built a live agent write-path benchmark (Rippling Deep Agents + Devin fixtures) and Rippling security wants a research collab. Looking for peers shipping privileged agents who'd do a 20-min peer review — not a sales pitch. Open to a quick chat?
```

---

## Today's checklist

| # | Action | Target |
|---|--------|--------|
| 1 | Send Rippling follow-up | Within 24h of meeting |
| 2 | Warm intro asks | 4–6 people |
| 3 | Tier A cold/semi-warm | 5 emails |
| 4 | LinkedIn | 5 connection requests + DM |
| 5 | Update Rippling deck link | Host or attach PDF if sending externally |
| 6 | Calendar | Block 2h for replies |

**Track in a sheet:** Name · Company · Wedge · Sent · Reply · Next step

---

## Rippling as social proof (use carefully)

**OK:** "After a peer benchmark conversation, Rippling security is exploring a research collaboration."  
**Not OK:** "Rippling is buying" / "we found bugs in production" / naming individuals without permission.

---

## Attachments (pick one)

- `docs/rippling_meeting_deck.html` (open in browser → print to PDF)
- `docs/agentauth_onepager.md` (or PDF if you have one)
- `README.md` soundness + Devin sections for technical readers

---

## If they reply "tell me more"

30-second verbal:

> We enforce at the tool boundary: the agent gets a signed token scoped to exactly one tool call — args, tenant, expiry — and every decision lands in a tamper-evident receipt chain. Rippling's model inherits full user permissions and humans approve each write; our benchmark shows the approval often isn't bound to what executes. We're not replacing IAM — we're the evidence and binding layer so you can safely reduce manual approval load.

Offer: 20-min screen share of one tricked trace + one partial trace from the deck.
