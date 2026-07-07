# Clay Seal Receipts

<img src="docs/assets/clay-seal-logo.png" alt="Clay Seal logo" width="420">

Clay Seal Receipts is currently published as `agentauth-receipts` under the
`agentauth.receipts` Python namespace for compatibility.

Cryptographic receipts for autonomous AI agents: prove that a consequential action was **authorized**, ran on the **claimed model**, and satisfied a **committed policy**.

OAuth 2.1 and MCP answer *who may act*. Agent Cards are self-declared. Clay Seal Receipts answer *what actually happened* with a verifiable `ExecutionProof`, a lower-layer decision model, and a tamper-evident audit chain.

---

# Clay Seal for autonomous coding agents (Cognition / Devin)

An autonomous software engineer like Devin acts directly on enterprise codebases: it reads repositories, issues, and PRs; runs commands; pushes commits; and spawns sub-agents. The thing standing between Devin and broad enterprise adoption is **trust** — can you prove what Devin did, prove it stayed inside the scope a human authorized, and be sure the record itself can't be forged? Clay Seal is the identity-and-verifiable-execution layer that answers those questions cryptographically. It turns Devin's output from *"commits your security team has to review"* into *"output guaranteed to have stayed within authorized scope, with machine-verifiable proof."*

This section has three parts: **Section 1** ranks what we have today by fit to Cognition's problems and summarizes the Cognition-tailored features we propose to build; **Section 2** describes the current capabilities in depth; **Section 3** is the technical implementation plan for the proposed features.

> **Honesty line.** Everything under "Built today" is implemented and, where noted, empirically validated. Everything under "Proposed" is roadmap — designed but not yet built. We mark the boundary explicitly because a verification company that overstates its own guarantees has already failed its one job.

## Section 1 — Ranked fit for Cognition

### Built today (ranked by fit to Cognition's enterprise-trust blockers)

1. **Goal-bound dynamic sandbox (runtime containment).** `build_sandboxed_gateway()` mints a capability lease from a signed task manda

## Three-layer install

This repo is layer 3 (receipts + verification). It depends on:

- [agentauth-identity](https://github.com/pberlizov/agentauth-identity)
- [agentauth-capabilities](https://github.com/pberlizov/agentauth-capabilities)

```bash
pip install -e ".[dev]"
python demo/poisoned_mcp_demo.py
arctl doctor
```

Developer guide: [docs/DEV_GUIDE.md](docs/DEV_GUIDE.md)
