# Open Standard Strategy

This document captures the product thesis behind Agent Receipts and a concrete path for defining an open standard for agent IAM and execution evidence.

## Executive summary

The company should not try to replace enterprise IAM. It should define a narrow open standard for **agent identity, delegation, capability grants, and action receipts**, then commercialize the **evidence plane** on top of that standard.

The open layer should make it easy for any agent, gateway, or control plane to express:

- who the agent is
- under whose authority it is acting
- what scope it has
- which action it attempted
- what evidence exists after execution

The paid layer should help customers answer:

- was the action allowed
- was it actually executed
- can we prove that to security, audit, or regulators
- can we correlate this across systems and detect abuse

## Product thesis

The market does not need another full-stack identity provider for agents. It needs a trustworthy way to bind agent actions to authority, policy, and evidence.

The strongest positioning is:

- **Open standard** for agent identity and delegated authorization
- **Open receipt schema** for post-execution evidence
- **Commercial evidence plane** for verification, analytics, policy enforcement, anomaly detection, forensics, and compliance

This avoids a head-on fight with Okta, Microsoft, Ping, Auth0, or cloud IAM while still letting the product sit in a high-value control point.

## Why this split works

An open identity standard increases adoption because buyers do not want vendor lock-in at the trust layer. A commercial evidence plane is still defensible because the pain is not in issuing an identifier. The pain is in answering what happened, whether it was allowed, and whether the answer will survive adversarial review.

This creates a clean division:

- The standard is the grammar.
- The product is the system of record, reasoning, and proof.

## Ideal wedge

Start with **privileged agent actions** rather than generic chat agents.

Best first workflows:

- code changes and CI/CD actions
- cloud administration and infrastructure changes
- ticket approval and workflow automation
- sensitive data access
- money-moving or high-risk tool calls

These workflows have three useful properties:

- the blast radius is high enough that security teams care
- the action surface is structured enough to model
- the evidence burden is high enough that customers will pay

## Buyer and user map

Primary buyer:

- CISO
- VP Security
- Head of Security Engineering
- Platform Security
- Identity or Zero Trust leader

Primary day-to-day user:

- security engineer
- platform engineer
- IAM architect
- internal audit or GRC partner

Economic message:

- reduce ungoverned agent privilege
- produce audit-grade evidence for agent actions
- shorten incident response and postmortem time
- support compliance without blocking agent adoption

## What should be open

The open standard should stay narrow and composable.

Standardize:

- agent identity document
- authority and delegation chain format
- capability and scope model
- action receipt schema
- attestation extension points
- trust metadata and discovery

Do not standardize:

- billing
- hosted policy authoring UX
- analytics
- alerting workflows
- compliance dashboards
- managed verification service internals

## Boundary between the standard and the implementer

The standard should not try to describe every internal detail of agent design.

Agent builders should retain freedom over:

- planning structure
- prompt construction
- memory layout
- model routing
- retry heuristics
- internal helper or subagent structure when it has no independent authority

The standard should become relevant when an execution unit crosses a trust boundary.

That means the standard should care about:

- who holds authority
- who can delegate authority
- what capability or budget is attached
- what approvals or obligations apply
- what externally meaningful action was attempted
- what evidence or receipt was produced

### Authority-bearing actors

Not every helper process or internal subagent needs to appear in the standard.

An internal component should become visible to the standard only when it is an **authority-bearing actor**. A practical threshold is when it has one or more of:

- its own delegated credential
- its own tool access scope
- its own resource or spend budget
- its own approval requirement
- its own independently useful receipt

This preserves implementer freedom while still covering the meaningful security boundary.

### Recommended rule

- Internal execution structure is the implementer’s prerogative.
- Authority-bearing actors are the standard’s concern.

This distinction is important because it keeps the spec narrow enough to gain adoption while still covering the actions and transitions that matter for security and audit.

## Relationship to existing standards

The standard should be a profile that sits on top of existing protocols where possible.

Use existing standards instead of reinventing them:

- **OAuth 2.1** for delegated authorization
- **RFC 9728** protected resource metadata for discovery
- **RFC 8414** authorization server metadata
- **DPoP** for sender-constrained tokens where appropriate
- **SPIFFE/SVID** for workload identity in infrastructure-heavy environments
- **OIDC / OID4VP** where verifiable identity assertions are needed
- **MCP** and **A2A** as transport and interoperability targets, not identity roots

The open standard should be able to say: "Here is how agents use these building blocks consistently."

## Design principles

1. **Layer, do not replace**
The standard should extend existing IAM and workload identity systems, not compete with them.

2. **Evidence after execution matters as much as authorization before execution**
Pre-execution auth answers "may this agent act?" Post-execution evidence answers "what actually happened?"

3. **Authority must be explicit**
Every action should be attributable to an agent, an operator, and a delegation chain.

4. **Capabilities must be concrete**
Scopes should describe actions and resources, not vague role names.

5. **Proof of possession should be first-class**
Bearer semantics alone are too weak for high-risk agent actions.

6. **Attestation is optional but pluggable**
The standard should support plain signed receipts, workload attestation, TEE attestations, and ZK-backed proofs without requiring all deployments to adopt the strongest mode immediately.

7. **Forensics matter**
Every standardized object should be designed so it can be retained, re-verified, and correlated later.

8. **Do not standardize internal cognition**
The standard should govern authority, action, and evidence boundaries, not internal reasoning architecture.

## Non-goals

The first version of the standard should not attempt to solve:

- semantic truthfulness of arbitrary LLM text
- universal personhood or legal identity for agents
- a new general-purpose PKI for the whole Internet
- a blockchain-based trust registry
- real-time cross-vendor policy semantics for every possible tool

## Proposed standard layers

### Layer 0: Existing trust rails

This layer is inherited from existing systems:

- OAuth authorization servers
- cloud IAM
- enterprise IdPs
- SPIFFE or mTLS environments
- MCP and A2A transports

### Layer 1: Agent identity profile

Define a standard **Agent Identity Document** that expresses stable claims about an agent deployment.

Suggested fields:

- `agent_id`
- `issuer`
- `subject`
- `organization`
- `display_name`
- `software_artifact`
- `model_provenance_ref`
- `supported_transports`
- `verification_methods`
- `trust_tier`
- `created_at`
- `expires_at`

This document should describe the agent deployment, not every individual execution.

### Layer 2: Delegation and capability grants

Define an **Agent Delegation Grant** that expresses who empowered the agent to do what.

Suggested fields:

- `grant_id`
- `issuer`
- `parent_grant_id`
- `actor`
- `delegator`
- `delegate`
- `allowed_actions`
- `allowed_resources`
- `constraints`
- `issued_at`
- `expires_at`
- `proof_of_possession_key`

Constraints should support:

- resource filters
- time bounds
- transaction limits
- environment restrictions
- required approval context

This layer is the heart of agent IAM. It must be easy to validate and hard to misinterpret.

The grant may apply to a top-level agent or to an authority-bearing subagent. The standard does not need to care how many internal helpers exist. It only needs to care when authority is split, attenuated, transferred, or consumed.

### Layer 3: Action receipt

Define an **Action Receipt** as the canonical post-execution artifact.

Suggested fields:

- `receipt_id`
- `request_id`
- `timestamp`
- `agent_id`
- `grant_id`
- `action`
- `resource`
- `input_commitment`
- `output_commitment`
- `policy_ref`
- `policy_result`
- `attestation_refs`
- `signatures`
- `previous_receipt_hash`

This object should be valid even when ZK is absent. In the weakest mode it is a signed, tamper-evident event. In stronger modes it includes attestation artifacts.

If an implementation kills and respawns an agent or subagent after authority changes, the new actor should continue under a new authority version and produce receipts that make the transition explicit. That handoff should be visible in evidence, even if the internal implementation details remain private.

### Layer 4: Attestation extensions

Define optional attestation types without forcing a single trust mechanism:

- `operator_signed`
- `workload_attested`
- `tee_attested`
- `zk_policy_proved`
- `zk_execution_proved`

The standard should let a verifier understand assurance level without guessing.

## Minimal trust taxonomy

The standard needs an honest trust vocabulary. Suggested tiers:

- `declared`
- `signed`
- `workload_attested`
- `tee_attested`
- `zk_policy_proved`
- `zk_execution_proved`

## Stateful authority and session model

Static scopes are not enough for privileged agent systems.

Many important decisions depend not only on the requested action but also on the evolving state of a session or delegated authority chain. Examples include:

- remaining spend or compute budget
- prior tool invocations
- approvals already consumed
- resources already touched
- unresolved obligations
- current authority version

This is where implementers are likely to build substantial custom logic. The standard should be modest here.

### What should be standardized

The standard should define:

- the request shape
- the receipt shape
- a portable decision result vocabulary
- references to session or authority version identifiers
- optional references to decision-context snapshots

### What should remain implementation-specific

The standard should not require one universal internal session engine.

Implementers may choose:

- workflow orchestration
- event sourcing
- a ledger-backed budget model
- an approval task system
- a custom projection store

The standard should only require that externally meaningful decisions and state transitions are explainable and referenceable.

## Decision outcomes beyond allow/deny

The standard should not assume authorization is purely binary.

A useful portable vocabulary would likely include:

- `allow`
- `deny`
- `deny_permanent`
- `deny_retryable`
- `pending_approval`
- `pending_step_up`
- `allow_with_obligations`
- `budget_reservation_required`

The precise internal mechanics remain implementation-defined, but the externally visible result should be portable enough for integrations, receipts, and audit.

This is important both for product honesty and for interoperability. A verifier must know whether a receipt is merely operator-signed or cryptographically stronger.

## Capability model

The standard should avoid generic scopes like `agent:*`. It should use capability tuples.

Suggested tuple shape:

- `action`
- `resource_type`
- `resource_selector`
- `constraints`

Examples:

- `tool.call` + `github.pull_request.merge` + repo selector
- `cloud.write` + `aws.iam.role` + account selector
- `data.read` + `customer_record` + region selector

This makes grants auditable and machine-enforceable.

## Discovery and transport profile

The standard should define how identity and receipt metadata are discovered over existing transports.

Recommended profile:

- authorization server discovery via RFC 9728 and RFC 8414
- agent identity document published at a stable URL or returned via metadata
- proof-of-possession key advertised in the identity document or grant
- action receipts returned inline, asynchronously, or via a receipt endpoint

For MCP and A2A, the standard should be transport-neutral:

- requests carry identity and delegation references
- responses may carry receipt references or full receipts
- asynchronous jobs must support later receipt retrieval

## Security properties the spec should require

At minimum, a conforming implementation should support:

- cryptographic binding between the acting agent and the request
- explicit delegation chain verification
- replay resistance for privileged actions
- immutable or tamper-evident receipt retention
- policy result binding to the receipt
- stable identifiers for correlation across systems

Nice-to-have properties:

- sender-constrained tokens
- workload identity binding
- hardware attestation support
- zero-knowledge or privacy-preserving proofs

## What the commercial product should own

The company should not merely host logs. It should own the evidence plane.

Product areas:

- receipt verification service
- trust graph across agents, grants, tools, and resources
- policy decision capture and replay
- anomaly detection on delegation and action patterns
- incident-response search and timeline reconstruction
- compliance exports and auditor views
- connectors to SIEM, GRC, ticketing, and cloud control planes

The moat comes from evidence quality, verification quality, detection quality, and workflow integration.

## Suggested rollout

### Phase 0: Profile existing standards

Goal:

- define a lightweight profile for OAuth, DPoP, SPIFFE, MCP, and A2A environments

Deliverables:

- agent identity document
- delegation grant schema
- action receipt schema
- JSON and JWT examples
- reference verifier

This is the fastest path to getting partners and collaborators aligned.

### Phase 1: Open-source reference stack

Goal:

- provide a reference implementation that issues identity documents, validates grants, and emits receipts

Deliverables:

- SDK support in this repository
- verifier API
- sample integrations for MCP and A2A
- test vectors and conformance fixtures

### Phase 2: Enterprise evidence plane

Goal:

- commercialize verification, detection, and compliance

Deliverables:

- hosted receipt verification
- trust graph and analytics
- policy management
- alerting and IR tooling
- enterprise connectors

## Governance recommendations

If the standard gets traction, it should not remain a single-company format forever.

Recommended path:

- start as an openly published profile and reference implementation
- recruit a small working group of security-minded practitioners
- keep the core schema small and versioned
- add extension points instead of stuffing everything into the base spec
- move toward neutral governance only after there is real implementation experience

Do not over-rotate into foundation work before there is a real deployment story.

## Open questions

These are the most important design questions to resolve with collaborators and design partners:

1. What is the minimal identity object that is still useful across vendors?
2. Should delegation be a standalone signed object, an OAuth token profile, or both?
3. What is the canonical capability grammar?
4. What receipt fields must be mandatory for audit-grade interoperability?
5. How should receipts express assurance tier without vendor-specific semantics?
6. When should SPIFFE-backed workload identity be the preferred profile?
7. How should MCP and A2A carry receipt references without breaking transport simplicity?
8. What must be public in a receipt, and what can remain commitment-only?
9. What is the clean commercial boundary between open verifier logic and managed evidence services?

## Near-term recommendation

The best next move is to publish a short working draft that defines:

- a narrow charter
- the core objects
- one capability grammar
- one receipt schema
- one OAuth-based profile
- one MCP example

That will make the conversation with collaborators concrete very quickly. It also keeps the effort focused on the real wedge: trustworthy evidence for privileged agent actions.

For the broader standards, OSS, and commercial landscape around this direction, see [landscape_research.md](landscape_research.md).
