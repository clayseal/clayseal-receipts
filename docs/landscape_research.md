# Landscape Research

As of **June 19, 2026**, the market and standards landscape around agent identity, authorization, and evidence is crowded in adjacent layers but still incomplete as a whole.

This memo summarizes what exists in open source and commercially, what is missing, and where Agent Receipts could add differentiated value.

## Executive summary

There is no single open standard or product today that cleanly combines:

- agent identity
- delegated authority
- fine-grained tool/resource authorization
- post-execution receipts
- attestation strength
- audit-grade evidence
- cross-system forensics

Instead, the market is split into partial layers:

- workload identity
- OAuth and authorization protocols
- policy engines
- secrets and machine identity
- software provenance and attestation
- observability and tracing
- governance products for non-human identities

That is good news. It means the category is real, but the stack is fragmented.

The strongest opportunity is not to replace IAM. It is to become the **evidence and trust layer for privileged agent actions** while aligning to open standards for identity and authorization.

## What exists today

### 1. Identity and delegated authorization standards

Relevant standards are real and actively moving:

- **OAuth 2.1** is still an IETF draft, but it remains the center of gravity for delegated authorization.
- **RFC 9728** defines protected resource metadata for authorization server discovery.
- **RFC 8414** defines authorization server metadata.
- **RFC 9449** defines DPoP for sender-constrained tokens and replay resistance.
- **RFC 9635** and **RFC 9767** define GNAP and GNAP resource server connections.
- **OpenID AuthZEN Authorization API 1.0** was approved as a Final Specification on **January 12, 2026**.
- **OpenID Shared Signals Framework**, **CAEP**, and **RISC** were approved as Final Specifications on **September 2, 2025**.
- **OpenID for Verifiable Presentations 1.0** became final on **July 9, 2025**.

This means the ecosystem already has strong building blocks for:

- identifying authorization components
- externalizing authorization decisions
- binding tokens to key material
- continuously revoking or attenuating access
- carrying portable verifiable assertions

What it does **not** yet have is a common standard for **agent action receipts** or **delegation-aware execution evidence**.

One additional development to watch is **WIMSE**. The IETF Workload Identity in Multi-System Environments working group explicitly focuses on workload identity at runtime and the propagation, representation, and processing of workload identities. That makes it relevant upstream infrastructure for agent identity, even if it does not solve agent-specific authority and evidence semantics by itself.

### 2. Agent interoperability standards

Two important protocols matter:

- **MCP** now has a formal OAuth-based authorization model and explicitly requires resource metadata aligned with RFC 9728.
- **A2A** has moved toward neutral governance under the Linux Foundation and is positioning itself as a standard for agent interoperability.

These are important distribution rails, but neither one is a complete agent IAM or evidence standard.

MCP is especially relevant because it creates a natural enforcement point around tool calls. A very recent OpenID AuthZEN Working Group announcement on **June 15, 2026** highlighted an emerging **COAZ** draft for MCP tool authorization and an **AARP** draft for approval-oriented authorization prerequisites. That is a strong signal that the standards world is moving toward exactly this problem, but it is still early.

### 2a. Capability-oriented delegation systems

Two additional families matter here:

- **Macaroons** introduced contextual caveats for decentralized authorization.
- **UCAN** provides publicly verifiable, delegable capabilities and is one of the more interesting modern designs for decentralized capability delegation.

These systems are important because they take attenuation seriously. They are relevant to subagent delegation, budget partitioning, and decentralized proof of delegated authority. Their weakness for enterprise settings is not cryptography but ecosystem integration and central visibility.

### 3. Workload identity and machine identity

Open-source and infrastructure-native identity is already mature:

- **SPIFFE/SPIRE** provides workload identity, SVIDs, workload attestation, and federation across trust domains.
- **OpenPubkey** binds public keys to OpenID identities and can be used as part of a larger signing system.

Commercially, this layer is getting crowded:

- **Teleport Machine & Workload Identity** gives machines and agents delegated, visible identity and audit logs.
- **Aembit** positions itself as workload IAM for apps, services, and AI agents with continuous identity verification and runtime policy enforcement.
- **CyberArk** is aggressively positioning machine identity security around secrets, certificates, and workload identities.
- **Auth0**, **Microsoft Entra**, and **Okta** all continue expanding machine-to-machine and workload identity capabilities.
- **ConductorOne** is explicitly extending governance into non-human identities and AI agents.

This layer answers “who is this workload?” and increasingly “what can it access right now?” It still does not answer “what exactly happened, under what authority, and how do I prove it later?”

### 4. Authorization engines and policy systems

The policy landscape is very strong:

- **OPA** is the most established open-source general-purpose policy engine.
- **Cedar** is an open-source policy language strongly associated with AWS Verified Permissions.
- **OpenFGA**, **SpiceDB**, and **Ory Keto** provide fine-grained authorization with graph or relationship-based models inspired by Zanzibar.
- **Cerbos** externalizes authorization into an open-source PDP.
- **Oso** and **Permit.io** provide authorization platforms with strong application integration stories.
- **Styra** commercializes OPA in enterprise environments.
- **Amazon Verified Permissions** provides a managed Cedar-based authorization service.

This layer is mature enough that building “yet another authorization engine” is probably the wrong move unless it solves an agent-specific problem that existing PDPs cannot.

What these tools generally do **not** provide is:

- a standard post-execution artifact
- attested delegation chains
- assurance tiers on actions
- forensic-grade action lineage

One subtle but important missing piece is that most policy engines still assume primarily binary or near-binary results. They can often be made to return richer metadata, but approval-native, resumable, and stateful agent outcomes are not yet the mainstream abstraction.

### 4a. Legacy and emerging non-binary authorization models

Two adjacent ideas are useful here:

- **XACML** has long supported obligations and advice in authorization responses, which means authorization can return more than a simple permit or deny.
- **AuthZEN AARP** suggests a modern direction for approval-oriented authorization flows.

This matters because agents often need outcomes like:

- pending approval
- allow with obligations
- step-up evidence required
- resumed after co-signature

That is a meaningful gap between what classic PDPs expose and what agent systems need.

### 5. Provenance, signing, and supply-chain attestation

There is also a rich ecosystem for artifact integrity and provenance:

- **Sigstore** signs and verifies artifacts using ephemeral keys and transparency logging.
- **in-toto** defines attestation frameworks for what steps were performed, by whom, and in what order.
- **SLSA** defines provenance and assurance levels for how artifacts were produced.
- **TUF** hardens software update distribution against key compromise and repository attacks.
- **GUAC** turns supply-chain metadata into a graph for security analysis.

This is one of the most important analogies for Agent Receipts.

Supply-chain security has already shown that the combination of:

- signed metadata
- attestation formats
- trust tiers
- verification tooling
- graph analysis

creates a whole product category.

Agent execution needs an equivalent.

Another adjacent IETF effort worth tracking is **SCITT**, which is defining interoperable building blocks for integrity and accountability in software supply chains. Even though SCITT is not built for agent sessions, it is a useful reference model for append-only transparency and externally verifiable evidence.

### 6. Secrets and machine credential systems

Secrets managers remain important plumbing:

- **OpenBao** provides identity-based secrets, PKI, lease management, and audit brokering.
- Vault-like systems generally provide issuance, rotation, revocation, and auditability for secrets and certificates.

These systems are useful inputs to agent identity and key management, but they are not a complete agent evidence plane.

### 6a. Workflow and durable execution systems

A major missing item in many IAM discussions is that approvals and resumable decisions usually live in workflow systems, not in pure authorization engines.

Relevant open-source foundations include:

- **Temporal** for durable workflow execution and event history
- **Camunda** for BPMN workflows, user tasks, approvals, and task-centric orchestration

These systems are strong foundations for:

- pending approval
- resume after human confirmation
- escalation
- timeout
- obligation handling

They still do not provide a portable agent authority model by themselves, but they are probably the most practical current substrate for approval-native authorization.

### 6b. Event sourcing and ledger foundations

The hardest stateful part of agent authorization starts to look less like static RBAC and more like event sourcing or accounting.

Relevant open-source foundations include:

- **EventStoreDB** for append-only event streams and replay
- **TigerBeetle** for debit/credit-style accounting and strict consistency

These are especially relevant if the system needs:

- consumable capability budgets
- reservations and holds
- shared subagent budget arbitration
- replayable authorization state

### 7. Observability and LLM tracing

The observability space is active but solves a different problem:

- **OpenTelemetry** standardizes traces, logs, and metrics.
- **Langfuse** is an open-source LLM engineering and observability platform.
- **Helicone** is an open-source AI observability and gateway platform.

These tools help teams debug and measure AI systems.
They are not designed to produce tamper-evident, policy-bound, verifier-friendly evidence artifacts for privileged actions.

## What the current market still lacks

### No standard action receipt

There is no dominant cross-vendor object today for:

- who acted
- under which delegated grant
- against which resource
- via which tool
- under which policy
- with what assurance level
- with what input/output commitments

That is the most obvious gap.

### No canonical bridge between pre-execution auth and post-execution evidence

OAuth, GNAP, AuthZEN, and workload identity can help answer “may this agent do this?”

But security teams also need:

- “did it actually do it?”
- “what data and tools were involved?”
- “what policy was in effect?”
- “was the authority delegated or direct?”
- “can I prove this six months later?”

That bridge is missing.

### No clear standard boundary between agent internals and authority-bearing actors

Many agent systems will have rich internal planner/worker structures.

The ecosystem still lacks a good shared answer to:

- which internal components are merely implementation details
- which components should be treated as independently governed actors
- when a subagent needs its own authority, budget, or receipt

This is important because over-standardizing agent internals will kill adoption, but under-standardizing authority-bearing actors leaves a large accountability gap.

### No standard trust taxonomy for agent actions

Today most systems flatten assurance into binary success or failure.
In reality, you want explicit tiers such as:

- declared
- signed
- sender-constrained
- workload-attested
- TEE-attested
- ZK-policy-proved
- ZK-execution-proved

The ecosystem does not yet have a common vocabulary for this.

### No graph of agent authority and execution

GUAC shows the power of graphing provenance for software artifacts.
There is no widely adopted equivalent graph for:

- agent identities
- delegated grants
- tool invocations
- receipt chains
- approvals
- policy evaluations
- attestation artifacts

That is a large product opportunity.

### No real standard for approval-oriented agent authorization flows

This is starting to move. The new OpenID AuthZEN **AARP** draft is directly relevant because agents often hit actions that are not denied forever, but are denied **until** an approval, attestation, or exception exists.

This suggests a strong future product direction:

- not only “allow/deny”
- but also “approvable, pending, resumed, re-evaluated”

### No standard model for consumable capability budgets

A particularly important open problem is that many agent permissions are not static. They are consumable.

Examples:

- spend up to a threshold
- use a limited number of tool calls
- consume a one-time approval
- split a finite budget across spawned subagents

There is no dominant open standard for capability budgets, reservations, or authority consumption in agent systems.

### No strong cross-protocol story

Different transports and frameworks are emerging:

- MCP
- A2A
- generic HTTP APIs
- service meshes
- cloud control planes

Each has different request formats and metadata models.
There is still no dominant cross-protocol profile that normalizes them into a stable authorization and evidence model.

## Commercial landscape: what companies are already claiming

### Companies closest to agent/non-human IAM

These are the closest visible commercial neighbors:

- **Okta** now explicitly talks about governing AI agents and “agentic identity.”
- **Aembit** positions itself as workload IAM for software workloads and AI agents.
- **Teleport** now markets machine and workload identity for AI agents, MCP, SSH, and Kubernetes.
- **CyberArk** is expanding machine identity security around non-human identities.
- **ConductorOne** is bringing identity governance into AI agents and non-human identities.
- **Permit.io** is moving hard into fine-grained authorization for the AI era.

These players are validating the market.
They also make it dangerous to compete on generic policy or generic workload identity.

### Companies adjacent on authorization

- **AWS Verified Permissions**
- **Oso**
- **Styra**
- **Cerbos**
- **AuthZed**
- **OpenFGA vendors and managed services**

These companies prove that externalized, fine-grained authorization is already valuable. Competing there without an agent-specific edge would be hard.

### Companies adjacent on observability

- **Langfuse**
- **Helicone**
- observability vendors using **OpenTelemetry**

These tools validate demand for operational visibility into AI systems, but they still leave room for a stronger evidence and trust layer.

## Where Agent Receipts can still win

The right position is not:

- “identity for agents”
- “yet another authz engine”
- “LLM observability”

The right position is:

- **evidence-grade trust and control plane for privileged agent actions**

More specifically:

- open profile for identity, delegation, and receipts
- commercial evidence plane for verification, analytics, detection, and compliance

Just as importantly, the product should not attempt to standardize the internal design of agents. It should standardize the authority and evidence boundary, especially for authority-bearing actors and externally meaningful actions.

## Additional value that could be added on top

Below are the most promising additive layers.

### 1. Standardized action receipts

Create the equivalent of in-toto attestations for agent actions.

Minimum fields should cover:

- actor
- delegator
- grant or authority chain
- tool or action
- resource
- policy reference
- decision result
- assurance tier
- commitments to input and output
- timestamps and chain linkage

This should work even without ZK.

### 2. A trust graph for agent operations

Build a GUAC-like graph for agent actions and authorities.

Nodes:

- agent identities
- grants
- policies
- tools
- resources
- receipts
- approvals
- attestation artifacts

Edges:

- delegated to
- invoked
- approved by
- bound to policy
- produced receipt
- attested by

This graph would be powerful for:

- blast-radius analysis
- incident response
- auditing
- policy simulation
- lateral-movement detection

### 3. Assurance-tier normalization

Normalize heterogeneous signals into one verifier-facing trust model.

Examples of raw signals:

- DPoP-bound token
- SPIFFE SVID
- Nitro Enclave attestation
- Intel TDX attestation
- Azure Attestation result
- Sigstore signature
- ZK proof bundle

The product value is not merely storing them, but making them comparable and queryable.

### 4. Approval and exception workflow as an authorization primitive

Lean into the emerging AuthZEN **AARP** direction.

Support decisions like:

- allow
- deny
- allow with obligations
- pending approval
- pending attestation
- pending step-up evidence

This fits privileged agent workflows much better than classic “permit or reject.”

### 4a. Authority-bearing actor boundary

A useful additive layer is a portable way to identify when an internal component becomes externally meaningful.

Examples:

- a worker with its own delegated grant
- a subagent with its own spend budget
- an execution unit that needs separate human approval
- a tool-specific actor that emits its own receipt

This is a practical way to preserve implementer freedom while still making the system governable.

### 5. Policy replay and forensic re-verification

Security teams will want to ask:

- What would policy say today about an action from last month?
- What changed between the policy then and now?
- Which receipts were signed under a weaker trust tier?

Very few existing systems make this easy.

### 5a. Session handoff and authority versioning

If an implementation revokes or restricts permissions mid-session, many systems will kill and respawn the affected agent or subagent.

That creates a new need:

- versioned authority
- explicit session handoff artifacts
- clear lineage from old authority to new authority
- replayable evidence across respawns

This is not well solved in open tooling today.

### 6. Cross-protocol normalization

Normalize MCP tool calls, A2A messages, API calls, and cloud actions into one common subject-action-resource-context model.

This could be one of the most valuable parts of the platform because customers do not want four governance stacks.

### 7. Continuous revocation and attenuation

Use Shared Signals / CAEP-style events for agent contexts:

- delegated grant revoked
- tool risk elevated
- model version withdrawn
- resource reclassified
- agent owner disabled
- enclave attestation expired

This turns the system into a living trust fabric instead of a static log.

### 7a. Budget reservations and compensation

If authority includes budgets, then authorization starts to look like transaction processing.

You may need:

- reserve capability before action
- commit capability on successful effect
- release or compensate on failure

This is a major source of product differentiation and one of the least solved areas in current open-source IAM tooling.

### 8. Separation-of-duties and conflict analysis for agents

Classic IAM has SoD for humans.
Agentic systems need:

- no single agent can both propose and approve a payment
- no agent can both write infrastructure and approve the deployment
- no delegated agent may exceed parent capability plus environment constraints

This is highly valuable and not well solved.

### 9. Compliance-native exports

Compliance teams do not want raw JSON.
They want mapped evidence:

- who approved what
- what policy enforced the threshold
- where the action happened
- what trust tier applied
- whether evidence remains re-verifiable

Productize exports for:

- SOC 2
- ISO 27001
- PCI-like payment controls
- internal audit narratives
- incident review packets

### 10. Privacy-preserving proofs where they matter

ZK should not be the main product, but it can be a major premium differentiator where customers need to prove:

- policy compliance without exposing raw data
- model use without revealing full inputs
- approval thresholds without revealing full transaction context

This is especially valuable in regulated or multi-party settings.

### 11. Conformance and certification

If an open standard emerges, the company can become the best implementation and verifier.

Longer-term value:

- conformance suite
- verifier reference implementation
- hosted compatibility testing
- partner certification

This mirrors how identity and supply-chain ecosystems often mature.

### 12. Agent provenance and lifecycle metadata

Receipts should not stop at runtime.
Customers will care about:

- which model version was active
- which prompt or policy bundle was deployed
- which tool manifest was available
- whether the agent owner changed
- whether a deployment was signed and attested

This begins to connect runtime evidence with software provenance.

## What should be standardized versus monetized

### Good candidates for the open layer

- identity document schema
- delegation grant schema
- action receipt schema
- assurance taxonomy
- subject-action-resource-context mapping profile
- verifier interface basics

### Good candidates for the commercial layer

- evidence graph
- policy replay and forensic tooling
- anomaly detection
- compliance reporting
- multi-source attestation normalization
- approval orchestration
- enterprise integrations
- managed verification service

## Strategic recommendation

The best strategic move is to treat this as the convergence of three existing markets:

1. **non-human / workload IAM**
2. **modern authorization**
3. **software provenance and supply-chain attestation**

Then build the missing fourth layer:

4. **agent execution evidence**

The product should look less like a new IdP and more like:

- Sigstore or in-toto for agent actions
- GUAC for agent authority and receipts
- AuthZEN plus MCP/A2A profiles for runtime authorization
- CAEP-style signals for continuous trust updates

It may also need to borrow heavily from:

- workflow engines for approvals and resumable decisions
- event-sourced systems for replayable state
- ledgers for consumable capability accounting

## Recommended next steps

### Near term

- define a canonical receipt object
- define a narrow capability grammar
- define an MCP profile for tool authorization and receipts
- define a trust-tier vocabulary

### Mid term

- build the trust graph and replay engine
- add Shared Signals / CAEP-style revocation and attenuation
- add attestation adapters for SPIFFE, DPoP, TEE, Sigstore, and cloud attestation systems

### Long term

- formalize the standard with implementers
- ship conformance tooling
- make privacy-preserving receipts and premium verification the highest-assurance tier

## Source map

Standards and protocols:

- MCP authorization: <https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>
- A2A announcement: <https://developers.googleblog.com/en/a2a-a-new-era-of-agent-interoperability/>
- A2A Linux Foundation move: <https://developers.googleblog.com/en/google-cloud-donates-a2a-to-linux-foundation/>
- WIMSE charter: <https://datatracker.ietf.org/doc/charter-ietf-wimse/>
- WIMSE workload identity practices: <https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-identity-practices/>
- OAuth 2.1 draft: <https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/>
- RFC 9728: <https://datatracker.ietf.org/doc/rfc9728/>
- RFC 8414: <https://datatracker.ietf.org/doc/html/rfc8414>
- RFC 9449 DPoP: <https://datatracker.ietf.org/doc/html/rfc9449>
- RFC 9635 GNAP: <https://datatracker.ietf.org/doc/html/rfc9635>
- RFC 9767 GNAP resource server connections: <https://datatracker.ietf.org/doc/rfc9767/>
- XACML 3.0 core spec: <https://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html>
- OID4VP final: <https://openid.net/specs/openid-4-verifiable-presentations-1_0-final.html>
- AuthZEN WG overview: <https://openid.net/wg/authzen/>
- Authorization API 1.0 final approval: <https://openid.net/authorization-api-1-0-final-specification-approved/>
- Shared Signals specs: <https://openid.net/wg/sharedsignals/specifications/>
- AuthZEN AARP and COAZ announcement: <https://openid.net/openid-foundation-advances-authorization-for-the-agent-era-with-new-authzen-working-group-drafts/>
- SCITT WG: <https://datatracker.ietf.org/group/scitt/about/>
- SCITT architecture draft: <https://datatracker.ietf.org/doc/html/draft-ietf-scitt-architecture-11>

Open source and technical building blocks:

- SPIFFE overview: <https://spiffe.io/docs/latest/spiffe-about/overview/>
- SPIFFE concepts and SVIDs: <https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/>
- UCAN spec: <https://github.com/ucan-wg/spec>
- UCAN getting started: <https://ucan.xyz/getting-started/>
- Macaroons paper: <https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/>
- OPA docs: <https://openpolicyagent.org/docs>
- OpenFGA: <https://openfga.dev/>
- SpiceDB: <https://authzed.com/spicedb>
- SpiceDB caveats: <https://authzed.com/docs/spicedb/concepts/caveats>
- Ory Keto: <https://www.ory.sh/keto/>
- Cerbos: <https://www.cerbos.dev/>
- Cedar: <https://cedarpolicy.com/>
- OPAL: <https://docs.opal.ac/>
- Temporal workflow execution: <https://docs.temporal.io/workflow-execution>
- Temporal event history: <https://docs.temporal.io/encyclopedia/event-history/>
- Temporal human-in-the-loop AI agent: <https://docs.temporal.io/ai-cookbook/human-in-the-loop-python>
- Camunda user tasks: <https://docs.camunda.io/docs/components/modeler/bpmn/user-tasks/>
- EventStoreDB: <https://docs.kurrent.io/server/v23.10/>
- TigerBeetle debit/credit: <https://docs.tigerbeetle.com/concepts/debit-credit/>
- Sigstore overview: <https://docs.sigstore.dev/about/overview/>
- in-toto specs: <https://in-toto.io/docs/specs/>
- SLSA provenance: <https://slsa.dev/spec/v1.0/provenance>
- TUF overview: <https://theupdateframework.io/docs/overview/>
- OpenBao: <https://openbao.org/>
- GUAC: <https://guac.sh/guac/>
- OpenTelemetry: <https://opentelemetry.io/docs/what-is-opentelemetry/>
- Langfuse: <https://langfuse.com/docs>
- Helicone OSS: <https://docs.helicone.ai/references/open-source>
- OpenPubkey: <https://github.com/openpubkey/openpubkey>

Commercial and product landscape:

- Teleport Machine & Workload Identity: <https://goteleport.com/platform/machine-and-workload-identity/>
- Aembit: <https://aembit.io/>
- CyberArk machine identity security: <https://www.cyberark.com/products/machine-identity-security/>
- AWS Verified Permissions: <https://aws.amazon.com/verified-permissions/>
- Permit.io: <https://www.permit.io/>
- Oso: <https://www.osohq.com/oso-for-apps>
- Okta govern AI agent identity: <https://www.okta.com/products/govern-ai-agent-identity/>
- Okta secure AI: <https://www.okta.com/solutions/secure-ai/>
- Auth0 M2M: <https://auth0.com/features/machine-to-machine>
- ConductorOne NHI governance: <https://www.conductorone.com/solutions/nhi-governance/>

Attestation and confidential computing:

- Intel TDX: <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html>
- NVIDIA confidential computing: <https://www.nvidia.com/en-us/data-center/solutions/confidential-computing/>
- AWS Nitro Enclaves: <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html>
- Azure confidential VM guest attestation: <https://learn.microsoft.com/en-us/azure/confidential-computing/guest-attestation-confidential-vms>
