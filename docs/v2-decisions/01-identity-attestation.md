# Piece v2.1 — Identity Service: from declared to attested

Reworks the Identity Service to match the production model in
[`identity/identity.md`](../../identity/identity.md). Maps the dev prototype onto SPIRE/SPIFFE:
identity is now **proven through attestation**, not **declared** by the caller.

## The problem with v1

The v1 Identity Service (`agentauth/backend/identity.py`) let any API-key holder call
`POST /v1/identify` with `{agent_type, owner, scopes}` and receive a signed JWT for exactly that.
The API key proved *which tenant* was calling, but nothing proved the workload was entitled to the
identity it asked for. An agent could claim to be `finance` with `pay:send` scope simply by typing
those strings. That is precisely the property `identity.md` says production must prevent:

> "An agent can't claim to be a finance type just by having credentials; it has to prove it's
> running in an environment that's been pre-approved for that agent type."

## What changed

`identify()` is now **attestation**. The flow:

1. **Admin registers a node trust anchor** (`POST /v1/node-attestors`) — the public key whose
   signatures the tenant accepts as proof of node provenance. This is the prototype's stand-in for
   bootstrapping a SPIRE Server with a cluster's/cloud's verification material (k8s PSAT issuer,
   AWS IID cert, GCP IIT).
2. **Admin pre-approves an identity** (`POST /v1/registration-entries`) — `{agent_type, selectors,
   scopes}`. The selectors are the node + workload selectors a workload must prove to receive that
   `agent_type` and those `scopes`.
3. **Workload attests** (`POST /v1/identify`) with a **signed attestation document** (a JWS). The
   server runs two attestor stages, then matches and issues:
   - **Node attestor** (`attestation.py::verify_node_attestation`) verifies the document's
     signature against a registered anchor → derives *node selectors*. This is the trust decision:
     a document signed by a key we don't trust proves nothing.
   - **Workload attestor** (`attestation.py::derive_workload_selectors`) reads the verified
     document's `workload` block → derives *workload selectors* (`k8s:sa:`, `k8s:pod-label:`,
     `docker:image-digest:`, `unix:uid:`).
   - **Match**: find the registration entry whose required selectors are a subset of the union;
     mint a credential for *that entry's* `agent_type`/`scopes`. No match → `attestation_denied`.

The headline guarantee, captured by the test `test_rogue_agent_wrong_pod_label_is_denied`: a
workload with a valid node signature and the correct service account but the wrong
`agentauth.io/agent-type` pod-label gets **no credential**, because the finance entry's selectors
are no longer a subset of what was proven.

## Key decisions

### 1. JWT-SVID, not raw X.509 SVID
Production SPIRE issues X.509 SVIDs (certs whose SAN URI is the SPIFFE ID). We keep the **JWT**
mechanism but reshape it into a **JWT-SVID**: `sub` is the SPIFFE ID
(`spiffe://agentauth.io/customer/{id}/agent/{type}`), `iss` is the trust domain, and the agent
*instance* id moves to a separate `agent_id` claim (the `identity.md` table calls for exactly this
— "short-lived cert + optional separate agent id claim"). This preserves the whole v1 verification
stack — per-customer signing keys, rotation, the JWKS endpoint, offline verification with
`jwt.decode` — so the change is contained to issuance/validation semantics rather than a new
credential transport. Raw X.509 SVIDs are deferred (see below).

### 2. Verified signed evidence, not asserted selectors
A caller never hands us a selector. Selectors are **derived from evidence the server verifies**.
The attestation document is a JWS signed by the node key; forging provenance requires the anchor's
private key. We can't call a live k8s TokenReview or AWS IID endpoint from an in-process service,
so the transport is simulated — but the cryptographic trust decision is real. `test_identity.py`
covers the four denial modes that matter: a forged/unparseable document, a document signed by an
**unregistered** key, an **expired** document, and selectors that match **no entry**.

### 3. agent_type and scopes come from the entry, never the request
`IdentifyRequest` no longer carries `agent_type` or `scopes` — only the attestation document, an
optional `owner`, and an optional `ttl_seconds`. The matched `RegistrationEntry` is the sole source
of `agent_type`/`scopes`. This is the structural enforcement of "prove, don't claim".

### 4. Most-specific entry wins
SPIRE would issue an SVID for *every* matching registration entry; we mint a single credential, so
`_match_entry` picks the entry requiring the **most** selectors (most specific), breaking ties by
earliest `created_at` for determinism. Documented in code at the call site.

### 5. Scope/owner live alongside the SPIFFE ID, not in attestation
Attestation answers "what workload is this?" — it yields a SPIFFE ID, `agent_type`, and the
`scopes` declared on the matched registration entry. This matches the `identity.md` note that
scope and owner are metadata attached to the SPIFFE ID rather than properties of the attestation
itself.

### 6. Trust anchors are per-customer
Each tenant registers its own node attestors, mirroring multi-tenant isolation already used for
signing keys: one tenant's trust material can never attest another tenant's workloads.

## Data model additions

- `NodeAttestor(id, customer_id, type, public_pem, description, created_at)` — `type` ∈
  `{k8s_psat, aws_iid, gcp_iit}`.
- `RegistrationEntry(id, customer_id, agent_type, selectors, scopes, owner?, ttl_seconds?,
  description, created_at)`.
- `Agent` gains `spiffe_id` and `selectors` (the attested selectors).

New error: `AttestationDeniedError` (`attestation_denied`, HTTP 403) for every failure to prove an
identity — bad signature, unregistered key, stale document, or no matching entry.

## Simulated vs real (honest scope)

- **Real**: the signature verification (RS256 against a registered public key), selector
  derivation, subset matching, the entry-driven authority model, and JWT-SVID issuance/validation.
- **Simulated**: there is no live node attestor calling Kubernetes TokenReview / the AWS IID
  endpoint / the GCP metadata server, and no Unix-socket Workload API. The signed document stands
  in for evidence a real SPIRE Agent gathers on the node. The selector *vocabulary* matches SPIRE
  conventions so the model transfers.

## Deferred

- **SDK + dashboard** still call the v1 `identify(agent_type, owner, scopes)` shape and need a
  follow-up to send attestation documents / manage node attestors + registration entries. This
  piece is intentionally scoped to `agentauth/backend/` + `backend/tests/`.
- **Raw X.509 SVIDs** (SAN-URI leaf certs chained to a per-customer CA) as an alternative to the
  JWT-SVID.
- **Real cloud/k8s node attestors** (AWS IID signature chain, k8s PSAT TokenReview) and a Workload
  API transport.
- **Selector richness** — image-digest / UID selectors are modelled but registration entries in
  tests key on namespace/SA/pod-label; stricter entries are a config choice, not a code change.
