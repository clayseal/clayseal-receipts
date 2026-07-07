# L1 to L3/L4 Boundary

While L2 capability-token work is still evolving, Layer 1 and Layers 3/4 should align on a **normalized authority-binding contract** rather than a final token shape.

## Goal

L1 should produce trustworthy authority facts.
L3/L4 should consume those facts for policy, receipts, replay, and audit.

The shared object is `AuthorityBinding` in [authority_binding.py](../agentauth/receipts/authority_binding.py).

The first concrete integration target is the partner `Clay Seal` credential
shape from `origin/layer_1` (`CredentialOut` / SDK `Credential`). That payload
already contains enough L1/L2 facts for `AuthorityBinding.from_agentauth_credential(...)`
to build a native lower-layer authority object.

## Required fields

| Field | Meaning |
|-------|---------|
| `subject_id` | Stable identity of the attested or delegated actor |
| `authority_id` | Stable authority/grant identifier |
| `issuer` | Issuer or trust root for the authority |

## Optional fields

| Field | Meaning |
|-------|---------|
| `tenant_id` | Tenant / audience / customer binding |
| `subject_type` | L1 identity class such as `finance`, `researcher` |
| `capabilities` | Normalized capability or scope values |
| `scope_claims` | Original flat `resource:action` scope strings from L1/L2 |
| `capability_rules` | Structured capability objects from L2 (`resource`, `action`, optional metadata) |
| `selectors` | Attested selectors / provenance-derived facts |
| `attestation_type` | Example: `k8s_psat`, `jwt_svid`, `spiffe` |
| `delegation_chain` | Parent authority / mandate / token lineage |
| `expires_at` | Expiry timestamp for the current authority |
| `trust_tier` | Optional assurance shorthand consumed by policy |
| `proof_of_possession` | Whether the authority is PoP-bound |
| `presenter_key_hash` | L2 PoP binding hash when capability grants are key-bound |
| `has_capability_grant` | Whether a separate L2 capability grant exists |
| `resource_scope` | Allowed resource patterns for the action |
| `budget_refs` | Budget identifiers the authority may draw on |
| `approval_refs` | Approval grant identifiers required for spend |

## Clay Seal credential mapping

For the current partner branch, the mapping is:

| Clay Seal field | AuthorityBinding field |
|-----------------|------------------------|
| `spiffe_id` | `subject_id`, `workload_principal` |
| `agent_id` | `authority_id` (current default) |
| SPIFFE trust domain | `issuer` |
| SPIFFE customer path segment | `tenant_id` |
| `agent_type` | `subject_type` |
| `owner` | `owner_ref` |
| `scopes` | `scope_claims` |
| `capabilities` | `capability_rules` |
| normalized `resource:action` union | `capabilities` |
| `selectors` | `selectors` |
| `expires_at` | `expires_at` |
| `biscuit` / `has_biscuit` + `bound_keyhash` | `has_capability_grant`, `proof_of_possession`, `presenter_key_hash` |

By default, the adapter currently maps:

- attested JWT-SVID credentials without PoP capability tokens to `trust_tier="workload_attested"`
- PoP-bound capability-token credentials to `trust_tier="sender_constrained"`

### L1 sender-constrained JWT-SVIDs

Identity issuance on the L1 service is **not bearer-only**. `identify()` requires
an Ed25519 `workload_pubkey_pem` in the attestation evidence; every minted
JWT-SVID carries `cnf.jkt` bound to that workload key, and each Biscuit carries
the same thumbprint in `bound_key(...)`. `/v1/validate` and `/v1/authorize`
require request-bound proof-of-possession over the server challenge, endpoint,
token hash, issued-at time, proof id, and operation. Stolen tokens cannot be
replayed without the workload private key and a fresh server challenge.

See [l1_l2_hardening.md](l1_l2_hardening.md) for the production key-custody,
PoP, and Biscuit revocation contract.

## Runtime mapping

`AuthorityBinding.to_authority_context()` maps the shared contract into `AuthorityContext`, which is already used by:

- `ExecutionContext`
- `DecisionResult`
- receipt export (`authority`, `execution_context`)
- replay / explain flows

That means L1 can evolve independently as long as it can still populate the normalized fields above.

## L3 enforcement (landed)

`PolicyEngine` evaluates `_authority_violations()` on every decision path. Beyond
expiry, PoP, and capability scope, the engine now enforces:

| Authority field | L3 check |
|-----------------|----------|
| `trust_tier` | Compared against `Policy.min_trust_tier` when set |
| `resource_scope` | Must allow the action's resources |
| `budget_refs` | Authorization `budget_id` must be listed when refs are present |
| `approval_refs` | Authorization `approval_id` must be listed when refs are present |

These checks are fail-closed: missing comparable authorization context fields when
refs are required produce violations rather than silent allow.

## Ownership split

### L1 owner

Owns:

- how authority is attested
- how credentials or delegation artifacts are serialized
- how selectors are derived
- how issuer / subject / expiry are verified

### L3/L4 owner

Owns:

- how normalized authority facts are interpreted for policy
- how they map into execution gating
- how they appear in receipts, verifier output, replay, and audit

## Non-goal

This boundary does **not** lock in the final L2 capability-token encoding.
It only aligns both sides on shared semantics now so later integration is incremental instead of a rewrite.
