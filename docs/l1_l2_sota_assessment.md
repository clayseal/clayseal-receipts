# L1/L2 SOTA Assessment — agent identity & capability authorization

> **Status update (2026-06-21):** This assessment captured the pre-hardening
> L1/L2 state. The P0/P1 hardening items it recommends have since landed for
> the workload-key and issued-credential paths: Ed25519 workload keys,
> Ed25519-signed JWT-SVIDs, `cnf.jkt` JWK thumbprints, request-bound PoP,
> one-time server challenges, and Biscuit revocation-id deny-lists. The current
> production contract lives in
> [l1_l2_hardening.md](l1_l2_hardening.md). Remaining strategic work is wire
> format standardization against WIMSE WIT/WPT and replacing the prototype node
> attestation transport with real SPIRE/cloud/hardware attestation.

Deep research on whether the mechanisms in **L1 (agent identity)** and **L2 (delegation /
capability grants)** represent the state of the art, and concrete improvements where they don't.

**Scope.** Assessed the implementation on `origin/layer_1` (the Clay Seal backend) plus the
`AuthorityBinding` integration on `layer_2`:

- L1: [`agentauth/backend/identity.py`](../agentauth/backend/identity.py) (JWT-SVID issuance),
  [`agentauth/backend/attestation.py`](../agentauth/backend/attestation.py)
  (node/workload attestation).
- L2: [`agentauth/backend/capabilities.py`](../agentauth/backend/capabilities.py) (Biscuit minting, attenuation, PoP, authorization).
- Bridge: [`agentauth/receipts/authority_binding.py`](../agentauth/receipts/authority_binding.py),
  [`docs/l1_l3l4_boundary.md`](l1_l3l4_boundary.md).

**Method.** Read the cryptographic core of each mechanism, then compared against current (2025–2026)
standards and literature (citations inline; full list at the end). Verdicts are deliberately
blunt; "below SOTA" means a named, adopted alternative is materially better, not that the code is
wrong.

**TL;DR.** The *architecture* is sound and several choices are genuinely modern (Biscuit Datalog
capabilities, Ed25519 token roots, monotonic attenuation, offline verification, short TTLs). But
three things hold L1/L2 back from SOTA: (1) **legacy crypto primitives** (RS256 / RSA PKCS#1 v1.5)
sitting next to the modern Ed25519 root; (2) a **bearer-token identity** (JWT-SVID) and a
**bespoke, replayable proof-of-possession** where the field has converged on key-bound tokens
(WIMSE WIT + WPT, DPoP `cnf`); and (3) **no real revocation** despite Biscuit handing it to us for
free. The single highest-leverage move is to **stop re-inventing WIMSE/DPoP ad hoc and align to
them**, which also yields interop with the MCP/A2A authorization world.

---

## SOTA scorecard

| # | Mechanism (as built) | SOTA reference (2025–2026) | Verdict |
|---|----------------------|----------------------------|---------|
| 1 | **Biscuit** Datalog capability tokens, Ed25519 root, offline verify, monotonic attenuation | Biscuit v3 / UCAN / macaroons | **At SOTA** — keep |
| 2 | **Historical:** JWT-SVID signing = RS256 (RSA); PoP signature = RSA PKCS#1 v1.5 | EdDSA/Ed25519 default for new Clay Seal-issued credentials and PoP | **Remediated on current branch** |
| 3 | **JWT-SVID is a bearer token** (PoP only on the capability side) | Key-bound identity: WIMSE **WIT**, **WIT-SVID** `cnf` (RFC 7800), DPoP-bound JWT-SVID | **Below SOTA** |
| 4 | **Bespoke PoP**: workload signs `keyhash\|challenge\|resource\|action` | WIMSE **WPT** (request-bound proof JWT); DPoP (RFC 9449) | **Below SOTA / reinvention** |
| 5 | PoP **freshness/replay**: server issues a challenge but the authorizer never enforces freshness or single-use | DPoP server **nonce** + `jti` single-use cache; request binding | **Gap (replayable)** |
| 6 | **Revocation** = root-key rotation (nuclear) + expiry only | Biscuit **revocation IDs**; UCAN revocation; short TTL + status list | **Gap (easy win)** |
| 7 | **Attestation** = SPIRE two-stage *stand-in*; RS256-signed JWT doc, simulated transport, no freshness nonce | Real SPIRE node/workload attestation; hardware-rooted (TPM/TEE) | **Prototype (expected)** |
| 8 | **Standards posture**: ad-hoc identity + PoP + delegation | IETF **WIMSE** (WIT/WPT/creds), **Transaction Tokens for Agents** (`act` chain), AuthZEN/MCP auth | **Reinventing adopted standards** |

---

## Findings & improvements

### 1. Capability core (Biscuit) — keep, it's SOTA

`capabilities.py` uses [Biscuit](https://www.biscuitsec.org/): per-customer **Ed25519** root,
Datalog `capability(resource, action)` facts, **offline** verification against a published root
key (a "biscuit JWKS"), and **monotonic attenuation** — appended blocks can only restrict. This is
exactly the modern capability model (Biscuit is the strongest production option for attenuation;
UCAN and macaroons are its peers). The `(resource, action)` + wildcard authorizer and the
capability↔scope reconciliation are clean. **No change recommended to the core design.** The
problems below are around it, not in it.

### 2. Legacy signature primitives (RS256 / PKCS#1 v1.5) — remediated

The original assessment found two legacy RSA uses:

- JWT-SVIDs are signed **RS256** with a per-customer RSA key (`identity.py`).
- The PoP signature is **RSA PKCS#1 v1.5 + SHA-256** (`sign_pop`/`verify_pop` in `capabilities.py`).

The current branch has removed those Clay Seal-issued RSA paths. JWT-SVIDs are
signed by per-customer Ed25519 keys and PoP requires Ed25519 workload keys.
The remaining RS256 references are the prototype node-attestation document,
which represents an external attestor and is tracked separately as attestation
productionization work.

In 2026 the consensus default for new JWT/PoP signatures is **EdDSA (Ed25519)** — ~8× faster
verification, 64-byte signatures, 32-byte keys, and no padding/curve foot-guns; ES256 is the
fallback, and the **FAPI** profile explicitly discourages RS256 and requires PS256/ES256
([JWT best practices 2026](https://jsoncraft.dev/docs/jwt-best-practices-2026/),
[Curity EdDSA](https://curity.io/resources/learn/jwt-signatures/)). The irony: the Biscuit root is
**already Ed25519** — the identity and PoP legs just didn't follow. This is the cheapest credibility
win: move JWT-SVID to EdDSA (or ES256 if a consumer needs JOSE-classic), and make the PoP signature
Ed25519. RSA PKCS#1 v1.5 in particular is the oldest, most padding-fragile choice and should be the
first to go.

> **Improvement 2.** EdDSA for JWT-SVID and PoP; drop RSA PKCS#1 v1.5 entirely. Low effort, removes
> the most dated primitive and unifies on one curve with the Biscuit root.

### 3 & 4. Bearer identity + bespoke PoP → align to WIMSE WIT/WPT

The JWT-SVID is a **bearer token**: anyone who captures it can present it as the agent. PoP exists,
but only on the *capability* side (the Biscuit's `bound_key` + `check if valid_pop(true)`), not on
the *identity* token. SPIFFE itself documents JWT-SVID as replay-susceptible — `aud`/`exp` help but
don't fully solve it, and multi-audience tokens are replayable across audiences
([SPIFFE JWT-SVID](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/),
[SPIFFE #260](https://github.com/spiffe/spiffe/issues/260)).

The field has already converged on the fix, and it is **exactly what Clay Seal built by hand**:

- IETF **WIMSE** defines the **Workload Identity Token (WIT)** — a JWT that *binds a public key to
  the workload identity* and **must not be used as a bearer token** — and the **Workload Proof
  Token (WPT)**, a protocol-independent signed-JWT proof of possession bound to a *specific HTTP
  request* ([draft-ietf-wimse-wpt-01](https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/),
  [workload-creds](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/), Mar 2026).
- The experimental **WIT-SVID** branch makes PoP via the `cnf` claim (RFC 7800) **mandatory** and
  drops `aud`, structurally closing JWT-SVID's bearer-replay risk
  ([SPIFFE deep dive](https://dev.to/kanywst/spiffe-compliance-deep-dive-5e29)).

Clay Seal's `keyhash|challenge|resource|action` RSA signature is a bespoke WPT. Re-expressing it as
**WIT (key-bound identity via `cnf`) + WPT (request-bound proof JWT)** gets the same security with
(a) a standard wire format MCP/A2A verifiers will understand, (b) audience scoping handled by the
PoP layer instead of fragile `aud` matching, and (c) request binding (method + URI + body hash)
instead of the coarse `(resource, action)` pair.

> **Improvement 3.** Make the identity token key-bound: add `cnf` (RFC 7800) holding the workload
> key thumbprint; verifiers require a matching proof. Track WIT/WIT-SVID.
>
> **Improvement 4.** Replace the bespoke PoP string with a **WPT-shaped** signed proof bound to the
> concrete request, not just `(resource, action)`.

### 5. PoP freshness & replay — the real security gap

`issue_challenge()` mints a nonce, and `pop_message` binds it — but **nothing enforces that the
challenge is fresh or single-use**. `authorize_biscuit` verifies the signature and runs Datalog; it
never checks that the challenge was recently issued, hasn't been seen before, or has expired. So a
captured `(challenge, signature)` for a given operation is **replayable for as long as that
challenge is accepted**, and nothing bounds that window. The `pop_message` operation-binding stops
*cross-operation* replay, not *same-operation* replay.

This is the precise problem **DPoP (RFC 9449)** addresses with two tools: a server-provided
**nonce** for freshness (it may embed server time to survive clock skew) and a **`jti` single-use
cache** for strong replay protection — noting that the `jti` cache "may not always be feasible …
when multiple servers behind a single endpoint have no shared state"
([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449),
[WorkOS DPoP](https://workos.com/blog/dpop-rfc-9449-explained)). That caveat is the crux of the
**offline** authorization model Clay Seal chose: pure-offline PoP *cannot* get single-use replay
protection without shared state. The honest SOTA options:

1. **Short, server-signed challenge with embedded expiry** so the offline authorizer can reject
   stale proofs without shared state (bounds the replay window to seconds).
2. **`jti`/nonce single-use cache at the enforcement point** (e.g., the MCP gateway / PEP) where
   shared state *does* exist — strongest, but only at online choke points.
3. **Bind the proof to the full request** (method, URI, body hash) à la WPT/DPoP so a replayed proof
   only authorizes the byte-identical request.

> **Improvement 5.** Treat offline PoP as "bounded-window" and say so in the trust model; add a
> signed-expiry challenge for the offline path and a `jti` replay cache at online PEPs. This is the
> highest-severity gap.

### 6. Revocation — Biscuit gives it to us; we don't use it

Today the only ways to kill a leaked capability token are **root-key rotation** (which invalidates
*every* token for the tenant) or waiting for **expiry**. Expiry alone is insufficient — there is
always a leak-to-expiry window — which is the standard argument for a revocation channel
([Biscuit revocation](https://www.biscuitsec.org/docs/guides/revocation/)). Biscuit already
provides **revocation identifiers**: each block's signature is a unique revocation ID, and revoking
a token revokes it *and everything attenuated from it*; the library lists them and the app maintains
the deny-list. UCAN has an analogous [revocation spec](https://ucan.xyz/revocation/). Clay Seal uses
none of this.

> **Improvement 6.** Record revocation IDs at mint time; check a (small, cacheable) revocation list
> in `authorize_biscuit`; expose a revoke endpoint. Low effort, uses a feature that already exists,
> closes the leaked-token hole without the nuclear key-rotation option. Pairs naturally with the
> short TTLs already in place.

### 7. Attestation — a faithful prototype, not yet SOTA (expected)

`attestation.py` is explicit that it's a **SPIRE stand-in**: the workload presents an RS256-signed
JWT "attestation document" verified against a tenant-registered anchor; the transport is simulated,
the trust decision is real. For a prototype this is reasonable and honestly documented. Gaps vs SOTA
real attestation: (a) RS256 again; (b) **no freshness nonce** on the attestation document, so node
evidence is replayable within its JWT `exp`; (c) no hardware root. SOTA is real SPIRE node/workload
attestation (k8s TokenReview, AWS IID, GCP IIT — the selector types are already modeled) and,
increasingly, **hardware-rooted** node attestation (TPM quote, TEE/confidential-computing evidence,
which the evidence plane's SOTA-2 work already touches). WIMSE's `workload-creds` and
`http-signature` drafts are the upstream to track here too.

> **Improvement 7.** Add an attestation-document nonce/audience binding now (cheap, kills replay);
> plan a real SPIRE integration and a hardware-rooted node-attestation path for production.

### 8. Standards posture — the strategic finding

Each gap above has the same root cause: **L1/L2 hand-rolled mechanisms that IETF standardized in
2025–2026.** Aligning isn't just hygiene — it's interop with the agent ecosystem the receipts layer
wants to plug into:

- **WIMSE** (Workload Identity in Multi-System Environments): WIT, WPT, workload-creds,
  http-signature — the upstream for L1 identity + PoP.
- **Transaction Tokens for Agents** ([draft-oauth-transaction-tokens-for-agents-06](https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/),
  base [draft-ietf-oauth-transaction-tokens-08](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens)):
  propagate identity + authorization through a **call chain** inside a trust domain, with an `act`
  field identifying the agent performing the action. This is the missing link between L2 delegation
  and the L3/L4 **receipt**: a receipt's authority lineage should be expressible as a Txn-Token
  `act` chain, and a Txn-Token is the natural per-request grant the receipt attests after the fact.
- **AuthZEN / MCP authorization / COAZ / AARP** (per [landscape_research.md](landscape_research.md))
  for the decision/approval surface — already on the team's radar.
- Academic frontier: **AIP — Agent Identity Protocol for Verifiable Delegation across MCP and A2A**
  ([arXiv 2603.24775](https://arxiv.org/pdf/2603.24775)) is the current research SOTA for
  cross-protocol verifiable delegation and worth reading before finalizing the delegation shape.

> **Improvement 8 (strategic).** Re-express L1 as a **WIT/WPT profile** and L2 grants as
> **Transaction-Tokens-for-Agents**, keeping Biscuit as the attenuation/offline mechanism *under*
> those standard envelopes. This converts "bespoke and isolated" into "standards-aligned and
> interoperable" and directly feeds the receipt's authority lineage.

---

## Prioritized recommendations

| Priority | Improvement | Effort | Why now |
|----------|-------------|--------|---------|
| **P0** | (5) Bound-window PoP: signed-expiry challenge + `jti` cache at PEPs; document the offline limit | M | Closes the one *security* gap (replayable PoP) |
| **P0** | (6) Biscuit revocation IDs + deny-list + revoke endpoint | S | Real revocation, feature already exists, cheap |
| **P1** | (2) EdDSA for JWT-SVID and PoP; remove RSA PKCS#1 v1.5 | S | Removes legacy crypto; unifies on the Biscuit curve |
| **P1** | (3/4) Key-bound identity (`cnf`) + WPT-shaped, request-bound proof | M | Kills JWT-SVID bearer replay; standard wire format |
| **P2** | (8) WIT/WPT profile + Transaction-Tokens-for-Agents envelope; bind to receipt lineage | L | Interop + the L2→L3/L4 bridge the other merge needs |
| **P2** | (7) Attestation nonce/audience now; real SPIRE + hardware root later | M/L | Replay fix now; production attestation path later |

**Net.** The capability *model* is SOTA; the *plumbing around it* (crypto primitives, PoP freshness,
revocation, bearer identity) is a half-generation behind, and the team is independently building
what WIMSE/DPoP/Transaction-Tokens already specify. P0/P1 are small, high-credibility hardening
wins; P2 is the strategic alignment that makes L1/L2 interoperable and feeds the receipt layer.

---

## References

- IETF WIMSE — [WPT (draft-ietf-wimse-wpt-01)](https://datatracker.ietf.org/doc/draft-ietf-wimse-wpt/),
  [workload-creds](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/),
  [http-signature-03](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-http-signature-03),
  [workload-identity-practices](https://datatracker.ietf.org/doc/html/draft-ietf-wimse-workload-identity-practices)
- IETF OAuth — [Transaction Tokens (draft-08)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-transaction-tokens),
  [Transaction Tokens for Agents (draft-06)](https://datatracker.ietf.org/doc/draft-oauth-transaction-tokens-for-agents/)
- [RFC 9449 — OAuth 2.0 DPoP](https://datatracker.ietf.org/doc/html/rfc9449) ·
  [DPoP explained (WorkOS)](https://workos.com/blog/dpop-rfc-9449-explained)
- SPIFFE — [JWT-SVID spec](https://spiffe.io/docs/latest/spiffe-specs/jwt-svid/) ·
  [#260 DPoP for JWT-SVID](https://github.com/spiffe/spiffe/issues/260) ·
  [SPIFFE compliance deep dive (WIT-SVID)](https://dev.to/kanywst/spiffe-compliance-deep-dive-5e29)
- Biscuit — [revocation guide](https://www.biscuitsec.org/docs/guides/revocation/) ·
  [spec](https://doc.biscuitsec.org/reference/specifications.html) · UCAN — [revocation](https://ucan.xyz/revocation/)
- JWT crypto — [JWT best practices 2026](https://jsoncraft.dev/docs/jwt-best-practices-2026/) ·
  [Curity: EdDSA signatures](https://curity.io/resources/learn/jwt-signatures/)
- [AIP — Agent Identity Protocol for Verifiable Delegation (arXiv 2603.24775)](https://arxiv.org/pdf/2603.24775)
- Internal: [landscape_research.md](landscape_research.md), [open_standard_strategy.md](open_standard_strategy.md),
  [l1_l3l4_boundary.md](l1_l3l4_boundary.md)
</content>
