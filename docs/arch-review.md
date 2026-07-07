# Clay Seal — Architecture & Production-Readiness Review

**Original review:** 2026-06-20 @ `5dd8121`
**Re-review:** 2026-06-20 @ `e6b19d8` (after remediation commits `5cd3311`, `c00dc4b`, `e6b19d8`)
**Scope:** Full codebase audit across all layers — identity (L1/L2), receipts/evidence plane (L3/L4), Rust ZK/TEE proving core, deployment/operability, and a claims-vs-code verification of the security & SOTA backlogs. Plus whether the in-repo SOTA research should be integrated.

**Method:** Five parallel deep audits, each reading full source and cross-checking the project's own docs against the code. For the re-review, every fix was verified against the actual diff and re-run test suites; the headline ZK soundness fix was re-read line-by-line.

---

## 0. Re-review summary (what changed)

The author addressed the audit in three focused commits. **All P0 findings and most P1 findings are resolved and verified.** The remediation is high quality: the fixes are correct, accompanied by new tests, and the deployment doc now codifies a secure-by-default production profile.

| ID | Finding | Original sev | Status |
|----|---------|:---:|--------|
| C1 | ZK policy circuit range check under-constrained | CRITICAL | ✅ **RESOLVED** (verified, + negative test) |
| H1 | Private keys plaintext-at-rest by default | HIGH | ✅ **RESOLVED** (fail-closed for prod DBs) |
| H2 | Self-declared trust tier gates policy decisions | HIGH | ✅ **RESOLVED** |
| H3 | Receipt bundles / certs unauthenticated by default | HIGH | ✅ **RESOLVED** (signatures now mandatory) |
| H4 | Prover silently no-ops; `full_zk` can mislabel a stub | HIGH | ✅ **RESOLVED** |
| H5 | Systemic "default-insecure" env-gating | HIGH | 🟡 **MOSTLY RESOLVED** (top items now secure-by-default + documented profile) |
| H6 | Node attestation is a simulation | HIGH | ⬜ **OPEN** (known prototype; now documented) |
| H7 | SQLite audit log not concurrency-safe | HIGH | ✅ **RESOLVED** |
| M2 | `bounded_auto` abstain only fired with a `decision` key | MEDIUM | ✅ **RESOLVED** |
| L1 | No CI security scanning; stale root-running container | LOW(op) | ✅ **RESOLVED** |
| M1 | Nova "aggregation" is logical; committed KZG keys unpinned | MEDIUM | ⬜ **OPEN** |
| M3 | Mandate "trusted issuer registry" overstated | MEDIUM | ⬜ **OPEN** |
| M4 | No backend observability / migrations / Postgres | MEDIUM | 🟡 **PARTIAL** (`/health` enriched; Alembic/metrics still open) |
| M5 | Some verification checks presence-gated | MEDIUM | ⬜ **OPEN** |
| M6 | Stub detection label-based; replay tables unpruned | MEDIUM | ⬜ **OPEN** |
| L2 | Dashboard API key in `localStorage` | LOW | ⬜ **OPEN** |
| L3 | Dead non-domain-separated Merkle code; doc path drift | LOW | ⬜ **OPEN** (dead code still present) |
| L4 | No JWT clock-skew leeway; brittle CLI string-parsing | LOW | ⬜ **OPEN** |

**Health baseline (re-verified this review):**

| Check | Original | Now |
|-------|:---:|:---:|
| Python tests | 455 pass | **465 pass, 2 skipped** (+10) |
| Rust `cargo test -p policy-circuit` | 19 pass | **20 pass** (+1 negative soundness test) |
| `cargo check --workspace` | PASS | PASS |
| `ruff check .` | 57 (cosmetic) | 45 (cosmetic) |
| Secrets committed | none | none |

---

## 1. Verdict (updated)

**The architecture was already strong; with this remediation the correctness and trust-default debt that blocked production is largely paid down.** The one genuine ZK soundness bug is fixed and now has a regression test. The pervasive "great mechanisms shipped off" posture has been inverted for the highest-impact controls — unsigned receipts and certificates now fail verification by default, private keys can't be silently persisted in plaintext on a production DB, the policy gate no longer trusts a caller-supplied trust tier, and the prover no longer silently degrades or mislabels stubs as `full_zk`. The audit log is now concurrency-safe, and CI gained real security scanning with a non-root container.

**What remains before "production-ready" is now a smaller, well-understood list, dominated by one structural item and several operability items:**

1. **Attestation is still a simulation (H6)** — the most security-sensitive remaining gap. The trust root is effectively API-key custody until real SPIRE/cloud/hardware attestation lands. This is honestly documented and is genuine engineering work, not a quick fix.
2. **Operability (M4)** — still SQLite-by-default with no migration framework (Alembic) and no backend logging/metrics/tracing. Fine for pilot, not for a multi-tenant identity authority at scale.
3. **Honest-labeling cleanups (M1, M3)** — the Nova/recursive layer should not be described as cryptographic aggregation, and the mandate "trusted issuer registry" is self-binding, not a registry.
4. **Smaller hardening (M5, M6, L2–L4)** — presence-gated checks, label-only stub detection, unpruned replay tables, dashboard credential storage, dead crypto code, clock-skew.

This is now a **credible, well-engineered pilot with a clean punch-list to GA**, rather than a strong design with foundational gaps.

---

## 2. Resolved findings — verification detail

**C1 — ZK range under-constraint → FIXED (re-read line-by-line).**
`crates/clay-seal-receipts-policy-circuit/src/circuit.rs`: `assign_diff` now takes `&AssignedCell` for both operands and uses `lhs.copy_advice(...)` / `rhs.copy_advice(...)` to bind the range-check cells to the instance-bound `score_cell`/`min_cell`/`max_cell` — exactly the pattern the confidential circuit already used. A new negative test, `mock_prover_rejects_split_public_range_witnesses`, constructs a circuit where the public score (`SCALE`) differs from the range-gate score (`SCALE/4`) and asserts `MockProver::verify()` fails. The range gate no longer floats free of the public inputs. **Soundness defect closed and regression-guarded.**

**H1 — plaintext keys → FIXED (fail-closed).**
`agentauth/backend/secret_encryption.py`: new `secret_encryption_required()` returns true for any non-SQLite DB (or when `AGENTAUTH_REQUIRE_SECRET_ENCRYPTION` is set), and `validate_secret_encryption_config()` (called at app startup in `main.py`) **raises and refuses to boot** if encryption is required but no provider is configured. `decrypt_secret`/`decrypt_private_pem`/`decrypt_private_hex` now **refuse to load plaintext** when encryption is enabled (closes the downgrade/tamper gap). `/health` reports `secret_encryption.{enabled,required}`. *Residual (acceptable):* the default local SQLite dev DB still stores plaintext — but it's now visible and a production DB cannot.

**H2 — self-declared trust tier → FIXED.**
`agentauth/receipts/policy_engine.py`: new `_effective_authority_trust_tier()` derives the tier from *verified* evidence. A new `evidence_verified` flag (in `authority_binding.py` / `runtime.py`) is set **only** on the `from_agentauth_credential` path. A declared tier above `SIGNED` without `evidence_verified` is rejected with an explicit issue; sender-constrained / workload-attested tiers are only credited when the corroborating evidence fields are present and verified. A caller can no longer assert `zk_execution_proved` to pass a high-tier policy.

**H3 — unauthenticated bundles/certs → FIXED (mandatory by default).**
`export.py`: new `AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES` defaults to required; an unsigned bundle now appends a `SIGNATURE_INVALID` issue and fails (`export.py:987-1003`). `certificate.py`: `AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE` default flipped `"1"→"0"`, so unsigned certs are rejected unless an explicit dev override is set.

**H4 — silent prover no-op / mislabeled stub → FIXED.**
`wrapper.py`: new `_strict_prover_required()` raises `RuntimeError` if a requested policy/inference/composed proof isn't produced in `prove`/`bounded_auto` modes — no more silent degradation. A new guard downgrades `attestation_path` from `FULL_ZK` to `SHADOW` if any attached sub-proof is a stub. Prove-side stub default flipped `"1"→"0"` in `compose.py` and `inference.py`.

**H5 — systemic default-insecure → MOSTLY RESOLVED.**
The high-impact controls are now secure-by-default (bundle signatures required, unsigned certs rejected, key encryption enforced for prod DBs, `ALLOW_UNSIGNED_CHECKPOINT` defaults off, `REQUIRE_MANDATE_FOR_BUDGETS` defaults on). `docs/deployment.md` adds a production-hardening table + an explicit "do not set these in production" dev-override list. *Residual (reasonable):* witness quorum (`REQUIRED_AUDIT_WITNESSES`) and checkpoint signer-trust remain opt-in — but these *require external infrastructure* (you can't enforce a quorum with no configured witnesses), and the verifier still refuses non-local binds without an API key. These are now documented operational choices rather than silent gaps.

**H7 — audit log concurrency → FIXED.**
`audit.py`: connection opened with `timeout=30.0, isolation_level=None, check_same_thread=False`; `PRAGMA journal_mode=WAL` + `PRAGMA busy_timeout=30000`; a `threading.RLock` guards operations; `append` runs inside `BEGIN IMMEDIATE` (takes the write lock before reading the tip), eliminating the two-writers-same-`prev_hash` forked-chain race. New transparency tests added.

**M2 — `bounded_auto` abstain → FIXED.**
`wrapper.py`: both the policy-violation and execution-gate paths now call `_blocked_output()` **unconditionally** (no `if "decision" in output` guard). Violating output is replaced with `{"decision":"abstain","abstain_reason":...,"blocked":true,"original_output_hash":...}` regardless of the tool's output schema.

**L1 — CI / container → FIXED.**
`.github/workflows/ci.yml` gains a `security` job: `pip-audit`, `cargo audit --deny warnings`, `npm audit --audit-level=high`, gitleaks secret scan, and a Trivy config scan with `exit-code: 1` on HIGH/CRITICAL. `Dockerfile` now copies `agentauth/` (not the stale `python/` layout), installs `.[server,mcp,verifier]` (drops `dev`), creates a system user, and runs as **non-root**. *Residual:* whether these jobs are *required* status checks is a GitHub branch-protection setting not visible in-repo — confirm they gate merges.

---

## 3. Remaining open findings (the punch-list to GA)

**H6 — Node/workload attestation is a simulation (OPEN, highest remaining risk).**
`agentauth/backend/attestation.py` still verifies an RS256 JWT signed by a tenant-registered key rather than performing a live TokenReview / AWS IID / GCP metadata check. Anyone with a tenant API key can register an attestor and self-issue any registered identity, so the trust root is API-key custody. Production SPIRE manifests exist under `identity/` but aren't wired to the backend. Honestly documented (`docs/l1_l2_hardening.md` updated). **Action:** integrate real SPIRE/cloud/hardware attestation; gate attestor registration behind stronger-than-API-key admin authz; add an attestation-document nonce to kill replay.

**M1 — Nova/recursive composition is logical, not cryptographic; committed KZG keys unpinned (OPEN).**
`crates/clay-seal-receipts-composed/src/recursive.rs`, `…-session/src/fold.rs`: the Nova step circuits allocate step elements as free witnesses; the real security still comes from the plaintext software re-checks. Honest in code comments, but should not be marketed as recursive proof aggregation. Multi-MB Nova `pp`/`pk`/`vk` (a KZG trusted-setup component) remain committed to git and are deserialized without pinning `pp` to a known-good digest. **Action:** pin/regenerate the SRS; stop describing the Nova layer as cryptographic aggregation until step inputs are constrained.

**M3 — Mandate "trusted issuer registry" overstated (OPEN).**
`mandate.py:127-136` performs *self-binding* (issuer string must equal the signer's own key), not registry-based issuer trust. **Action:** add a real trusted-issuer registry, or rename the claim.

**M4 — Operability: migrations, observability, datastore (PARTIAL).**
`/health` is now richer, but the backend still has no structured logging/metrics/tracing and no `/ready`; schema is managed by `create_all` + a hand-rolled `ADD COLUMN` loop (no Alembic); default DB is SQLite. **Action:** adopt Alembic + require Postgres for production; add structured logging, `/ready`, and metrics — fold into the OTel GenAI SOTA item (§5).

**M5 — Presence-gated verification checks (OPEN).**
The `decision.policy_satisfied == proof.policy_satisfied` check (`export.py:763`) and `model_provenance_hash` binding still skip when the section/blob is absent rather than being required for the relevant tiers.

**M6 — Label-only stub detection; unpruned replay tables (OPEN).**
Stub rejection still keys on a self-declared `attestation:"stub"` label (no trusted `verification_key_id` allowlist); the attestation `jti` and PoP challenge tables are never pruned (unbounded growth; freshness must stay independently enforced if cleanup is ever added).

**L2–L4 (OPEN).** Dashboard still stores the tenant API key in `localStorage` (`dashboard/src/auth/AuthContext.tsx:30`); the dead, non-domain-separated Merkle implementation still lingers in `audit.py:50-180` (crypto foot-gun, unused — should be deleted); no JWT `leeway`; `compose.verify_composed` still decides validity by string-matching CLI stdout.

---

## 4. Genuine strengths (preserved)

These held up under skeptical audit and remain true:

- **RFC 6962 Merkle math is correct and domain-separated** (`c2sp.py`); inclusion/consistency proofs verify against RFC vectors. (Note: a *second, dead* non-domain-separated copy still lingers in `audit.py` — L3.)
- **The witness protocol is real anti-equivocation** (refuses to co-sign non-append-only extensions).
- **The Nitro TEE verifier is REAL** — full COSE_Sign1 ES384, cert-chain to a pinned AWS root, PCR/report-data binding — *stronger than the SOTA docs admit*. TDX is honestly hard-rejected.
- **The confidential policy circuit is correctly constrained** — and the plain circuit now matches it (C1 fix).
- **RISC Zero zkVM integration is genuine** when the toolchain is present.
- **AP2 mandate binding + decision/authority modeling** are real and ahead of peers.
- **API keys: PBKDF2-HMAC-SHA256 (200k) + constant-time compare**; default-deny Biscuit authorizer; request-bound, single-use PoP.
- **465 passing Python tests + 20 Rust tests + sophisticated coverage tooling** — and the remediation added regression tests for the fixes.
- **Unusually honest, current self-assessment docs** — a real asset, now backed by a documented production-hardening profile.

---

## 5. SOTA documentation — should we integrate it? (updated guidance)

The in-repo SOTA corpus (`docs/state_of_the_art.md`, `combined_corpus_sota_review.md`, `l1_l2_sota_assessment.md`, `sota_backlog.md`) is excellent and current; the team already executed SOTA-1…10. With the correctness/default-posture debt now largely paid, the path is clearer. My recommended sequence for the *remaining* SOTA proposals:

1. **(E) OpenTelemetry GenAI semconv alignment — do this next.** It is both a SOTA item and the fix for the backend-observability gap (M4). Aligning the `execution_context` capture schema to OTel GenAI makes receipts drop into existing SIEM pipelines *and* makes the service operable. High value, low crypto risk.
2. **(A) SCITT + COSE Receipts envelope.** Highest strategic leverage: converts strong-but-bespoke receipts into interoperable standard ones and folds in the transparency-log work. The Merkle tree is already RFC-6962-correct, so this is mostly re-encoding to COSE_Sign1/CBOR. The earlier rationale to "make signatures mandatory during this migration" is now moot — signatures are already mandatory (H3) — so this is cleaner to land.
3. **(C) SP1/Plonky3 zkVM port.** ~5× faster + ed25519 precompile. **Now unblocked** by the C1 fix (the circuit it would port is sound). Treat as a performance/maintenance bet, not urgent.
4. **(F) WIMSE WIT/WPT + Transaction-Tokens, (B2) tile-based static log.** Sound longer-term interop bets; lower urgency.

**Do NOT prioritize** Poseidon2/Monolith standalone (correctly folded into the SP1 track — no Halo2 Poseidon2 chip exists).

**Sequencing note (updated):** the original review cautioned that standards adoption was premature relative to correctness/safety debt. That debt is now mostly cleared, so SCITT/OTel adoption is appropriately timed. The one thing that should still precede a "trust us, it's attested" GA claim is **real attestation (H6)** — interop with SCITT is less meaningful if the identity it carries is self-asserted.

---

## 6. Prioritized path to production (updated)

**P0 — Correctness & trust:** ✅ **Complete.** (C1, H1–H4, H7, M2, and the H5 core all resolved and tested.)

**P1 — Trust model & honesty:**
1. Real attestation path (SPIRE/cloud/hardware) or keep the explicit documented caveat until then (H6).
2. Stop over-claiming Nova aggregation; pin/regenerate KZG keys (M1).
3. Real trusted-issuer registry or rename the mandate claim (M3).
4. Make presence-gated verification checks required for their tiers (M5); add a trusted `verification_key_id` allowlist + replay-table pruning (M6).

**P2 — Operability:**
5. Alembic + Postgres for production; remove the `ADD COLUMN` hack (M4).
6. Backend structured logging, `/ready`, metrics — implement via the **OTel GenAI** SOTA item (M4 + SOTA-E).
7. Confirm the new CI `security` job is a *required* merge gate; move the dashboard API key off `localStorage` + add CSP (L2); delete the dead Merkle code (L3).

**P3 — Strategic SOTA / interop:**
8. SCITT + COSE receipt envelope; then WIMSE/Txn-Tokens, tile-based log, SP1 port.

---

## 7. Bottom line (updated)

The remediation is **correct, well-tested, and squarely on target** — it closed the one real ZK soundness bug (with a regression test), inverted the default-insecure posture for every high-impact control, made the audit log concurrency-safe, and added real supply-chain scanning and a hardened container. The project has moved from "strong architecture, foundational gaps" to "credible pilot, clean punch-list." The remaining work is dominated by **real attestation (H6)** and **operability (migrations/observability/Postgres, M4)**, plus a few honest-labeling and hardening cleanups. Land real attestation and the OTel/Postgres operability layer, and this is GA-grade infrastructure for a category it is genuinely helping define.
