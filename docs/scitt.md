# SCITT-aligned receipts (SOTA-11)

Re-expresses our receipts in the IETF **SCITT** model so they verify under an adopted
standard, not just our JSON verifier. See [combined_corpus_sota_review.md](combined_corpus_sota_review.md) §A.

## Model

| SCITT term | Ours |
|------------|------|
| **Signed Statement** | a receipt (claim) wrapped as a **COSE_Sign1** (EdDSA) |
| **Transparency Service** | the audit log / `TransparencyService` over an RFC 6962 Merkle tree |
| **Receipt** | a **COSE_Sign1** carrying an **RFC 9162 inclusion proof**, signed over the Merkle root |
| **Transparent Statement** | the Signed Statement with its Receipt embedded in the COSE unprotected header |

Implemented in [`agentauth/receipts/scitt.py`](../agentauth/receipts/scitt.py), built on the
standards-correct RFC 6962 hashing in [`c2sp.py`](../agentauth/receipts/c2sp.py). COSE_Sign1
framing matches the Nitro path (`tee_nitro.py`): untagged 4-element array,
`Sig_structure = ["Signature1", protected, external_aad, payload]`.

## Usage

```python
from agentauth.receipts import scitt
from agentauth.receipts.signing import generate_keypair

issuer_key = generate_keypair()
stmt = scitt.sign_receipt_bundle(bundle, issuer_key, issuer="acme.ai", subject="agent-42")

ts = scitt.TransparencyService(generate_keypair(), service_id="agent-receipts.local/log")
receipt = ts.register(stmt)                       # COSE Receipt (RFC 9162 inclusion proof)
assert scitt.verify_receipt(stmt, receipt, ts.public_key)

transparent = scitt.transparent_statement(stmt, receipt)   # statement + receipt in one COSE envelope
```

`verify_receipt` reconstructs the RFC 6962 root from the receipt's inclusion proof + the statement's
leaf hash, then checks the service's COSE_Sign1 signature over that root — so it proves *this
statement is in the log the service signed*, with no access to our JSON verifier.

## The live audit log as the Transparency Service

The real audit log issues COSE Receipts for its own records — the SCITT verifiable data structure
*is* the audit log's RFC 6962 tree:

```python
receipt = chain.scitt_receipt(record.record_hash, service_id="agent-receipts.local/log")
assert scitt.verify_receipt(bytes.fromhex(record.record_hash), receipt, chain.signing_key.public_key)

# append-only proof between two checkpoints
cons = chain.scitt_consistency_receipt(old_size, service_id="agent-receipts.local/log")
assert scitt.verify_consistency_receipt(cons, trusted_old_root, chain.signing_key.public_key)
```

`verify_consistency_receipt` reconstructs the new root from the proof + a trusted earlier root and
checks the service's signature over it, so a rewritten history fails.

## Usage (bundles)

When exporting with `build_receipt_bundle(..., scitt_issuer_key=..., audit_chain=...)`, the
bundle gains a `scitt` section:

- `signed_statement` — COSE_Sign1 over the canonical CBOR of the bundle (excluding `scitt`)
- `audit_inclusion_receipt` — COSE Receipt that the `audit_record.record_hash` is in the log
- `c2sp_checkpoint` — C2SP signed-note over the same RFC 6962 root
- `confidential` (optional) — HPKE-sealed CBOR for recipient-only viewing

`verify_receipt_bundle()` validates the SCITT section when present. Write canonical CBOR with
`arctl format-bundle --cbor receipt.json`.

## Status & limits

- **Done:** Signed Statements, COSE Receipts (RFC 9162 **inclusion** + **consistency** proofs),
  transparent statements, a standalone `TransparencyService`, the live `AuditChain` wired as
  the Transparency Service, **bundle integration** (`scitt` section in receipt bundles,
  CBOR-canonical artifacts, HPKE confidential payloads, `verify_receipt_bundle` SCITT checks),
  and 16+ tests across `test_scitt.py` and `test_scitt_bundle.py`.
- **Header labels** track the current drafts as named constants in `scitt.py`; pin to final
  IANA values when the drafts publish.
- **Interop:** internal round-trip and third-party-style tile monitor verification are tested;
  live interop with an external SCITT reference implementation is optional follow-up.
