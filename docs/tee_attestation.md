# TEE attestation (SOTA-2)

Agent Receipts supports **TEE-hybrid** mode: a hardware attestation quote proves
*where inference ran* (model/enclave identity via PCRs), while a ZK policy proof
can still bind *what policy held* on the attested output.

This is the pragmatic **LLM-scale provenance path** — you attestation-quote a
confidential GPU/CPU enclave instead of ZK-proving a transformer.

## Supported formats

| `tee_quote.format` | Status | Use |
|--------------------|--------|-----|
| `nitro_enclave_v1` | **Verified** | AWS Nitro Enclaves NSM attestation document (COSE Sign1) |
| `tdx_v1` | Stub | Reserved for Intel TDX quotes |

Attach quotes on `execution_proof.bundle.tee_quote`:

```json
{
  "format": "nitro_enclave_v1",
  "quote_b64": "<base64 COSE Sign1 attestation document>",
  "report_data_hash": "sha256:…optional binding…",
  "max_age_seconds": 86400
}
```

Set `attestation_path` to `tee_hybrid` on the execution proof.

## Verification

```python
from agentauth.receipts import verify_tee_quote, TeeQuote, TeeQuoteFormat

result = verify_tee_quote({
    "format": "nitro_enclave_v1",
    "quote_b64": "...",
})
assert result["valid"]
assert result["tee_assurance"] == "tee_attested"
assert result["eat"]["sub"]  # module_id
```

Nitro verification:

1. Decode COSE Sign1 (ES384)
2. Validate attestation document fields + PCR map
3. Verify X.509 chain to [AWS Nitro root CA](../config/certs/aws_nitro_enclaves_root_g1.pem)
4. Verify COSE signature with leaf certificate public key
5. Optionally bind `user_data` to `report_data_hash`

Override root path: `AGENT_RECEIPTS_NITRO_ROOT_PEM=/path/to/root.pem`

## Assurance tiers

| Outcome | `assurance.level` | `assurance.tier` |
|---------|-------------------|------------------|
| Quote verifies | `tee_attested` | `tee_attested` (ordinal 4) |
| Quote missing/invalid | `tee_hybrid_claimed` | `signed` (ordinal 1) |

Receipt assurance blocks also include:

- `tee_verified`: boolean
- `tee_assurance`: `tee_attested` | `tee_hybrid_claimed`
- `eat`: EAT-shaped claim set (`iss`, `sub`, `meas.pcr0`, …)

Threshold example:

```bash
arctl verify-bundle receipt.json --min-assurance-tier tee_attested
```

## RATS / EAT mapping

| RATS role | Agent Receipts component |
|-----------|-------------------------|
| Attester | Agent runtime inside Nitro enclave (NSM issues document) |
| Verifier | `verify_tee_quote` / `verify_receipt_bundle` |
| Relying Party | Partner verifier / compliance consumer |

Verified quotes emit `eat_profile: agent-receipts.eat-tee-v1` claims suitable for
mapping onto RFC 9334 EAT consumers.

## Routing rule (model size)

| Model scale | Inference leg | Policy leg |
|-------------|---------------|------------|
| Small heads (fraud ONNX, classifiers) | EZKL / Halo2 ZK | Halo2 `policy_range_v3` |
| LLM / large models | **TEE quote (`nitro_enclave_v1`)** | ZK or software policy on committed output |
| Mid-size (future) | opML / zkVM research (SOTA-8) | Same |

## Related

- [assurance_taxonomy.md](assurance_taxonomy.md)
- [trust_model.md](trust_model.md)
- [architecture.md](architecture.md) — TEE hybrid path
