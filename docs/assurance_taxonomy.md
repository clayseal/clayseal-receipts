# Assurance taxonomy (SOTA-3)

Agent Receipts exposes an **ordered trust scale** so evidence consumers can threshold
verification (`require ≥ tee_attested`) and map receipts onto standard attestation
vocabulary ([RFC 9334 RATS](https://www.rfc-editor.org/info/rfc9334)).

Scale identifier: `agent-receipts.trust-tier.v1`

## Ordered tiers (low → high)

| Ordinal | Tier | Meaning |
|--------:|------|---------|
| 0 | `declared` | Operator logged the action; no envelope signature or crypto proof |
| 1 | `signed` | Ed25519-signed receipt envelope and/or unverified TEE claim |
| 2 | `sender_constrained` | Token bound to a proof-of-possession key (future OAuth/DPoP profile) |
| 3 | `workload_attested` | Workload identity attested (e.g. SPIFFE JWT-SVID from L1) |
| 4 | `tee_attested` | AWS Nitro (or future TDX) quote verified via COSE + chain |
| 5 | `zk_policy_proved` | Halo2 policy circuit satisfied with output/policy binding |
| 6 | `zk_execution_proved` | Composed inference + policy proof verified |

Higher ordinals strictly imply stronger evidence. A consumer requiring tier `N` accepts
receipts at tier `N` or above.

## Implementation levels → tiers

Receipt `assurance.level` is the implementation label; `assurance.tier` is the portable scale.

| `assurance.level` | `assurance.tier` | Notes |
|-------------------|------------------|-------|
| `shadow` | `declared` | Default dev / shadow mode |
| `operator_signed` | `signed` | Signed envelope without ZK |
| `tee_hybrid_claimed` | `signed` | TEE path asserted; quote not verified |
| `tee_attested` | `tee_attested` | Nitro COSE document verified against AWS root CA |
| `policy_proved` | `zk_policy_proved` | Policy Halo2 proof present |
| `composed_proved` | `zk_execution_proved` | Inference + policy composed proof |

## RATS role mapping

| Agent Receipts component | RATS role | Responsibility |
|--------------------------|-----------|----------------|
| Agent / prover runtime | **Attester** | Produce execution evidence, proofs, signed receipts |
| `verify_receipt_bundle` / HTTP `/v1/verify` | **Verifier** | Validate proofs, signatures, schema, assurance tier |
| Partner SIEM / compliance tool | **Relying Party** | Consume verification result; enforce tier policy |

### Receipt fields as attestation claims (EAT-shaped)

| Receipt field | EAT-like claim |
|---------------|----------------|
| `assurance.tier` / `assurance.tier_ordinal` | Overall evidence strength |
| `assurance.attestation_path` | Mechanism (`shadow`, `full_zk`, `tee_hybrid`) |
| `execution_proof.policy_commitment` | Policy binding |
| `execution_proof.output_hash` | Output commitment |
| `evidence.summary.has_policy_proof` | Policy proof present |
| `signatures[]` | Envelope integrity (Attester signature) |

Full EAT encoding is future work; the ordinal scale is stable for programmatic thresholds.

## Verifier thresholding

CLI:

```bash
arctl verify-bundle receipt.json --min-assurance-tier signed
arctl verify-bundle receipt.json --min-assurance-tier zk_policy_proved
```

HTTP verifier (`POST /v1/verify?min_assurance_tier=signed`):

```bash
curl -s -X POST 'http://localhost:8787/v1/verify?min_assurance_tier=signed' \
  -H 'Content-Type: application/json' \
  -d @receipt.json
```

When the receipt is cryptographically valid but below the required tier, verification returns
`valid: false` with issue code `assurance_threshold_not_met`. The `assurance` block includes
`required_tier`, `required_tier_ordinal`, and `meets_minimum`.

Python:

```python
from agentauth.receipts import meets_assurance_threshold, TrustTier

meets_assurance_threshold("shadow", TrustTier.SIGNED)  # False
meets_assurance_threshold("policy_proved", "zk_policy_proved")  # True
```

## Related docs

- [trust_model.md](trust_model.md) — threat model and capability matrix
- [state_of_the_art.md](state_of_the_art.md) — gap analysis motivating this taxonomy
- [sota_backlog.md](sota_backlog.md) — SOTA-2 delivered (`docs/tee_attestation.md`)
