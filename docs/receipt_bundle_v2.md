# Receipt Bundle v2

Schema ID: `agent-receipts.receipt-bundle.v2`

The SDK now **defaults to v2** when building receipts. v1 bundles (`agent-receipts.receipt-bundle.v1`) remain supported for load and verify.

## Required sections

- `execution_proof` — cryptographic attestation (unchanged from v1)
- `decision` — outcome, policy satisfaction, violations, obligations, approval state
- `authority` — authority id/version and session binding
- `action` — structured action metadata
- `evidence` — `decision_record`, `summary`, and nested `assurance`

## Optional sections

- `session` — session id and authority version
- `approval` — approval state and metadata
- `budget` — capability budget items and decision budget effects
- `handoff`, `lineage`, `policy`, `audit_record`, `evidence_refs`, `execution_context` — retained for replay and partner workflows

## v1 → v2 changes

| v1 | v2 |
|----|-----|
| top-level `assurance` | `evidence.assurance` |
| top-level `policy_violations` | `decision.violations` |
| top-level `recommended_action` | `decision.recommended_action` |
| top-level `budgets` | `budget.items` |

## API

```python
from agentauth import build_receipt_bundle, migrate_v1_to_v2

# default is v2
bundle = build_receipt_bundle(result, certificate=cert, policy=policy)

# explicit v1 for backward compatibility
v1 = build_receipt_bundle(result, certificate=cert, policy=policy, schema_version="v1")

# upgrade stored v1 bundles without re-running the agent
v2 = migrate_v1_to_v2(v1)
```

NDJSON batch export:

```bash
arctl export-ndjson receipt-a.json receipt-b.json --out receipts.ndjson
```

```python
from agentauth import write_receipts_ndjson, load_receipts_ndjson
```

## Verifier

`verify_receipt_bundle()` accepts both schemas. v2 bundles must include all required sections (including `evidence.summary`). The HTTP verifier `/v1/version` lists both supported schema IDs.

## Design decisions (resolved)

- **Violations** live under `decision.violations`; top-level `policy_violations` is v1-only.
- **Assurance** is nested under `evidence` in v2; explain/verify helpers read either location.
- **`execution_context`** remains an optional convenience section for replay, not a required v2 section.
- **Duplication** between `execution_proof` and `decision` is intentional: proof fields are cryptographically bound; decision block is the human/audit view.

Implementation: `agentauth/receipts/receipt_schema.py`, `export.py`, tests in `python/tests/test_schema_v2.py`.
