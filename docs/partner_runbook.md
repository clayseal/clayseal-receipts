# Partner operations runbook

One-page guide for design partner engineering, security, and compliance contacts.

## Roles

| Role | Responsibility |
|------|----------------|
| **Integration engineer** | Wire `AgentWrapper` / `ReceiptedMcpClient`, maintain `config/partner.yaml` |
| **Security** | Review receipt redaction before export; approve retention |
| **Compliance / audit** | Verify receipts via `arctl` or HTTP verifier |

## Escalation

| Severity | Example | Action |
|----------|---------|--------|
| **P1** | Audit chain fails `verify_chain()` in production | Stop auto-actions; preserve `.audit/` and logs; contact vendor |
| **P2** | `arctl doctor --require-prover` fails in prove mode | Fall back to `shadow` mode; file issue with `arctl doctor` output |
| **P3** | HTTP verifier returns unexpected `reasons` | Attach receipt JSON + verifier response; use `arctl verify-bundle` locally to compare |

**Include in every ticket:**

1. `arctl doctor` JSON (or `/health` from verifier)
2. SDK version from receipt `sdk_version`
3. Git tag or Docker image digest (`v0.2.1` recommended)
4. One redacted receipt (see below)

## Data handling

### What to retain (pilot default)

| Artifact | Retention suggestion | Location |
|----------|---------------------|----------|
| Audit SQLite DB | 90 days minimum for pilot | `audit_db` in partner.yaml |
| Receipt JSON exports | Per regulatory need | `receipts/` |
| Policy YAML | Life of deployment + 1 year | `policies/` |

### Redaction before sharing externally

```bash
arctl redact receipts/<proof-id>.json --out receipts/<proof-id>.redacted.json
```

Default redacted paths:

- `certificate.principal.principal_id`
- `certificate.principal.organization`
- `context.input`
- `context.authorization`
- `output.result.transaction_id`

Add custom paths: `arctl redact ... --fields context.input.customer_id`

**Never share** unredacted receipts outside your trust boundary unless contractually allowed.

### Fields safe to share with auditors

- `schema`, `sdk_version`, `execution_proof` (hashes), `verification`
- `policy.commitment`, `policy.name`
- Redacted `audit_record` (seq, hashes, action)

## Verification workflows

### Offline (no network)

```bash
arctl verify-bundle receipts/<id>.json
```

### HTTP verifier (compliance desk)

```bash
docker compose up verifier
curl -s -X POST http://localhost:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -d @receipts/<id>.json
```

Valid response: `"valid": true` with empty `reasons`.

**Shadow mode** receipts always return `"valid": false` (expected — no ZK attached).

## Operating mode playbook

| Mode | When to use | On violation |
|------|-------------|--------------|
| `shadow` | Week 1 instrumentation | Log only |
| `bounded_auto` | Production pilot with guardrails | Force abstain in output |
| `prove` | Demo to regulators / crypto stakeholders | Requires bootstrap + keys |

## Policy changes

1. Scaffold or edit YAML: `python3 scripts/scaffold_policy.py --name my_policy ...`
2. Note new `policy_commitment` printed by scaffold script
3. Update agent certificates / `model_provenance_hash` alignment in partner config
4. Re-run `partner_smoke.sh` before promoting

## Docker-only environments

Partners without local Rust:

```bash
git checkout v0.2.1
docker compose build
docker compose up verifier
```

Run pilot inside container:

```bash
docker compose --profile pilot run --rm pilot
```

## Health checks

| Check | Command |
|-------|---------|
| SDK + keys | `arctl doctor --require-prover` |
| Verifier up | `curl -s http://localhost:8787/health` |
| Full stack | `bash scripts/partner_smoke.sh` |

## Out of scope (pilot)

- Hosted multi-tenant verifier SLA
- X.509 enterprise issuance
- EU AI Act export automation
- 24/7 on-call from vendor

Document agreed support hours in your pilot SOW.
