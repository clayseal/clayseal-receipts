# HTTP verifier

Minimal service for compliance teams to verify receipt bundles without installing Rust or `arctl`.

## Start locally

```bash
pip install -e ".[verifier]"
arctl serve --host 127.0.0.1 --port 8787
```

Or Docker:

```bash
docker compose up verifier
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness (no auth) |
| `GET` | `/ready` | Readiness; 503 if prover required but missing |
| `GET` | `/v1/version` | Verifier + supported receipt schemas |
| `POST` | `/v1/verify` | Body: receipt bundle JSON. Optional query: `min_assurance_tier=<tier>` |

## Authentication (recommended)

```bash
export AGENT_RECEIPTS_VERIFIER_API_KEY="$(openssl rand -hex 32)"
arctl serve
curl -H "X-API-Key: $AGENT_RECEIPTS_VERIFIER_API_KEY" ...
```

Public without key: `/health`, `/ready`, `/v1/version`.

## Verify example

```bash
curl -s -X POST http://localhost:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -d @receipts/<proof-id>.json | jq .
```

Response:

```json
{
  "valid": true,
  "reasons": [],
  "cryptographic": { "valid": true, "reasons": [] },
  "schema": "clay-seal-receipts.receipt-bundle.v1",
  "proof_id": "...",
  "sdk_version": "0.2.1",
  "verifier_version": "0.2.1"
}
```

Optional tier policy (`?min_assurance_tier=signed`): verification fails with
`assurance_threshold_not_met` when the receipt is below the required trust tier.
See [assurance_taxonomy.md](assurance_taxonomy.md).

Shadow-mode receipts return `"valid": false` with reasons mentioning shadow mode — expected when ZK proofs were not generated.

## Trusted signer policy

The verifier requires an envelope signature by default. Configure an explicit trusted
signer policy before expecting `valid: true`:

```bash
export AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS="<ed25519-public-key-hex>"
# or:
export AGENT_RECEIPTS_TRUSTED_SIGNER_KEY_IDS="<signer-key-id>"
```

Unsigned bundles fail with `signature_invalid`. Signed bundles without one of those
settings remain cryptographically signed but fail trust validation with a reason
indicating that no trusted signer policy was configured.

For local demos only:

```bash
export AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=0
export AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE=1
```

## Security notes (pilot)

- No authentication on `/v1/verify` by default — deploy behind your API gateway or VPC
- `valid: true` also requires a trusted receipt signer and a trusted certificate issuer
- Do not expose publicly without rate limiting and TLS termination
- POST only receipt bundles already redacted if they leave your trust zone

See [partner_runbook.md](partner_runbook.md) for redaction and retention.
