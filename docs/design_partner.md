# Design partner guide

This guide is for teams integrating Agent Receipts in a **pilot** (fraud MCP, policy receipts, optional ZK). It assumes you are not building on a hosted verifier yet — you run the SDK and CLI in your environment.

## CLI naming

| Command | Role |
|---------|------|
| **`arctl`** | Python SDK tooling (`doctor`, `verify-bundle`, `explain`, `audit-summary`, `replay-check`, `format-bundle`, `export-audit`) |
| **`agent-receipts`** | Rust prover/verifier (`prove-policy`, `setup`, `verify-composed`) |

## What you get

| Artifact | Purpose |
|----------|---------|
| **Audit chain** (SQLite) | Tamper-evident log of every receipted action |
| **Receipt bundle** (JSON) | One action: proof, decision, authority, evidence summary, assurance, verification — shareable with risk/compliance |
| **Policy YAML** | Committed rules (ranges, tools, required fields) bound to `policy_commitment` |
| **Optional ZK** | Halo2 policy-range proofs; composed inference+policy when `mode=prove` |

## Before you ship to a partner

Run the deployment gate:

```bash
bash scripts/partner_preflight.sh
# Production-shaped config:
cp config/partner.production.example.yaml config/partner.yaml
arctl preflight config/partner.yaml --strict
```

Full checklist: [deployment.md](deployment.md).

## 30-minute onboarding

```bash
git clone <repo> && cd agent-receipts
bash scripts/bootstrap.sh          # pip, Rust CLI, proving keys
cp config/partner.example.yaml config/partner.yaml
# Edit partner.yaml: organization, principal_id, model_provenance_hash
python3 examples/partner_pilot.py   # one run + receipt in receipts/
arctl verify-bundle receipts/<uuid>.json
arctl explain receipts/<uuid>.json
```

Receipt bundles include `decision`, `authority`, `evidence` (decision record + summary + obligation rollup), and nested `assurance`. See [decision_model.md](decision_model.md) and [execution_context.md](execution_context.md).

Optional: plug a custom `PolicyEngine` or `reservation_callback` on `AgentWrapper` for budget-aware decisions (`budget_reservation_required` outcome). Sign envelopes with `sign_bundle()` after export; verification checks `signatures[]` when present.

```bash
arctl audit-summary receipts/<uuid>.json
arctl replay-check receipts/<uuid>.json --policy policies/fraud_decision.yaml
```

Full smoke (tests + pilot + verify):

```bash
bash scripts/partner_smoke.sh
```

## Configuration

`config/partner.yaml` (copy from [config/partner.example.yaml](../config/partner.example.yaml)):

| Field | Description |
|-------|-------------|
| `policy_path` | YAML policy (default: fraud pilot) |
| `audit_db` | SQLite audit log path |
| `mode` | `shadow` (default), `recommend`, `bounded_auto`, `prove` |
| `certificate_path` | Optional JSON cert; omit for dev certificate |
| `model_provenance_hash` | Your model/version identifier |
| `prove_composed` | Set `true` with `mode: prove` for EZKL+Halo2 bundle |

Show resolved paths:

```bash
arctl show-config config/partner.yaml
```

## Operating modes (choose one for pilot)

| Mode | Use when |
|------|----------|
| **shadow** | Instrument first — audit + policy checks, no ZK latency |
| **bounded_auto** | Enforce abstain on policy violation in production-like pilots |
| **prove** | Demonstrate cryptographic verification to stakeholders |

Start in **shadow**, move to **prove** only after `arctl doctor --require-prover` passes.

## MCP integration path

1. **Local tools** — `ReceiptedMcpGateway` (in-process handlers)
2. **Live server** — `ReceiptedMcpClient` + stdio/SSE ([mcp_live_server.md](mcp_live_server.md))
3. **Cursor** — `python3 scripts/gen_cursor_mcp.py`

Prove mode on live MCP:

```bash
python3 examples/mcp_live_prove_client.py
```

## Receipt bundle format

Schema: `agent-receipts.receipt-bundle.v1`

```bash
# Export happens in your agent code:
from agentauth.receipts.export import export_run_result, build_receipt_bundle

export_run_result("receipts/tx-1.json", result, certificate=agent.certificate, policy=policy)

# Third party / internal audit:
arctl verify-bundle receipts/tx-1.json
```

Bundle includes: `execution_proof`, `output`, `policy_violations`, `verification`, `certificate`, optional `audit_record` and `policy` metadata.

Export full audit trail:

```bash
arctl export-audit --audit-db .audit/partner.sqlite --out audit/export.jsonl
```

## Integration checklist

- [ ] Pin release: `git checkout v0.2.1` ([RELEASE.md](../RELEASE.md))
- [ ] Run `bash scripts/bootstrap.sh` and `arctl doctor --require-prover` (if using prove mode)
- [ ] Copy and edit `config/partner.yaml`
- [ ] Set `model_provenance_hash` to your deployed model artifact hash
- [ ] Scaffold or align policy: `scripts/scaffold_policy.py` or `policies/fraud_decision.yaml`
- [ ] Wire `AgentWrapper` or `ReceiptedMcpClient` at your agent gateway
- [ ] Export receipt JSON; verify with `arctl verify-bundle` or HTTP `POST /v1/verify`
- [ ] Share redacted receipts only: `arctl redact` ([partner_runbook.md](partner_runbook.md))
- [ ] Agree retention for `audit_db` + `receipts/` with compliance

## Known limitations (set expectations)

- **Dev certificates** only unless you bring your own JSON cert format
- **No hosted verifier** — partners run `agent-receipts` CLI locally
- **Composed proofs** are logically bound (two verifiers), not one recursive SNARK
- **EZKL** optional; stubs work for demos, production pilots should run real setup ([inference_and_composition.md](inference_and_composition.md))
- **Fraud vertical** is the reference policy; general semantic policies are not ZK-proven yet

## Support artifacts to share with us

When reporting issues, attach:

1. Output of `arctl doctor`
2. One redacted `receipts/*.json` bundle
3. `config/partner.yaml` (redact org names if needed)
4. SDK version from bundle `sdk_version` field

## HTTP verifier (compliance desk)

```bash
arctl serve --port 8787
# or: docker compose up verifier
curl -s -X POST http://localhost:8787/v1/verify -H 'Content-Type: application/json' -d @receipts/<id>.json
```

See [http_verifier.md](http_verifier.md).

## Custom policy from your schema

```bash
python3 scripts/scaffold_policy.py \
  --name spend_cap_v1 \
  --required-field decision \
  --required-field amount_usd \
  --range amount_usd:0:10000
```

## Redact before sharing

```bash
arctl redact receipts/<id>.json --out receipts/<id>.redacted.json
```

## Pinned releases

Check out tag **`v0.2.1`** (not floating `main`). See [RELEASE.md](../RELEASE.md) and [CHANGELOG.md](../CHANGELOG.md).

## Docker (no local Rust)

```bash
git checkout v0.2.1
docker compose build && docker compose up verifier
```

## Operations

[partner_runbook.md](partner_runbook.md) — escalation, retention, redaction, health checks.

## Next steps after pilot

- Pin `policy_commitment` in your CI/CD for the model you deploy
- X.509 agent certificates (roadmap) for enterprise PKI

See [roadmap.md](roadmap.md) for milestone tracking.
