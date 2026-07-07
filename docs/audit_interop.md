# BYO audit & observability (Phase 3 interop surface)

Receipts interoperate with external audit, observability, transparency and
compliance systems through one seam: the `ReceiptExporter` protocol
(`agentauth.core.protocols`), discovered via the `agentauth.receipt_exporters`
entry-point group. Nothing in receipt *building* depends on any exporter; every
exporter is side-effect-only on its destination.

```python
from agentauth.core.plugins import get_plugin

exporter = get_plugin("receipt_exporters", "otel_genai")
exporter.export(bundle)                      # returns delivery metadata
```

| Name | Target | Module |
|---|---|---|
| `otel_genai` | OTel `gen_ai.*` log records over OTLP/HTTP JSON | `exporters/otel_genai.py` |
| `ocsf_ai_operation` | OCSF `ai_operation` API Activity (+ Detection Findings) | `exporters/ocsf.py` |
| `scitt` | Any SCRAPI SCITT Transparency Service | `exporters/scitt_scrapi.py` |
| `vanta` | Vanta Custom Resources (control evidence) | `exporters/vanta.py` |
| `drata` | Drata Custom Connections records | `exporters/drata.py` |

Third-party exporters register under the same entry-point group and become
`get_plugin`-discoverable without touching this repo.

## OTel GenAI (`otel_genai`)

One exporter reaches every OTel-native backend: Datadog, New Relic, Langfuse,
LangSmith, Braintrust and Splunk Observability all ingest `gen_ai.*` semantic
conventions directly. The mapping (`agentauth/receipts/otel.py`) puts tool
calls in `gen_ai.*` and receipt-specific evidence (authority, decision,
assurance, integrity) under `agent_receipts.*` — the honest crosswalk gap.

The gen_ai semconv is still **Development** status upstream, so payloads pin
`GEN_AI_SEMCONV_VERSION` (currently 1.40.0) via OTLP `schemaUrl`. Bump it
deliberately, reviewing the mapping against the semconv release notes.

Configuration: `AGENTAUTH_OTLP_LOGS_ENDPOINT` (or the standard
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT`), plus per-backend auth headers:

```python
OtelGenAiExporter(endpoint="https://http-intake.logs.datadoghq.com/api/v2/logs",
                  headers={"DD-API-KEY": "…"})           # Datadog logs intake
OtelGenAiExporter(endpoint="https://otlp.nr-data.net/v1/logs",
                  headers={"api-key": "…"})              # New Relic OTLP
OtelGenAiExporter(endpoint="https://cloud.langfuse.com/api/public/otel/v1/logs",
                  headers={"Authorization": "Basic …"})  # Langfuse
```

The cleanest production shape is an **OTel Collector** in front (endpoint
`http://collector:4318/v1/logs`) fanning out to backends.

## OCSF (`ocsf_ai_operation`)

Maps each receipt onto OCSF v1.8 (the release that shipped the `ai_operation`
profile):

| Receipt | OCSF |
|---|---|
| every receipt | API Activity (`class_uid` 6003, category 6), profile `ai_operation` |
| tool call | `api.operation`, `api.service.name`, `resources[]` |
| agent | `actor.app_name` / `actor.app_uid`, `src_endpoint` |
| model identity (when known) | `ai_model` (name + provider required by OCSF) |
| deny / step-up / approval-pending | additional Detection Finding (`class_uid` 2004) |
| authority / policy / assurance | `unmapped.agent_receipts.*`, field names aligned with the OWASP Agentic Top-10 decision-log recommendations |

All three event shapes validate with **0 errors / 0 warnings** against the
live `schema.ocsf.io/api/v2/validate` (checked 2026-07-06). Receipts'
delegation/actor-chain model maps onto the OCSF v1.9-dev `delegation` objects
(PRs #1640/#1665) — revisit when v1.9 ships.

SIEM delivery recipes (recipes, not connectors — the events are plain JSON):

- **Splunk HEC**: wrap each event as `{"event": <ocsf_event>, "sourcetype": "ocsf:ai_operation"}` and POST to `https://splunk:8088/services/collector/event` with `Authorization: Splunk <token>`.
- **Datadog Cloud SIEM**: POST the events to `https://http-intake.logs.datadoghq.com/api/v2/logs` (`DD-API-KEY` header); Datadog's OCSF-normalized SQL detections pick them up.
- **Microsoft Sentinel**: use the Logs Ingestion API with a DCR mapping the OCSF fields to your custom table (the legacy HTTP collector retires 2026-09).
- **Google SecOps / Chronicle**: submit via UDM `udmevents:batchCreate`, or land the JSON in GCS and ingest with a feed.

## SCITT / SCRAPI (`scitt`)

`agentauth/receipts/scitt.py` is conformant with the published RFCs — **RFC
9943** (SCITT architecture) and **RFC 9942** (COSE receipts): tagged
COSE_Sign1 statements/receipts, final IANA header labels (`receipts` 394 as an
array, `vds` 395 = RFC9162_SHA256, `vdp` 396), `kid` + CWT Claims in protected
headers, detached-payload Merkle roots. Untagged pre-0.5 envelopes still
verify.

Both SCRAPI directions are implemented (`agentauth/receipts/scrapi.py`):

- **Serve** — the verifier server (`arctl serve`) mounts `POST /entries`
  (201 + COSE Receipt), `GET /entries/{entry_id}` (fresh receipts) and
  `GET /.well-known/scitt-keys` (COSE Key Set). The log is in-process; pin
  `AGENTAUTH_SCITT_SIGNING_KEY_HEX` so receipts stay verifiable across
  restarts, and `AGENTAUTH_SCITT_SERVICE_ID` for the receipt issuer claim.
- **Publish** — the `scitt` exporter signs the bundle's canonical CBOR as a
  Signed Statement and registers it with any SCRAPI service
  (`AGENTAUTH_SCITT_BASE_URL`, statement key via
  `AGENTAUTH_SCITT_STATEMENT_KEY_HEX`), handling 201-direct and 202-poll.
  Interop targets: Azure Code Transparency, DataTrails, self-hosted
  scitt-ccf-ledger — or another Clay Seal verifier.

Live interop against a third-party SCITT service is not yet asserted in CI;
the internal round-trip (sign → register → receipt → verify) is.

## DSSE / in-toto attestations (`agentauth/receipts/intoto.py`)

Receipts wrap into in-toto v1 Statements with the published predicate type
**`https://agentauth.dev/receipt/v1`** inside DSSE envelopes (Ed25519 over the
PAE). The subject digest is the SHA-256 of the bundle's canonical JSON
(`agentauth.core.hash_util`), so stock supply-chain tooling verifies receipts
with no Clay Seal code:

```bash
cosign verify-blob-attestation \
  --type https://agentauth.dev/receipt/v1 \
  --key ed25519.pub --signature receipt.att --check-claims bundle.json
```

Rekor transparency anchoring rides the same tooling rather than a hand-rolled
client: `cosign attest-blob … --rekor-url https://rekor.sigstore.dev` (Rekor
v2 logs the DSSE as a `hashedrekord` over its PAE; keep the bundle — v2 stores
digests, not attestations). For volume, batch: anchor the audit log's signed
checkpoint (see `c2sp.py`) instead of every receipt.

`verify_envelope` also accepts foreign DSSE statements signed with a known
Ed25519 key — e.g. OpenSSF Model Signing (`https://model_signing/signature/v1.0`)
statements as model-provenance evidence. Full Sigstore-chain verification
(Fulcio certs, TUF trust root) stays with `cosign`/`sigstore-python`.

## Attestation verifiers (`agentauth.attestation_verifiers`)

The TEE-evidence seam follows the industry's managed-verifier convergence:
verifiers emit signed JWT/EAT claim sets, so one JWKS-based verifier covers
Azure MAA, Intel Trust Authority (PS384 EAT) and Google Cloud Attestation.

| Name | Evidence | Notes |
|---|---|---|
| `nitro` | AWS Nitro Enclave attestation documents | full COSE + cert-chain validation against the Nitro root CA |
| `eat_jwt` | JWT/EAT tokens from managed verifiers | `AGENTAUTH_ATTESTATION_JWKS_URL` / `_ISSUER` / `_AUDIENCE`; RS/ES/PS algorithms only |

Both raise on invalid evidence and return EAT-shaped claims dicts, making them
interchangeable evidence sources in receipt bundles.

## Compliance platforms (`vanta`, `drata`)

What gets pushed is `receipt_evidence_record()` — the receipt condensed to its
**verification verdict** plus decision/policy metadata. Merkle
inclusion/consistency proofs make the pushed population cryptographically
complete (AT-C 205 IPE), which is the differentiated SOC 2 story: auditors get
system-generated evidence whose completeness is provable, not screenshots.

- **Vanta**: OAuth client-credentials → `PUT` full-state sync to your custom
  connector's resource URL (`AGENTAUTH_VANTA_RESOURCES_URL`, `_CLIENT_ID`,
  `_CLIENT_SECRET`). Author a Custom Test on the pushed records (e.g. "every
  receipt verifies and satisfied policy") to turn them into control evidence.
- **Drata**: Bearer-auth `POST` to
  `/public/custom-connections/{id}/resources/{id}/records`
  (`AGENTAUTH_DRATA_API_KEY`, `_CONNECTION_ID`, `_RESOURCE_ID`).

## EU AI Act mapping

- **Art. 12(1)** — high-risk AI systems must technically allow automatic
  recording of events over their lifetime. Receipts are exactly this record:
  the `eu-ai-act` compliance profile (`compliance/eu-ai-act.yaml`) checks each
  bundle for the Art. 12-relevant fields (system version, input/output
  commitments, decision outcome, human oversight, integrity protection).
- **Art. 26(6)** — *deployers* must retain automatically generated logs for a
  period appropriate to the system's purpose, **at least six months** (subject
  to EU/national law). Configure receipt-store retention to ≥ 6 months by
  default; hash-chained audit records plus consistency receipts let you prove
  the retained window was never rewritten.
- Annex III applicability lands 2027-12-02 (Digital Omnibus timeline); the
  logging duties are the same ones SOC 2 / ISO 42001 auditors already ask for.

Receipt decision-log field naming follows the OWASP Top 10 for Agentic
Applications (2026) recommendations: action classification, authorization
outcome, policy version, approval id, session tagging — see
`unmapped.agent_receipts` in the OCSF exporter and `receipt_evidence_record`.
