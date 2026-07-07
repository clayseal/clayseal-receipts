# Demo sets (D-01 – D-08)

Curated narrative fixtures for partners, investors, and auditors — not scored benchmark corpora.

## Generate

```bash
# All demo sets
python benchmarks/demo/generate.py

# Subset
python benchmarks/demo/generate.py --only D-01,D-08

# Custom output dir
python benchmarks/demo/generate.py --out /tmp/demo-output
```

Requires corpora for ULB/ATIF/BFCL (`scripts/download_benchmark_corpora.sh`). Prove-mode sets (D-02, D-08) need:

```bash
export AGENT_RECEIPTS_ALLOW_STUB=1
cargo build -p clay-seal-receipts-cli --release
```

## Deliverables

| ID | Folder | Contents |
|----|--------|----------|
| D-01 | `output/D-01_quickstart/` | ULB receipt + 5-minute walkthrough |
| D-02 | `output/D-02_mcp_prove/` | Composed prove bundle + live MCP pointer |
| D-03 | `output/D-03_partner_pilot/` | Fixed-amount pilot receipt + story |
| D-04 | `output/D-04_capability_block/` | BFCL allowlist block narrative |
| D-05 | `output/D-05_identity_atif/` | 3 identity-bound ATIF receipts |
| D-06 | `output/D-06_auditor_packet/` | 10-bundle zip + verify commands |
| D-07 | `output/D-07_compliance_ingest/` | ECS JSONL from 5 receipts |
| D-08 | `output/D-08_assurance_ladder/` | shadow / bounded_auto / prove comparison |

`output/manifest.json` lists all generated paths.

See [DATA_EVIDENCE_BACKLOG.md](../DATA_EVIDENCE_BACKLOG.md) for evidence IDs.
