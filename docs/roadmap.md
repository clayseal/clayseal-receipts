# Roadmap

Status markers: `[ ]` not started · `[>]` **being worked on** (do not pick up) · `[~]` partial · `[x]` done. See [l3_l4_backlog.md](l3_l4_backlog.md#status-markers).

## Milestone 0 — Scaffold

- [x] Repo layout: Rust core + Python SDK
- [x] `Policy`, `AgentCertificate`, `ExecutionProof`, `AuditChain`
- [x] Shadow-mode `AgentWrapper` demo
- [x] CI (Rust + Python on push)

## Milestone 1 — Verifiable structural policies

- [x] Halo2 `policy_range_v1` circuit (in-circuit `min + diff = score` and `score + diff = max`)
- [x] Halo2 `policy_range_v2` — binds output_hash and policy_commitment as public inputs
- [x] Proof bytes attached in `prove` mode
- [x] Local verifier CLI (`agent-receipts verify-policy`)
- [x] Bit-decomposed range witnesses (24-bit)
- [x] Halo2 `policy_range_v3` — in-circuit required-field presence mask (up to 8 fields)

## Milestone 2 — MCP integration

- [x] Wrap MCP tool calls as `action` + authorization context
- [x] Biscuit capability enforcement for MCP tools in `bounded_auto`
- [x] Delegation tokens with monotonic scope reduction
- [x] Optional `mcp` SDK session bridge (`mcp_bridge.wrap_mcp_session`)
- [x] Live stdio MCP fraud server (`agentauth.receipts.mcp_server`, `ReceiptedMcpClient`)
- [x] SSE + streamable HTTP transports; Cursor `mcp.json` generator
- [x] `prove` + `prove_composed` on live MCP (`mcp_live_prove_client.py`)

## Milestone 2b — Dynamic sandbox + action monitoring

- [x] `SessionActionMonitor` + heuristic suspiciousness signal — [l2_l3_sandbox_monitor_backlog.md](l2_l3_sandbox_monitor_backlog.md) SM-1–SM-5
- [x] `allow_with_review` decision outcome + policy `monitoring` block
- [x] Mandate → `resource_scope` compiler (SM-6)
- [x] ML anomaly baseline on ATIF corpus (SM-9)
- [x] Runtime egress sandbox + Devin gate unification (SM-8, RT-*)

## Milestone 3 — Inference attestation

- [x] EZKL export path for a small ONNX fraud head (`circuits/fraud_head`, `scripts/`)
- [x] Logical composition: inference ∪ policy (`ComposedProofEnvelope`, `verify-composed`)
- [ ] Single recursive SNARK across EZKL + Halo2 (research)
- [x] TEE quote verification for AWS Nitro (`nitro_enclave_v1`) with EAT claims; TDX stub remains

## Design partner readiness

- [x] Partner YAML config (`config/partner.example.yaml`)
- [x] Receipt bundle export + `verify-bundle` CLI
- [x] `arctl doctor` environment diagnostics
- [x] `bootstrap.sh` / `partner_smoke.sh` scripts
- [x] [design_partner.md](design_partner.md) onboarding guide
- [x] HTTP verifier (`arctl serve`, `POST /v1/verify`) — [http_verifier.md](http_verifier.md)
- [x] [partner_runbook.md](partner_runbook.md) (escalation, redaction, retention)
- [x] Pinned release `v0.2.0` — [RELEASE.md](../RELEASE.md), [CHANGELOG.md](../CHANGELOG.md)
- [x] `scripts/scaffold_policy.py` for custom policies
- [x] Docker image + `docker-compose.yml`
- [x] Deployment hardening (preflight, verifier auth, cert persist) — [deployment.md](deployment.md)
- [ ] Partner-facing SLA / commercial support tier

## Milestone 4 — Commercial

- [ ] X.509 custom OIDs for agent fields
- [ ] Cloud verification key registry
- [ ] EU AI Act structured compliance export

## Detailed lower-layer backlog

- [x] L4/L3 implementation backlog — [l3_l4_backlog.md](l3_l4_backlog.md) *(L3/L4 foundation complete; ledger/TEE research items remain)*
- [x] L2/L3 sandbox + monitoring — [l2_l3_sandbox_monitor_backlog.md](l2_l3_sandbox_monitor_backlog.md) *(SM-1–SM-25 feature tickets complete; research items in footnotes)*
