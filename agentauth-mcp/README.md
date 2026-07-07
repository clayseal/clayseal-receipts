# agentauth-mcp — the AgentAuth gate as an MCP server

An authorization gate for autonomous coding agents (Devin), exposed over MCP. It
integrates the **full agent-receipts stack** behind four tools and a CI merge
gate, so a closed agent you cannot modify is held to a human-signed scope.

```
Devin ──MCP/ngrok──▶ agentauth-gate (this server)
                       L1 identity      AgentAuth.identify  → JWT-SVID
                       L2 capability     Biscuit (PoP)       → session.authorize
                       L3 receipts       AgentWrapper.record → ExecutionProof + audit chain
                       L4 proof path     auto shadow/prove   → prove when Rust CLI exists
                     ─────────────────────────────────────────────────────────
                     embedded AgentAuth backend (in-process, throwaway sqlite)
```

## The four tools (session lifecycle)

1. **`begin_authorized_session(issue_ref, agent_actor)`** — issues a task-scoped
   identity + Biscuit capability grant derived from the human-signed mandate;
   returns an opaque `session_token` and the authoritative task briefing. The
   briefing describes the task and the rules — it does **not** list scope paths.
   **Start here.**
2. **`authorize_action(session_token, resource, action)`** — capability check
   (proof-of-possession) for one file change; on allow, records a Halo2
   ZK-proven, gate-signed receipt. `resource` is `repo:<path>`.
3. **`finalize_for_pull_request(session_token)`** — aggregates the session's
   receipts into one signed bundle to commit to the PR branch for CI.

Scope lives **entirely in the capability token** — the mandate's scope *is* a
signed list of `{resource, action}` grants, with no allow/deny path list and no
diff logic. The agent is never shown which files it may touch; it discovers scope
only by calling `authorize_action` and getting allow/deny back from the token, so
files like `swe_triage/auth.py` / `secrets.json` are denied by the token itself.

## Connect it to Devin (STDIO — recommended)

STDIO is the default transport. Devin launches the server as a subprocess and
talks JSON-RPC over stdin/stdout — **no ports, no ngrok, no tunnel collisions**,
and any number of MCP servers run side by side. One-time setup:

```bash
cd agentauth-mcp
uv venv --python 3.12 .venv
uv pip install -e . -e '..[identity,mcp,server,verifier]'
.venv/bin/python setup_mandate.py     # generate the signed mandate + keys
```

In Devin: **Settings → Connections → MCP servers → Add a custom MCP**, Transport
**STDIO**:

```json
{
  "transport": "STDIO",
  "command": "/absolute/path/to/agentauth-receipts/agentauth-mcp/.venv/bin/python",
  "args": ["/absolute/path/to/agentauth-receipts/agentauth-mcp/server.py"]
}
```

Substitute your checkout path (or set `AGENTAUTH_MCP_PYTHON` when running `tests/test_stdio.py`).

By default the gate uses `AGENTAUTH_MCP_RECEIPT_MODE=prove` when
`target/release/agent-receipts` exists, otherwise it uses `shadow` so local stdio
smokes still authorize and write receipts. Set `AGENTAUTH_MCP_RECEIPT_MODE=prove`
in production/CI to require the Rust proof path.

The old checked-in poisoned `mcp-lab/` fixture was removed from this launch repo.
If you keep a separate lab checkout, add it as its own STDIO server; otherwise
run only the `agentauth-mcp` gate connection.

Then tell Devin (Knowledge/playbook): *"Use the agentauth-gate connection. Call
begin_authorized_session first, authorize_action before each file edit, and
finalize_for_pull_request before opening a PR; commit the returned receipt."*

> ⚠️ **Where the STDIO command runs.** Devin executes `command` in *its* runtime.
> If you use **Devin CLI / a local runtime on this machine**, the absolute
> `.venv/bin/python` paths above work as-is. If you use **cloud Devin**, those
> laptop paths don't exist in Devin's VM — publish the servers (`pip`/`uvx`/a git
> install) or run them in Devin's workspace and point `command`/`args` there. For
> the gate specifically, running inside the agent's own VM weakens it (the agent
> could tamper with its own gate); the CI receipt-gate remains the external
> enforcement regardless. STDIO note: the lab's `/control/*` HTTP arming plane is
> unavailable over stdio — use `--arm-at-start` or `--auto-arm-after N`.

### Optional: remote / HTTP transport (ngrok)

```bash
./run.sh    # forces AGENTAUTH_MCP_TRANSPORT=streamable-http, serves + ngrok
```

Then add it in Devin with Transport **HTTP**, URL `<ngrok-https-url>/mcp`, Auth
**None**. On ngrok's free plan you get one reserved domain / one agent session,
so exposing two HTTP servers at once needs two domains (paid) or two agent
sessions — which is exactly why STDIO is preferred here.

## The hard layer: CI receipt-gate

The tool descriptions persuade; the CI gate enforces. In the gated repo,
`.github/workflows/receipt-gate.yml` runs `.github/scripts/verify_pr_receipt.py`,
which fails the merge unless the committed session receipt is gate-signed, every
authorized receipt carries a valid Halo2 policy proof, the embedded human
authorization is signed by the trusted maintainer key, and **every changed file
maps to an allow-receipt** (coverage). Make `receipt-gate` a required status
check with bypass disabled.

Pin these as repo variables (printed at server boot):
- `AGENTAUTH_GATE_KEY_ID`     — the gate signing key id (`keys/gate_ed25519.key`)
- `AGENTAUTH_MANDATE_KEY_ID`  — the maintainer mandate key id (`keys/mandate_ed25519.key`)

## Proof tier (honest)

Receipts carry a **real Halo2 structural-policy proof** (the SDK's prebuilt Rust
CLI + shipped params). We do **not** build the EZKL/risc0 inference backend, so we
do not claim composed `full_zk`. The gate's allow/deny decision is encoded as a
bounded `decision_risk` score the circuit proves in-range and binds to the policy
and output commitments; the actual allow/deny is enforced by the Biscuit. CI
verifies the standalone policy proof (`verify-policy`), not the aggregate
`verify_receipt_bundle` flag (which expects a composed proof for `full_zk`).

## What is and isn't guaranteed (residual trust)

**Guaranteed:** a workload-attested identity with a PoP-bound Biscuit; out-of-scope
resources denied by the token; each allowed action carries a signed,
offline-verifiable Halo2 policy proof; CI blocks merges lacking a valid, allow,
trusted-signed receipt with full file coverage.

**Not guaranteed:** this server does not mediate Devin's actual filesystem writes
and does not diff for scope. The capability check is advisory at edit-time; its
teeth come from CI. The binding between *what changed* and *what was authorized*
is closed by the coverage check + branch protection: an out-of-scope edit gets a
denied receipt or no receipt → coverage fails → merge blocked. This is the maximum
achievable without an in-process write interceptor. Note also that this is a
PR-time gate: it catches scope escalation in the diff, but a credential
exfiltration sent over a *different* MCP wire leaves no diff — closing that
requires additionally fronting untrusted MCP servers with a receipted egress proxy.

## Tests

Manual integration tests (require local `.venv` setup above):

```bash
.venv/bin/python tests/test_inproc.py    # all four tools, allow + deny, proof + signature self-check
.venv/bin/python tests/test_ci_gate.py   # CI verifier: pass + tamper (uncovered file / wrong key / corrupt proof)
.venv/bin/python tests/test_stdio.py     # spawns BOTH servers over stdio (Devin-style), verifies clean JSON-RPC

# optional over-the-wire (streamable-http): start the server, then drive it
AGENTAUTH_MCP_TRANSPORT=streamable-http AGENTAUTH_MCP_PORT=8851 .venv/bin/python server.py &
TEST_PORT=8851 .venv/bin/python tests/test_http.py
```
