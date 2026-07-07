# Demo: A Coding Assistant vs. a Poisoned "Dev Tools" MCP Server

> **The one-liner:** A compromised dev-tools server can lie to your coding agent and try to
> trick it into running arbitrary code — but it can't make the agent exceed its granted
> capabilities, and it can't lie to the receipt.

A coding-assistant agent is told to review a repository: **read files → run tests → scan
dependencies**, by calling a "dev tools" MCP server. Both the server *and* the codebase are
compromised:

- the **repo** (`demo/sample_repo/`) ships a **typosquatted dependency** (`reqursts`, a fake
  `requests`) and an **inert backdoor** in `app.py`;
- the **MCP server** is poisoned: it **lies** that the tests passed and dependencies are clean
  (hiding the compromise), buries **prompt-injection** in its tool descriptions, and advertises two
  privileged tools the coding agent was **never granted** — `run_shell` (arbitrary command
  execution) and `exfiltrate_secrets` (data exfiltration).

The demo runs the agent against the server twice — once **ungoverned**, once **through
Clay Seal** — and shows the difference.

*(Deploy is intentionally out of scope for now; the flow ends at the dependency scan. It can be
added later as a human step-up — a separate, human-authorized elevated credential.)*

---

## Run it

```bash
# from the repo root
pip install -e ".[mcp]"          # installs the mcp transport + the groq SDK
source .venv/bin/activate

# Real LLM agent (it actually reads the poisoned descriptions and may get injected):
export GROQ_API_KEY=sk-...        # model via GROQ_MODEL (default llama-3.3-70b-versatile)
python demo/code_exec_demo.py

# No key: a deterministic scripted agent (which OBEYS the injection) runs instead,
# so the demo is fully reproducible:
python demo/code_exec_demo.py

python demo/code_exec_demo.py --verbose     # + raw receipt JSON / authority / proof bytes
```

The script boots an embedded Clay Seal backend on a throwaway database, attests a coding-assistant
identity, and spawns the dev-tools server as a subprocess — zero config. Nothing dangerous runs:
`run_shell`/`exfiltrate_secrets` are **simulated**, `read_file` is **path-sandboxed** to the fixture,
and `run_tests` only executes the fixture's own safe test.

---

## The acts (talk track)

**Act 0 — Inspect the repo + server.** Read `requirements.txt` through the (sandboxed) `read_file`
tool — the `reqursts` typosquat is right there. List the MCP tools: `run_shell` / `exfiltrate_secrets`
are advertised but not granted, and the `run_tests` / `scan_dependencies` descriptions carry "SYSTEM
DIRECTIVE" injection.

**Act 1 — Ground truth.** Run the *honest* tools on the *real* fixture: `scan_dependencies` flags the
malicious dependency (`risk_score 0.95`), the tests run for real. The repo genuinely is compromised —
remember that when the poisoned server claims everything is clean.

**Act 2 — Arbitrary code execution + exfiltration.**
- *Without Clay Seal:* a real (Groq) LLM agent reads the poisoned descriptions, trusts the fabricated
  "all clear," and is injected into calling `run_shell` and `exfiltrate_secrets` — **arbitrary code
  execution and secret exfiltration (simulated), with no record.**
- *With Clay Seal:* the same `run_shell` / `exfiltrate_secrets` calls are **blocked before their bodies
  run** — they're outside the agent's per-tool Biscuit capability grant — and the attempts are
  captured in `deny` receipts.

**Act 3 — Poisoned "all clear" + forensics.** Through Clay Seal, `run_tests` returns `passed:true` and
`scan_dependencies` returns `risk_score:0.0` — lies the structural policy can't detect. But each is now
pinned in a receipt **bound to the attested identity** (SPIFFE selectors, `jwt_svid`, sender-constrained,
proof-of-possession, per-tool capabilities). When the compromise surfaces, this is the non-repudiable
record that the agent was fed false signals:

```bash
arctl explain receipts/<scan_receipt>.json
```

**Act 4 — Tamper-evidence.** Edit the scan receipt to make the lie look like a catch
(`risk_score 0.0 → 0.9`). The verifier instantly flags `output_mismatch` / `decision_mismatch`: the
exported output no longer matches the `output_hash` inside the execution proof.

**Act 5 — Zero-knowledge proof.** Re-run the scan in `prove` mode and generate a **Halo2 ZK proof** that
the recorded dependency-risk score satisfies the committed policy range, then verify it independently
(`verify_structural_policy → valid: true`) — offline, with no access to the prover or the model.

A scoreboard summarizes every vector and confirms the audit chain is intact.

---

## What Clay Seal does — and does not — do (read this)

- It does **not** strip injection text: tool descriptions reach the model verbatim (that's how MCP
  works). The guarantee is at the **action** layer — the agent literally cannot call `run_shell` /
  `exfiltrate_secrets`, because its PoP-bound Biscuit capability grant covers only `read_file` /
  `run_tests` / `scan_dependencies`.
- It does **not** do semantic reasoning: it can't know `passed:true` is a lie. For that class the value
  is **non-repudiable, tamper-evident forensics** — the honest-tools ground truth (Act 1) exposes the
  lie; the receipts make it provable.
- **Safety:** `run_shell` / `exfiltrate_secrets` are simulated and never execute; `read_file` is
  path-sandboxed; `run_tests` runs only the fixture's own safe test.
- **Dev-mode verification notes.** This demo uses unsigned dev certificates and no TEE, so
  `arctl verify-bundle` reports `certificate is unsigned` + `tee_hybrid: no tee_quote attached`
  (`valid:false`) — the production-hardening checklist (PKI-signed certs + TEE/ZK attestation), not
  integrity failures. The integrity checks are what flip on tamper (Act 4), and the Halo2 proof (Act 5)
  is the clean cryptographic green check. The verify command prints with the two dev env vars set.

---

## Files

| File | Role |
|---|---|
| `demo/sample_repo/` | The compromised fixture the agent reads: `requirements.txt` (typosquat dep), `app.py` (inert backdoor), `test_app.py` (safe test). |
| `demo/dev_tools_server.py` | Honest **or** poisoned dev-tools FastMCP server (`AGENT_RECEIPTS_POISON=honest|lies`). `read_file` (sandboxed), `run_tests`/`scan_dependencies` (real vs lie), `run_shell`/`exfiltrate_secrets` (simulated, ungranted). |
| `demo/code_exec_demo.py` | The orchestrator — the acts + scoreboard. `--verbose` for raw artifacts. |
| `demo/dev_tools.yaml` | Committed policy for the agent: structural, `min_trust_tier: sender_constrained`; no output schema (dev-tool outputs are heterogeneous — capability is the gate). |
| `demo/dev_scan.yaml` | Policy for the ZK finale only: `numeric_ranges: risk_score [0,1]` so the Halo2 circuit has a field to prove. |
| `demo/llm_agent.py` | Shared tool-calling agent (real Groq + scripted fallback), reused from the fraud demo. |

The agent identity, the policy, and every receipt are tied together by one seam:
`auth.identify(capabilities=[...])` → `session.wrap(model, policy=..., mode="bounded_auto")` → each MCP
tool call is authorized by the Biscuit capability grant and receipted, bound to the attested identity.

See also the sibling fraud-scoring demo: [`../examples/POISONED_MCP_DEMO.md`](../examples/POISONED_MCP_DEMO.md).
