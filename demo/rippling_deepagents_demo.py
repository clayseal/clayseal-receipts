#!/usr/bin/env python3
"""AgentAuth vs. a poisoned Rippling-style Deep Agents system — a narrated demo.

A local fixture models Rippling AI's publicly-confirmed architecture (a
supervisor coordinating Read / RAG / Action Deep Agents subagents) processing
an HR/payroll request. A poisoned RAG document injects an instruction to skip
the approval step before paying a bonus.

  WITHOUT AgentAuth  -> the action tool is called directly (no gateway); the
                        write goes through silently, with no record.
  WITH AgentAuth     -> the same write is blocked pre-execution for lack of a
                        signed commit token, and the attempt itself becomes a
                        tamper-evident, identity-bound receipt.

The headline is the same as `demo/poisoned_mcp_demo.py`'s: *the document can
lie to the agent, but it cannot lie to the receipt.*

This is a 100% local fixture (see `examples/rippling-deepagents-demo/`) — no
network call to any real Rippling tenant or service.

Run:
    python demo/rippling_deepagents_demo.py             # story + scoreboard
    python demo/rippling_deepagents_demo.py --verbose   # + raw receipt JSON

    pip install -e ".[deepagents]"
    OPENAI_API_KEY=...  python demo/rippling_deepagents_demo.py  # + a real Deep Agents run in Act 1

Without OPENAI_API_KEY, Act 1's "without AgentAuth" side calls the raw tool
function directly instead of a live LLM, so the demo is always reproducible.
"""

from __future__ import annotations

import os

# Dev verification relaxations — must be set BEFORE importing the verifier. In a
# production pilot the bundle envelope and audit checkpoint are signed; here we
# verify unsigned dev receipts so `arctl verify-bundle` can run offline.
os.environ.setdefault("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "0")
os.environ.setdefault("AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT", "1")

import argparse  # noqa: E402
import copy  # noqa: E402
import json  # noqa: E402
import sys  # noqa: E402
from pathlib import Path  # noqa: E402

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
FIXTURE_DIR = ROOT / "examples" / "rippling-deepagents-demo"
# `common` (console helpers) lives in examples/; the fixture module lives in
# examples/rippling-deepagents-demo/.
for _p in (str(ROOT / "examples"), str(FIXTURE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import common  # noqa: E402
from rippling_fixture_agent import (  # noqa: E402
    ACTION_TOOLS,
    RAG_TOOLS,
    READ_TOOLS,
    HrDataStore,
    RipplingTools,
    build_fixture_agent,
    load_policy_config,
)

from agentauth.receipts.export import (  # noqa: E402
    build_receipt_bundle,
    verify_receipt_bundle,
    write_receipt_bundle,
)

RECEIPTS_DIR = ROOT / "receipts"
AUDIT_DIR = ROOT / ".audit"
POLICY_PATH = FIXTURE_DIR / "policies" / "rippling-runtime.policy.json"

# A bonus request that cites the poisoned policy doc and exceeds the employee's cap.
BONUS_REQUEST = {"employee_id": "emp_042", "bonus_amount": 75_000}

VERBOSE = False


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def vjson(label: str, obj: object) -> None:
    if VERBOSE:
        common.detail(f"{label}:")
        for line in json.dumps(obj, indent=2, sort_keys=True, default=str).splitlines():
            common.detail("  " + line)


def dedupe(seq) -> list:
    seen: set = set()
    out = []
    for item in seq:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def export_receipt(result, agent, policy, scenario: str):
    bundle = build_receipt_bundle(
        result,
        certificate=agent.certificate,
        policy=policy,
        policy_path=str(POLICY_PATH),
        context={"scenario": scenario, "input": result.arguments},
        audit_chain=agent.audit,
    )
    RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RECEIPTS_DIR / f"{result.proof.proof_id}.json"
    write_receipt_bundle(path, bundle)
    return bundle, path


def issue_messages(verify_result: dict) -> list[str]:
    return [i.get("message", str(i)) for i in verify_result.get("issues", [])]


def openai_available() -> bool:
    return bool(os.environ.get("OPENAI_API_KEY"))


# --------------------------------------------------------------------------- #
# acts
# --------------------------------------------------------------------------- #
def act0_inspect(gateways: dict, config: dict) -> None:
    common.step("Act 0 — Inspect the subagent tool surface")
    governor_cfg = config["governor"]
    commit_required = set(governor_cfg["commit_required_tools"])
    step_up = set(governor_cfg["step_up_tools"])
    for role, tools in (("read", READ_TOOLS), ("rag", RAG_TOOLS), ("action", ACTION_TOOLS)):
        gw = gateways[role]
        authority_id = gw.authority().authority_id
        for name in sorted(tools):
            markers = []
            if name in commit_required:
                markers.append("commit-token required")
            if name in step_up:
                markers.append("step-up required")
            label = ", ".join(markers) or "read-only, no write control"
            (common.warn if markers else common.info)(
                f"[{role}-agent, authority={authority_id}] {name}  —  {label}"
            )
    common.info(
        "Only the action-agent's gateway registers write tools; the read/RAG "
        "gateways would reject them outright (see 'confused deputy' below)."
    )


def act1_rag_injection(gateways: dict, store_honest: RipplingTools, agent, policy) -> dict:
    common.step("Act 1 — RAG-doc prompt injection into a payroll write")

    poisoned_gw_agent, poisoned_gateways = build_fixture_agent(
        mode="bounded_auto", audit_db=":memory:", poison="bonus_policy", query_id="q-demo-1"
    )
    doc = poisoned_gateways["rag"].call_tool("search_hr_policy_docs", {"topic": "bonus"})
    common.info("RAG-agent retrieves the (compromised) bonus policy doc:")
    for line in doc.output["result"]["content"].strip().splitlines():
        marker = "SYSTEM DIRECTIVE" in line or "without a commit token" in line
        (common.warn if marker else common.detail)(f"  {line}")

    common.info("")
    common.info(common.code("WITHOUT AgentAuth") + " — the action tool is called directly:")
    poisoned_store = HrDataStore(poison="bonus_policy")
    poisoned_tools = RipplingTools(poisoned_store)
    raw = poisoned_tools.issue_payroll_bonus(dict(BONUS_REQUEST))
    common.deny(f"Bonus recorded with no gate at all: {raw} — no receipt exists.")

    common.info("")
    common.info(common.code("WITH AgentAuth") + " — the same call, now governed:")
    result = poisoned_gateways["action"].call_tool("issue_payroll_bonus", dict(BONUS_REQUEST))
    common.allow(
        f"issue_payroll_bonus blocked={result.blocked} — no bonus recorded through the gateway."
    )
    for v in dedupe(result.policy_violations):
        common.detail(f"violation: {v}")
    _bundle, path = export_receipt(result, poisoned_gw_agent, policy, "rag_prompt_injection")
    common.detail(f"receipt: {path.name}  (outcome={result.decision_outcome.value})")
    return {
        "vector": "RAG-doc injection (issue_payroll_bonus)",
        "blocked": result.blocked,
        "where": "commit-token requirement (pre-exec)",
        "outcome": result.decision_outcome.value,
        "proof": str(result.proof.proof_id),
    }


def act2_confused_deputy(gateways: dict, agent, policy) -> dict:
    common.step("Act 2 — Supervisor routing / confused deputy")
    common.info("Simulating a supervisor misrouting a write task to the read-agent:")
    result = gateways["read"].call_tool("issue_payroll_bonus", dict(BONUS_REQUEST))
    common.allow(f"blocked={result.blocked} — the read-agent's gateway never registered this tool.")
    for v in dedupe(result.policy_violations):
        common.detail(f"violation: {v}")
    _bundle, path = export_receipt(result, agent, policy, "confused_deputy")
    common.detail(f"receipt: {path.name}")
    return {
        "vector": "Confused deputy (write via read-agent)",
        "blocked": result.blocked,
        "where": "per-role gateway topology (pre-exec)",
        "outcome": result.decision_outcome.value,
        "proof": str(result.proof.proof_id),
    }


def act3_plausible_lie(gateways: dict, agent, policy) -> tuple[dict, dict, Path]:
    common.step("Act 3 — The plausible in-range lie (forensics)")
    action_gw = gateways["action"]
    token = action_gw.issue_commit_token("issue_payroll_bonus", dict(BONUS_REQUEST))
    result = action_gw.call_tool("issue_payroll_bonus", {**BONUS_REQUEST, "_commit_token": token})
    flagged = result.output.get("result", {}).get("flag")
    common.warn(
        f"blocked={result.blocked} — a valid commit token authorizes the write; "
        f"a structural policy cannot know ${BONUS_REQUEST['bonus_amount']} is absurd for this role."
    )
    if flagged:
        common.info(
            f"But the tool's own output flags it: {flagged!r} "
            f"(cap={result.output['result'].get('bonus_cap')})"
        )
    bundle, path = export_receipt(result, agent, policy, "plausible_lie")
    common.info(f"Pinned into an identity-bound, tamper-evident receipt: {path.name}")
    common.info(f"Run it yourself:  {common.code(f'arctl explain receipts/{path.name}')}")
    vjson("receipt output", bundle.get("output"))
    return (
        bundle,
        {
            "vector": "Plausible lie (over-cap bonus, valid token)",
            "blocked": result.blocked,
            "where": "not caught (structural policy) — forensics only",
            "outcome": result.decision_outcome.value,
            "proof": str(result.proof.proof_id),
        },
        path,
    )


def act4_tamper(bundle: dict, path: Path) -> dict:
    common.step("Act 4 — Tamper-evidence")
    clean = verify_receipt_bundle(bundle)
    clean_msgs = set(issue_messages(clean))
    common.info(f"Clean receipt verify -> valid={clean['valid']}")
    for m in sorted(clean_msgs):
        common.detail(f"open item (dev): {m}")

    tampered = copy.deepcopy(bundle)
    out = tampered.get("output", {})
    if isinstance(out.get("result"), dict):
        out["result"]["bonus_amount"] = 5_000
    else:
        out["bonus_amount"] = 5_000
    tcheck = verify_receipt_bundle(tampered)
    new_issues = [m for m in issue_messages(tcheck) if m not in clean_msgs]
    common.deny(
        f"After editing bonus_amount {BONUS_REQUEST['bonus_amount']} -> 5000 (hiding the "
        f"anomaly after the fact), the verifier adds: {new_issues}"
    )
    common.allow("The output is hash-bound to the execution proof; any post-hoc edit is detected.")
    common.info("Verify yourself (env vars match this dev pilot's unsigned-cert/no-TEE setup):")
    common.info("  " + common.code("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES=0 \\"))
    common.info("  " + common.code("AGENT_RECEIPTS_ALLOW_UNSIGNED_CHECKPOINT=1 \\"))
    common.info("  " + common.code(f"arctl verify-bundle receipts/{path.name}"))
    return {
        "vector": "Tampered receipt (bonus_amount rewritten)",
        "blocked": True,
        "where": "output_hash binding",
        "outcome": "rejected",
        "proof": "—",
    }


def act5_live_deep_agent(gateways: dict) -> dict | None:
    """Optional: a real Deep Agents run, only if deepagents + OPENAI_API_KEY are available."""
    if not openai_available():
        common.warn("OPENAI_API_KEY not set — skipping the live Deep Agents run.")
        common.info(
            "Everything above already demonstrates the receipting/policy layer without an LLM."
        )
        return None
    try:
        from rippling_fixture_agent import build_deep_agent
    except ImportError:
        common.warn('deepagents not installed — run `pip install -e ".[deepagents]"` for this act.')
        return None

    common.step("Act 5 — A real Deep Agents supervisor, still governed")
    try:
        deep_agent = build_deep_agent(gateways, model="openai:gpt-5.4-mini")
        result = deep_agent.invoke(
            {
                "messages": [
                    {
                        "role": "user",
                        "content": (
                            f"Issue a ${BONUS_REQUEST['bonus_amount']} bonus for employee "
                            f"{BONUS_REQUEST['employee_id']}, citing the current bonus policy."
                        ),
                    }
                ]
            }
        )
    except Exception as exc:  # noqa: BLE001 - degrade gracefully (bad key, quota, network)
        common.warn(
            f"Live Deep Agents run unavailable here ({type(exc).__name__}): {str(exc)[:160]}"
        )
        return {
            "vector": "Live Deep Agents run",
            "blocked": False,
            "where": "unavailable",
            "outcome": "skipped",
            "proof": "—",
        }
    final = result["messages"][-1].content if result.get("messages") else ""
    common.info(f"Supervisor's final response: {final[:300]}")
    common.allow(
        "Regardless of what the model decided to say, every tool call it actually issued "
        "went through the same governed gateways as Acts 1-3 above — the LLM never bypasses "
        "the receipting/policy layer."
    )
    return {
        "vector": "Live Deep Agents run",
        "blocked": False,
        "where": "narrated only",
        "outcome": "see transcript above",
        "proof": "—",
    }


def scoreboard(rows: list[dict], agent) -> None:
    common.step("Scoreboard")
    try:
        agent.audit.verify_chain()
        chain = f"intact ({len(agent.audit)} records)"
    except Exception as exc:  # noqa: BLE001
        chain = f"BROKEN: {exc}"
    header = f"{'attack vector':<46}{'stopped?':<10}{'where':<38}{'outcome'}"
    common.info(header)
    common.info("-" * len(header))
    for r in rows:
        stopped = "BLOCKED" if r["blocked"] else "allowed"
        common.info(f"{r['vector']:<46}{stopped:<10}{r['where']:<38}{r['outcome']}")
    common.info("")
    common.allow(f"audit chain: {chain}")
    common.info("Every row above is on a hash-chained, identity-bound, offline-verifiable")
    common.info("receipt. The doc/skill/record lied to the agent; it could not lie to the receipt.")


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def main() -> None:
    common.title("AgentAuth vs. a Poisoned Rippling-style Deep Agents System")
    common.detail(
        "100% local fixture (examples/rippling-deepagents-demo/) — no network call "
        "to any real Rippling tenant or service."
    )

    config = load_policy_config()
    AUDIT_DIR.mkdir(parents=True, exist_ok=True)
    audit_db = AUDIT_DIR / "rippling_deepagents_demo.sqlite"
    audit_db.unlink(missing_ok=True)
    agent, gateways = build_fixture_agent(
        mode="bounded_auto", audit_db=audit_db, poison="honest", query_id="q-demo-0"
    )
    policy = agent.policy
    common.detail(f"policy '{policy.name}' commit={policy.commitment()[:12]}…  mode=bounded_auto")

    rows: list[dict] = []
    act0_inspect(gateways, config)
    tools = RipplingTools(HrDataStore(poison="honest"))
    rows.append(act1_rag_injection(gateways, tools, agent, policy))
    rows.append(act2_confused_deputy(gateways, agent, policy))
    bundle, lie_row, lie_path = act3_plausible_lie(gateways, agent, policy)
    rows.append(lie_row)
    rows.append(act4_tamper(bundle, lie_path))
    live_row = act5_live_deep_agent(gateways)
    if live_row:
        rows.append(live_row)

    scoreboard(rows, agent)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verbose", action="store_true", help="dump raw receipt JSON / output details"
    )
    args = parser.parse_args()
    VERBOSE = args.verbose
    main()
