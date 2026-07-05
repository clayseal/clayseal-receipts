#!/usr/bin/env python3
"""Deterministic two-sided enforcement benchmark for AgentAuth.

Replays the attack + benign corpus in
``examples/rippling-deepagents-demo/enforcement_cases.py`` directly against a
real ``build_fixture_agent()`` gateway (no LLM), and reports two first-class
numbers: attack catch-rate and benign pass-rate (== 1 - false-positive-rate).

Run:  python scripts/run_enforcement_benchmark.py [--verbose] [--case <id>]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "examples" / "rippling-deepagents-demo"
for _p in (str(ROOT), str(FIXTURE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from enforcement_cases import ALL_CASES, CASES_BY_ID, Case, Step  # noqa: E402
from rippling_fixture_agent import build_fixture_agent  # noqa: E402

# Benchmark-only arg markers stripped before the call. (``_idempotency_key`` is
# NOT a marker -- it's a real passthrough arg the budgets read, and it must be
# present at both token-issuance and call time so the commit-token hash matches.)
_MARKER_KEYS: tuple[str, ...] = ()

_WRITE_GATEWAYS = {"action", "shadow"}


def _classify(result) -> str:
    """allowed | step_up | hard_block"""
    if not result.blocked:
        return "allowed"
    status = ""
    if isinstance(result.output, dict):
        status = str(result.output.get("status", ""))
    if status == "step_up_required":
        return "step_up"
    return "hard_block"


def _run_step(gateways, step: Step) -> str:
    target_gw = gateways[step.gateway]
    call_args = {k: v for k, v in step.args.items() if k not in _MARKER_KEYS}
    # Action-gateway writes need a matching commit token; the shadow gateway
    # has no commit-signing key by construction, so we call it bare.
    if step.gateway == "action":
        token = gateways["action"].issue_commit_token(step.tool, call_args)
        call_args = {**call_args, "_commit_token": token}
    result = target_gw.call_tool(step.tool, call_args)
    return _classify(result)


def run_case(case: Case, *, verbose: bool = False) -> dict:
    _agent, gateways = build_fixture_agent(
        mode="bounded_auto",
        audit_db=":memory:",
        poison="honest",
        db_path="fixtures/mock_rippling.db",
        tenant_id="ten_acme",
        query_id=f"q-bench-{case.id}",
        goal_summary=case.goal_summary,
    )
    outcomes: list[tuple[Step, str]] = []
    for step in case.steps:
        outcomes.append((step, _run_step(gateways, step)))

    hard_blocks = [s for s, o in outcomes if o == "hard_block"]
    step_ups = [s for s, o in outcomes if o == "step_up"]

    if case.kind == "attack":
        exploit_steps = [s for s in case.steps if s.is_exploit_step] or case.steps
        # Caught iff every exploit-defining step was hard-blocked or forced to step-up.
        caught = all(
            dict((id(s), o) for s, o in outcomes)[id(es)] in ("hard_block", "step_up")
            for es in exploit_steps
        )
        passed = caught
    else:
        # Benign PASSES iff no step is hard-blocked. Step-up is tolerated
        # friction (a present requester satisfies it) -- surfaced via
        # step_up_count in the scorecard, not counted as a failure.
        passed = len(hard_blocks) == 0
        caught = None

    if verbose:
        print(f"\n[{case.kind}] {case.id}  ->  {'PASS' if passed else 'FAIL'}")
        for step, outcome in outcomes:
            flag = "" if outcome == "allowed" else f"  <-- {outcome}"
            print(f"    {step.gateway}.{step.tool}({step.args}) : {outcome}{flag}")

    return {
        "id": case.id,
        "kind": case.kind,
        "passed": passed,
        "caught": caught,
        "outcomes": [(s.tool, o) for s, o in outcomes],
        "hard_block_count": len(hard_blocks),
        "step_up_count": len(step_ups),
        "resembles": case.resembles,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--case", default=None, help="run a single case id")
    args = ap.parse_args()

    cases = [CASES_BY_ID[args.case]] if args.case else ALL_CASES
    results = [run_case(c, verbose=args.verbose) for c in cases]

    attacks = [r for r in results if r["kind"] == "attack"]
    benign = [r for r in results if r["kind"] == "benign"]
    caught = [r for r in attacks if r["passed"]]
    benign_pass = [r for r in benign if r["passed"]]

    print("\n" + "=" * 66)
    print("  AgentAuth enforcement benchmark (deterministic, no-LLM)")
    print("=" * 66)
    print(f"  attack catch-rate : {len(caught)}/{len(attacks)}"
          + (f"  ({100*len(caught)//len(attacks)}%)" if attacks else ""))
    print(f"  benign pass-rate  : {len(benign_pass)}/{len(benign)}"
          + (f"  ({100*len(benign_pass)//len(benign)}%)" if benign else "")
          + "   (pass = never hard-blocked)")
    print("-" * 66)
    for r in attacks:
        mark = "caught " if r["passed"] else "OPEN   "
        print(f"  attack  {mark} {r['id']:42s} {r['outcomes']}")
    for r in benign:
        mark = "ok     " if r["passed"] else "BLOCKED"
        near = f"  (near-miss vs {r['resembles']})" if r["resembles"] else ""
        print(f"  benign  {mark} {r['id']:42s} hard_blocks={r['hard_block_count']}"
              f" step_ups={r['step_up_count']}{near}")
    print("=" * 66)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
