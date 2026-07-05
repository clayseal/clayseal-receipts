#!/usr/bin/env python3
"""Demonstrate GATE-4 TOCTOU binding: stale P1 receipt must not authorize P2 merge.

    python3.11 scripts/evaluate_gate_toctou_binding.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "examples/devin-agentauth-demo/gated/.agentauth/agentauth_gate.py"
FIXTURE = ROOT / "examples/devin-gate-toctou-demo"


def run(cmd: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, check=False)


def main() -> int:
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from agentauth.core.signing import load_or_create_key

    tmp = Path(tempfile.mkdtemp(prefix="toctou-bind-"))
    gate_dir = tmp / "gate"
    receipts_dir = gate_dir / "receipts"
    receipts_dir.mkdir(parents=True)
    (gate_dir / "keys").mkdir(parents=True)
    (gate_dir / "mandates").mkdir(parents=True)
    (gate_dir / "policies").mkdir(parents=True)

    ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
    shutil.copytree(FIXTURE, tmp / "repo", ignore=ignore)
    repo = tmp / "repo"
    policy_src = ROOT / "examples/devin-agentauth-demo/gated/.agentauth/policies/devin-pr-gate.policy.json"
    shutil.copy2(policy_src, gate_dir / "policies/devin-pr-gate.policy.json")

    run(["git", "init", "-b", "main"], cwd=repo)
    run(["git", "add", "-A"], cwd=repo)
    run(["git", "commit", "-m", "baseline"], cwd=repo)
    base = run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()

    parser = repo / "toctou_app" / "parser.py"
    parser.parent.mkdir(parents=True, exist_ok=True)
    parser.write_text('def normalize(value: str) -> str:\n    return value.upper()\n', encoding="utf-8")
    run(["git", "add", "-A"], cwd=repo)
    run(["git", "commit", "-m", "P1 safe fix"], cwd=repo)
    p1 = run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()

    key = load_or_create_key(gate_dir / "keys/gate.ed25519.pem")
    mandate_doc = {
        "schema": "agentauth.human_authorization.v1",
        "authorization_id": "auth_toctou",
        "created_at": "2026-06-29T00:00:00Z",
        "agent": {"provider": "cognition-devin", "github_actor_patterns": ["*"]},
        "scope": {
            "allowed_paths": ["toctou_app/**", "tests/**"],
            "denied_paths": [],
            "allowed_operations": ["add", "modify"],
            "required_tests": [],
        },
        "intent": {"summary": "TOCTOU demo"},
    }
    mandate_path = gate_dir / "mandates/toctou.authorization.json"
    mandate_path.write_text(
        json.dumps({"document": mandate_doc, "signature": key.sign(mandate_doc)}, indent=2)
    )

    receipt_p1 = receipts_dir / "p1.receipt.json"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    run(
        [
            sys.executable,
            str(GATE),
            "evaluate",
            "--repo",
            str(repo),
            "--base",
            base,
            "--head",
            p1,
            "--authorization",
            str(mandate_path),
            "--policy",
            str(gate_dir / "policies/devin-pr-gate.policy.json"),
            "--receipt",
            str(receipt_p1),
            "--key",
            str(gate_dir / "keys/gate.ed25519.pem"),
            "--github-actor",
            "devin-ai-integration[bot]",
        ],
        cwd=repo,
    )

    workflow = repo / ".github/workflows/post-gate.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text("name: post-gate\non: push\n", encoding="utf-8")
    run(["git", "add", "-A"], cwd=repo)
    run(["git", "commit", "-m", "P2 denied path"], cwd=repo)
    p2 = run(["git", "rev-parse", "HEAD"], cwd=repo).stdout.strip()

    merge_ok = run(
        [
            sys.executable,
            str(GATE),
            "verify-merge",
            "--receipt",
            str(receipt_p1),
            "--merge-head",
            p1,
            "--json",
        ],
        cwd=repo,
    )
    stale = run(
        [
            sys.executable,
            str(GATE),
            "verify-merge",
            "--receipt",
            str(receipt_p1),
            "--merge-head",
            p2,
            "--json",
        ],
        cwd=repo,
    )
    merge_ok_body = json.loads(merge_ok.stdout)
    stale_body = json.loads(stale.stdout)

    print(f"P1 evaluated head: {p1}")
    print(f"P2 branch head:    {p2}")
    print(f"verify-merge @ P1: {'VALID' if merge_ok_body.get('valid') else 'INVALID'}")
    print(f"verify-merge @ P2: {'VALID' if stale_body.get('valid') else 'INVALID'} (expected INVALID)")

    shutil.rmtree(tmp, ignore_errors=True)
    ok = merge_ok_body.get("valid") is True and stale_body.get("valid") is False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
