"""Regression tests for P0 backlog fixtures (A8/A9/A10, I4)."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / "scripts" / "evaluate_devin_issue_attacks.py"

P0_CASES = (
    "15_benign",
    "17_poison",
    "18_poison",
    "19_poison",
)


def test_p0_issue_attack_cases_pass() -> None:
    cmd = [sys.executable, str(EVAL), *[f"--case={c}" for c in P0_CASES]]
    env = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(cmd, cwd=ROOT, env=env, text=True, capture_output=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_k2_stdio_rce_demo_json() -> None:
    demo = ROOT / "examples" / "k2_mcp_stdio_rce_demo.py"
    env = {**dict(__import__("os").environ), "PYTHONPATH": str(ROOT)}
    proc = subprocess.run(
        [sys.executable, str(demo)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
    )
    assert proc.returncode == 0, proc.stderr
    assert "governed_issue_refund_blocked" in proc.stdout
    assert "true" in proc.stdout.lower()
