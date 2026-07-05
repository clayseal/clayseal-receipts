import subprocess
import sys
from pathlib import Path

import yaml

from agentauth.receipts.policy import Policy

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "scaffold_policy.py"


def test_scaffold_policy_script(tmp_path: Path):
    out = tmp_path / "custom.yaml"
    subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--name",
            "custom_pilot",
            "--out",
            str(out),
            "--required-field",
            "decision",
            "--required-field",
            "risk_score",
            "--range",
            "risk_score:0:100",
        ],
        check=True,
        cwd=ROOT,
    )
    raw = yaml.safe_load(out.read_text())
    assert raw["name"] == "custom_pilot"
    policy = Policy.from_dict(raw)
    assert policy.commitment()
