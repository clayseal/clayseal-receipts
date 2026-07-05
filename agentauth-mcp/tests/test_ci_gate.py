"""Faithful test of the CI receipt-gate verifier (subprocess + real git).

Finalizes a real gate session, lays it into a throwaway git repo, and runs
.github/scripts/verify_pr_receipt.py for the pass case and three tamper cases.
Run with .venv/bin/python.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import server

VERIFIER = "/Users/yuvvan_talreja/Developer/devin-agentauth-gated-demo/.github/scripts/verify_pr_receipt.py"
PY = sys.executable


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


def run_verifier(repo: Path, manifest_glob: str, gate_key_id: str, mandate_key_id: str, base: str, head: str):
    return subprocess.run(
        [
            PY, VERIFIER,
            "--receipt", manifest_glob,
            "--trusted-gate-key-id", gate_key_id,
            "--trusted-mandate-key-id", mandate_key_id,
            "--base-ref", base,
            "--head-ref", head,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        env={**os.environ},
    )


# --- produce a real finalized manifest (authorize parser.py only) ------------- #
server.boot()
state = server._state()
gate_key_id = state.gate_key.key_id
mandate_key_id = state.mandate.signature["key_id"]

begin = server.begin_authorized_session(issue_ref="1", agent_actor="devin-ai-integration[bot]")
token = begin["session_token"]
server.authorize_action(token, "repo:swe_triage/parser.py", "modify")
server.authorize_action(token, "repo:swe_triage/auth.py", "modify")  # denied
fin = server.finalize_for_pull_request(token)
manifest = fin["bundle"]

tmp = Path(tempfile.mkdtemp(prefix="ci-gate-test-"))
git(tmp, "init", "-q")
git(tmp, "config", "user.email", "t@t.t")
git(tmp, "config", "user.name", "t")
(tmp / "swe_triage").mkdir()
(tmp / "swe_triage" / "parser.py").write_text("# original\n")
(tmp / "swe_triage" / "auth.py").write_text("# original auth\n")
git(tmp, "add", "-A")
git(tmp, "commit", "-qm", "base")
git(tmp, "branch", "-M", "main")

# head branch: modify parser.py (in scope) and commit the receipt
git(tmp, "checkout", "-qb", "pr")
(tmp / "swe_triage" / "parser.py").write_text("# original\n# normalized lowercase ids\n")
receipts_dir = tmp / ".agentauth" / "receipts"
receipts_dir.mkdir(parents=True)
manifest_path = receipts_dir / f"{token}.json"
manifest_path.write_text(json.dumps(manifest, indent=2, default=str))
git(tmp, "add", "-A")
git(tmp, "commit", "-qm", "pr: normalize parser + receipt")

results = {}

# CASE 1: clean PR -> PASS
r = run_verifier(tmp, ".agentauth/receipts/*.json", gate_key_id, mandate_key_id, "main", "pr")
results["pass_clean"] = (r.returncode == 0, r.stdout.strip() or r.stderr.strip())

# CASE 2: PR also edits auth.py with no receipt -> FAIL (coverage)
(tmp / "swe_triage" / "auth.py").write_text("# original auth\nTICKET_RE = re.compile(r'...', re.IGNORECASE)\n")
git(tmp, "add", "-A")
git(tmp, "commit", "-qm", "pr: sneak auth.py change")
r = run_verifier(tmp, ".agentauth/receipts/*.json", gate_key_id, mandate_key_id, "main", "pr")
results["fail_uncovered_authpy"] = (r.returncode != 0, (r.stdout + r.stderr).strip())
# revert that sneaky change for the remaining cases
git(tmp, "revert", "--no-edit", "HEAD")

# CASE 3: wrong trusted gate key id -> FAIL (signature/trust)
r = run_verifier(tmp, ".agentauth/receipts/*.json", "deadbeef" * 8, mandate_key_id, "main", "pr")
results["fail_wrong_gate_key"] = (r.returncode != 0, (r.stdout + r.stderr).strip())

# CASE 4: corrupt the Halo2 policy proof bytes -> FAIL (proof invalid)
bad = json.loads(manifest_path.read_text())
pb = bad["authorized"][0]["receipt"]["execution_proof"]["bundle"]["policy_proof_b64"]
bad["authorized"][0]["receipt"]["execution_proof"]["bundle"]["policy_proof_b64"] = ("A" + pb[1:])
manifest_path.write_text(json.dumps(bad, default=str))
git(tmp, "add", "-A")
git(tmp, "commit", "-qm", "pr: corrupt proof")
r = run_verifier(tmp, ".agentauth/receipts/*.json", gate_key_id, mandate_key_id, "main", "pr")
results["fail_corrupt_proof"] = (r.returncode != 0, (r.stdout + r.stderr).strip())

print("\n=== CI GATE TEST RESULTS ===")
ok = True
for name, (passed, detail) in results.items():
    status = "OK" if passed else "WRONG"
    ok = ok and passed
    print(f"[{status}] {name}: {detail[:140]}")

print("\nCI GATE TEST", "OK" if ok else "FAILED")
sys.exit(0 if ok else 1)
