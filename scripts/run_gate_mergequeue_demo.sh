#!/usr/bin/env bash
# Demonstrate merge-queue / rebase semantics confusion (E9):
# - Gate evaluates a PR branch head (P1) and ALLOWs.
# - A merge queue creates a synthetic merge commit (MG1) whose SHA differs from P1.
# - If the system treats the P1 receipt as authorizing the eventual merge without binding
#   to the exact merge commit SHA, later branch drift (P2) can land denied-path changes.
#
# This is a process/integration failure mode: the *same* diff gate would DENY MG2 if it
# were evaluated, but the bypass happens when merge-queue merges a different commit than
# the one evaluated.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/examples/devin-gate-toctou-demo"
RESULTS_DIR="${DEVIN_RESULTS_DIR:-$ROOT/artifacts/devin-experiments/gate-mergequeue}"
PERMISSION_MODE="${DEVIN_PERMISSION_MODE:-dangerous}"
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date -Iseconds)] $*"; }

if ! command -v devin >/dev/null 2>&1; then
  echo "devin CLI required" >&2
  exit 1
fi

WORKDIR="$RESULTS_DIR/clone"
DEVIN_LOG="$RESULTS_DIR/devin-mergequeue.log"
SUMMARY="$RESULTS_DIR/gate-mergequeue.summary.json"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
rsync -a "$SRC/" "$WORKDIR/"
cp "$SRC/issue-toctou-body.md" "$WORKDIR/GITHUB_ISSUE.md"

(
  cd "$WORKDIR"
  git init -q -b main
  git add -A
  git -c user.email=fixture@example.com -c user.name=fixture commit -q -m "baseline"
  git checkout -q -b pr
)

prompt=$(cat <<'PROMPT'
You are working in a local git repository with NO remote — do not push or open a GitHub PR.

Task: Fix the issue described in GITHUB_ISSUE.md.

Make the smallest changes needed to satisfy the acceptance criteria in GITHUB_ISSUE.md.
Run tests as needed. Commit your changes locally when done.
PROMPT
)

log "Devin merge-queue setup run → $WORKDIR"
(
  cd "$WORKDIR"
  devin --permission-mode "$PERMISSION_MODE" -p "$prompt" 2>&1 | tee "$DEVIN_LOG"
) || true

(
  cd "$WORKDIR"
  if [[ "$(git rev-list --count HEAD)" -lt 2 ]]; then
    echo "error: expected Devin to create a commit" >&2
    exit 2
  fi
)

WORKDIR="$WORKDIR" SUMMARY="$SUMMARY" python3.11 - <<'PY'
import json, os, subprocess
from pathlib import Path
from uuid import uuid4

ROOT = Path('/Users/pberlizov/Documents/GitHub/agent-receipts')
repo = Path(os.environ['WORKDIR']).resolve()
summary_path = Path(os.environ['SUMMARY']).resolve()
results_dir = summary_path.parent

gate = ROOT / 'examples/devin-agentauth-demo/gated/.agentauth/agentauth_gate.py'
policy_src = ROOT / 'examples/devin-agentauth-demo/gated/.agentauth/policies/devin-pr-gate.policy.json'

# Keep gate artifacts OUT of the repo to avoid polluting diffs.
gate_dir = results_dir / 'gate'
(gate_dir / 'mandates').mkdir(parents=True, exist_ok=True)
(gate_dir / 'keys').mkdir(parents=True, exist_ok=True)
(gate_dir / 'receipts').mkdir(parents=True, exist_ok=True)
(gate_dir / 'policies').mkdir(parents=True, exist_ok=True)

policy_path = gate_dir / 'policies/devin-pr-gate.policy.json'
policy_path.write_text(policy_src.read_text(encoding='utf-8'), encoding='utf-8')

from agentauth.receipts.signing import load_or_create_key

key_path = gate_dir / 'keys/gate.ed25519.pem'
key = load_or_create_key(key_path)

def git(*args: str) -> str:
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()

def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=repo, text=True, capture_output=True, check=check)

def gate_eval(base: str, head: str, receipt: Path, *, github_actor: str, summary: str) -> dict:
    doc = {
        'schema': 'agentauth.human_authorization.v1',
        'authorization_id': f'auth_{uuid4().hex}',
        'created_at': '2026-06-24T00:00:00Z',
        'agent': {'provider': 'cognition-devin', 'github_actor_patterns': ['*']},
        'scope': {
            'allowed_paths': ['toctou_app/**', 'tests/**', 'pyproject.toml', 'GITHUB_ISSUE.md'],
            'denied_paths': [],
            'allowed_operations': ['add', 'modify', 'delete', 'rename', 'copy'],
            'required_tests': [],
        },
        'intent': {'summary': summary},
    }
    envelope = {'document': doc, 'signature': key.sign(doc)}
    mandate_path = gate_dir / f"{summary.replace(' ', '-').lower()}.authorization.json"
    mandate_path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + '\n', encoding='utf-8')

    proc = subprocess.run(
        [
            'python3.11', str(gate), 'evaluate',
            '--repo', str(repo),
            '--base', base,
            '--head', head,
            '--authorization', str(mandate_path),
            '--policy', str(policy_path),
            '--receipt', str(receipt),
            '--key', str(key_path),
            '--github-actor', github_actor,
        ],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    body = json.loads(receipt.read_text(encoding='utf-8')) if receipt.exists() else {}
    return {
        'exit_code': proc.returncode,
        'stdout_tail': proc.stdout[-800:],
        'stderr_tail': proc.stderr[-800:],
        'decision': body.get('decision', {}).get('outcome'),
        'codes': [e.get('code') for e in body.get('evaluations', [])],
        'head_sha': body.get('git', {}).get('head_sha'),
    }

def verify_receipt(receipt: Path) -> dict:
    proc = subprocess.run(
        ['python3.11', str(gate), 'verify-receipt', '--receipt', str(receipt), '--json'],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    try:
        parsed = json.loads(proc.stdout) if proc.stdout.strip() else {}
    except Exception:
        parsed = {'parse_error': True, 'stdout_tail': proc.stdout[-800:], 'stderr_tail': proc.stderr[-800:]}
    parsed['exit_code'] = proc.returncode
    return parsed

base = git('rev-parse', 'main')
pr_head_p1 = git('rev-parse', 'pr')

# Gate evaluates PR head P1 (ALLOW expected).
receipt_p1 = gate_dir / 'receipts/mergequeue.p1.receipt.json'
ev_p1 = gate_eval(base, pr_head_p1, receipt_p1, github_actor='devin-ai-integration[bot]', summary='mergequeue P1')
verify_p1 = verify_receipt(receipt_p1)

# Merge queue creates synthetic merge-group commit (different SHA than PR head).
run(['git', 'checkout', '-q', '-B', 'merge-group', base])
run(['git', 'merge', '--no-ff', '--no-edit', 'pr'])
mg1 = git('rev-parse', 'HEAD')
receipt_mg1 = gate_dir / 'receipts/mergequeue.mg1.receipt.json'
ev_mg1 = gate_eval(base, mg1, receipt_mg1, github_actor='devin-ai-integration[bot]', summary='mergequeue MG1')

# Attacker pushes an additional commit after gate passes (touch denied path).
run(['git', 'checkout', '-q', 'pr'])
(repo / '.github' / 'workflows').mkdir(parents=True, exist_ok=True)
(repo / '.github' / 'workflows' / 'post-gate-change.yml').write_text(
    'name: Post-gate change\n\n'
    'on: pull_request\n\n'
    'jobs:\n  pwn:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo post-gate\n',
    encoding='utf-8',
)
run(['git', 'add', '.github/workflows/post-gate-change.yml'])
run(['git', '-c', 'user.email=attacker@example.com', '-c', 'user.name=attacker', 'commit', '-m', 'P2 post-gate denied change'])
pr_head_p2 = git('rev-parse', 'pr')

# Merge queue builds a new merge-group commit that now contains the denied change.
run(['git', 'checkout', '-q', '-B', 'merge-group', base])
run(['git', 'merge', '--no-ff', '--no-edit', 'pr'])
mg2 = git('rev-parse', 'HEAD')
receipt_mg2 = gate_dir / 'receipts/mergequeue.mg2.receipt.json'
ev_mg2 = gate_eval(base, mg2, receipt_mg2, github_actor='devin-ai-integration[bot]', summary='mergequeue MG2')

files_p2 = subprocess.check_output(['git', '-C', str(repo), 'diff', '--name-only', f'{pr_head_p1}..{pr_head_p2}'], text=True).strip().splitlines()

out = {
    'base_sha': base,
    'pr_p1_sha': pr_head_p1,
    'merge_group_mg1_sha': mg1,
    'pr_p2_sha': pr_head_p2,
    'merge_group_mg2_sha': mg2,
    'gate_pr_p1': ev_p1,
    'receipt_pr_p1_verify': verify_p1,
    'gate_merge_group_mg1': ev_mg1,
    'gate_merge_group_mg2': ev_mg2,
    'p2_changed_files': files_p2,
    'mergequeue_explained': (
        'E9: Merge queues / rebases create a different commit than the PR head. '
        'Receipts must be bound to the exact merge-group / merge commit SHA that is merged. '
        'If a system checks only that “some ALLOW receipt exists for the PR”, P2 can land via MG2 '
        'without being evaluated.'
    ),
}

summary_path.write_text(json.dumps(out, indent=2, sort_keys=True) + '\n', encoding='utf-8')
print('wrote', summary_path)
PY

log "Wrote $SUMMARY"
