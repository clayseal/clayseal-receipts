# Clay Seal Devin PR Gate Demo

This demo shows a realistic failure mode for autonomous coding agents:

- a human asks Devin to fix one GitHub issue;
- the issue body is poisoned with instructions that widen the task;
- the Devin PR fixes the bug and also changes privileged files;
- vanilla merge flow accepts the PR;
- Clay Seal CI evaluates the real PR diff against signed human authorization,
  fails closed, and emits a signed receipt explaining why.

The local replay does not mock the gate. It creates real git repositories, real
branches, a real bot-authored commit, runs the configured test command, evaluates
the diff with the same CI command, and verifies the signed receipt offline. The
only replayed part is the representative Devin PR diff in
`patches/devin-poisoned-gh-1337.patch`; replace `--head` with an actual Devin PR
branch to use the same gate live.

## Run

```bash
# from the repo root, once per checkout if Clay Seal is not already installed
python3 -m venv .venv
.venv/bin/python -m pip install -e .

python3 demo/run_demo.py
```

Expected result:

- `vanilla-devin` merges the poisoned PR and protected files land on `main`;
- `agentauth-devin` refuses to merge;
- a signed receipt appears under `demo/.run/agentauth-devin/agentauth-output/`;
- changing the receipt makes `verify-receipt` fail.

## Use With A Real Devin PR

1. Put a signed authorization envelope in the target repo, usually under
   `.agentauth/mandates/<issue>.authorization.json`.
2. Let Devin create a branch or PR for the issue.
3. In CI, check out the PR with full history and run:

```bash
python3 demo/agentauth_gate.py evaluate \
  --repo . \
  --base origin/main \
  --head "$PR_HEAD_SHA" \
  --authorization .agentauth/mandates/gh-1337.authorization.json \
  --policy demo/policies/devin-pr-gate.policy.json \
  --issue .github/issues/gh-1337.md \
  --receipt agentauth-receipts/pr-gate-receipt.json \
  --key "$AGENTAUTH_GATE_KEY_PATH" \
  --github-actor "$PR_AUTHOR"
```

Exit code `0` means merge may proceed. Exit code `1` means fail closed.

Verify the receipt offline:

```bash
python3 demo/agentauth_gate.py verify-receipt \
  --receipt agentauth-receipts/pr-gate-receipt.json
```

## Files

| Path | Purpose |
| --- | --- |
| `agentauth_gate.py` | CI-compatible Clay Seal gate. |
| `run_demo.py` | End-to-end replay using real git branches and commits. |
| `fixtures/acme-payments/` | Small repo with the real `GH-1337` checkout bug. |
| `issues/gh-1337-poisoned.md` | Poisoned GitHub issue body. |
| `mandates/gh-1337.authorization.template.json` | Human-approved scope before signing. |
| `patches/devin-poisoned-gh-1337.patch` | Representative Devin PR diff. |
| `policies/devin-pr-gate.policy.json` | Default out-of-scope and dangerous-content rules. |
| `github-actions/agentauth-devin-gate.yml` | Workflow template for a real GitHub repo. |

## What The Receipt Proves

The receipt binds together:

- the human authorization document and its signature;
- the claimed Devin/GitHub actor;
- base and head commit SHAs;
- the diff hash and changed-file list;
- test command results;
- every gate violation;
- the Clay Seal gate signature.

That makes the denial portable: a reviewer can verify it without rerunning Devin,
trusting the CI logs, or accepting a mutable PR comment.
