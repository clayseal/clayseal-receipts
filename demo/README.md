# PR gate demo

A coding agent is asked to fix one issue. The issue body is poisoned and the
PR also touches privileged files. Vanilla merge accepts it. Clay Seal evaluates
the real diff against signed authorization, fails closed, and emits a signed
receipt.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
python3 demo/run_demo.py
```

Exit code `0` means merge may proceed. Exit code `1` means fail closed.

```bash
python3 demo/agentauth_gate.py verify-receipt \
  --receipt agentauth-receipts/pr-gate-receipt.json
```

See `run_demo.py`, `agentauth_gate.py`, and `policies/`.
