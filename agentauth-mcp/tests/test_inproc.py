"""In-process exercise of the gate tools (no HTTP). Run with .venv/bin/python."""
from __future__ import annotations

import json
import sys
from pathlib import Path

_PKG = Path(__file__).resolve().parents[1]
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))

import server
import receipts_engine

server.boot()

# 1. begin
begin = server.begin_authorized_session(issue_ref="1", agent_actor="devin-ai-integration[bot]")
token = begin["session_token"]
print("session_token:", token[:16], "...")
print("authority_summary:", begin["authority_summary"]["scope_model"][:60], "...")
# Scope lives in the token: NO file paths (granted or denied) may be surfaced.
leaked = [p for p in ("swe_triage/parser.py", "swe_triage/auth.py", "secrets.json", "tests/test_parser.py")
          if p in json.dumps(begin)]
assert not leaked, f"scope paths leaked to agent: {leaked}"

# 2. the task briefing is returned by begin (no separate get_task_briefing tool)
print("briefing summary:", begin["task_briefing"]["summary"])

# 3a. authorize in-scope -> allow + ZK proof
ok = server.authorize_action(token, "repo:swe_triage/parser.py", "modify")
print("parser.py:modify ->", ok)
assert ok["allowed"] is True and ok["receipt_id"]

# 3b. authorize the poison targets -> deny (purely from the token)
d1 = server.authorize_action(token, "repo:swe_triage/auth.py", "modify")
d2 = server.authorize_action(token, "repo:swe_triage/secrets.json", "modify")
print("auth.py:modify   ->", d1)
print("secrets.json     ->", d2)
assert d1["allowed"] is False and d2["allowed"] is False
# Sanitized: no raw biscuit internals leaked in the deny reason.
assert "policy index" not in json.dumps(d1)

# 4. finalize
fin = server.finalize_for_pull_request(token)
print("finalize:", {k: fin[k] for k in ("receipt_ref", "authorized_count", "denied_count")})
assert fin["authorized_count"] == 1 and fin["denied_count"] == 2

# self-check the finalized bundle: gate signature + Halo2 policy proof
state = server._state()
check = receipts_engine.self_check_bundle(fin["bundle"], gate_key=state.gate_key)
print("signatures.valid:", check["signatures"]["valid"])
print("policy_proofs:", check["policy_proofs"])
assert check["signatures"]["valid"] is True
assert check["policy_proofs"] and all(p["valid"] for p in check["policy_proofs"])

print("\nIN-PROC TEST OK")
