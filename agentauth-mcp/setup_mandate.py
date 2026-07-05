"""One-time setup: generate the maintainer mandate signing key and write a signed
human-authorization mandate for the gated demo repo.

Run once: .venv/bin/python setup_mandate.py
Prints the mandate signer key id so it can be pinned via
AGENTAUTH_MCP_TRUSTED_MANDATE_KEY_ID.
"""

from __future__ import annotations

from pathlib import Path

from agentauth.receipts import signing

import config
from mandate import write_signed_mandate

HERE = Path(__file__).resolve().parent
MANDATE_KEY_PATH = HERE / "keys" / "mandate_ed25519.key"

# The human-signed authorization for issue #1: normalize lowercase ticket IDs in
# the parser ONLY. Scope IS the capability grant below — an explicit allowlist of
# {resource, action} pairs. There is no denylist: auth.py / secrets.json are simply
# not granted, so the capability token denies them. The grant is minted into the
# agent's Biscuit and never shown to the agent.
DOCUMENT = {
    "schema": "agentauth.human_authorization.v1",
    "mandate_id": "issue-1",
    "authorized_at": "2026-06-22T12:00:00+00:00",
    "authorized_by": {
        "organization": "demo-org",
        "principal": "human-maintainer@example.com",
        "role": "repository-maintainer",
    },
    "agent": {
        "provider": "cognition-devin",
        "github_actor_patterns": ["devin-ai-integration[bot]", "devin-ai[bot]", "devin*"],
    },
    "constraints": {"deny_anything_not_explicitly_granted": True, "fail_closed": True},
    "scope": {
        "capabilities": [
            {"resource": "repo:swe_triage/parser.py", "action": "modify"},
            {"resource": "repo:swe_triage/parser.py", "action": "add"},
            {"resource": "repo:tests/test_parser.py", "action": "modify"},
            {"resource": "repo:tests/test_parser.py", "action": "add"},
        ],
        "required_tests": ["python -m pytest -q"],
    },
    "task": {
        "github_issue": 1,
        "repository": "devin-agentauth-gated-demo",
        "summary": "Normalize lowercase Jira-style ticket IDs in the parser only.",
    },
}


def main() -> None:
    config.ensure_dirs()
    MANDATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    key = signing.load_or_create_key(MANDATE_KEY_PATH)
    envelope = write_signed_mandate(config.MANDATE_PATH, DOCUMENT, key)
    print(f"wrote signed mandate -> {config.MANDATE_PATH}")
    print(f"mandate signer key id: {key.key_id}")
    print(f"signature key_id in envelope: {envelope['signature']['key_id']}")


if __name__ == "__main__":
    main()
