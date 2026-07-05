"""01 - Quickstart: issue, validate, and revoke an agent identity.

Demonstrates the whole identity lifecycle a developer adds to their agent:
  1. create a tenant,
  2. identify() an agent -> a short-lived, signed JWT-SVID credential,
  3. inspect the credential and its claims,
  4. validate() the token,
  5. list the tenant's agents,
  6. revoke() the agent and show validation now fails.

Run:  python examples/01_quickstart.py
"""
from __future__ import annotations

import common

from agentauth import AgentRevokedError


def main() -> None:
    common.title("AgentAuth Quickstart - Identity")
    auth, _api_key, _url = common.bootstrap("Acme AI")

    # 1. Give the agent a real, signed identity (a short-lived JWT-SVID).
    #    Under the hood this is an attestation: the SDK proves the workload's
    #    provenance and the service mints a credential for it.
    common.step("Issue an identity for a 'researcher' agent")
    session = auth.identify(
        agent_type="researcher",
        owner="alice@acme.ai",
        scopes=["db:read", "web:*"],
        ttl_seconds=3600,
    )
    common.info(f"agent_id   = {common.code(session.agent_id)}")
    common.info(f"agent_type = {session.agent_type}")
    common.info(f"owner      = {session.owner}")
    common.detail(f"scopes = {session.scopes}")
    common.detail(f"token  = {session.token[:32]}...")

    # 2. Validate the freshly issued token.
    common.step("Validate the token")
    result = session.validate()
    claims = result.claims or {}
    common.allow(f"valid={result.valid}  agent_id={claims.get('agent_id')}")
    common.detail(f"claims: sub={claims.get('sub')}  exp={claims.get('exp')}")

    # 3. List the tenant's agents.
    common.step("List agents for this tenant")
    agents = auth.agents()
    for a in agents:
        common.info(f"- {a.id}  type={a.agent_type}  status={a.status}")

    # 4. Revoke the agent. The credential is invalidated immediately.
    common.step("Revoke the agent")
    auth.revoke(session.agent_id)
    common.detail("revocation is immediate")

    # 5. Validation now fails for the revoked credential.
    common.step("Validate the token again")
    try:
        session.validate()
        common.info("unexpected: revoked token still validated")
    except AgentRevokedError as exc:
        common.deny(f"rejected: {exc.code} (credential revoked)")

    common.title("Done - issue, validate, revoke in a handful of calls")


if __name__ == "__main__":
    main()
