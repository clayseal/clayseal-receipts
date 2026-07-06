"""Error-mapping tests: backend codes -> typed SDK exceptions."""
from __future__ import annotations

import pytest

from agentauth.identity import (
    AgentAuth,
    AgentAuthError,
    AgentNotFoundError,
    InvalidAPIKeyError,
    InvalidTokenError,
)
from agentauth.identity.errors import from_envelope


def test_bad_api_key_raises_invalid_api_key(base_url):
    client = AgentAuth(api_key="aa_not_real", base_url=base_url, dev_attestation=True)
    with pytest.raises(InvalidAPIKeyError) as exc:
        client.identify(agent_type="x", owner="y", scopes=[])
    assert exc.value.code == "invalid_api_key"


def test_identify_requires_explicit_attestation_or_dev_mode(api_key, base_url):
    client = AgentAuth(api_key=api_key, base_url=base_url)
    with pytest.raises(AgentAuthError) as exc:
        client.identify(agent_type="x", owner="y", scopes=[])
    assert exc.value.code == "attestation_required"


def test_dev_attestation_is_localhost_only(api_key):
    client = AgentAuth(
        api_key=api_key,
        base_url="https://agentauth.example.test",
        dev_attestation=True,
    )
    with pytest.raises(AgentAuthError) as exc:
        client.identify(agent_type="x", owner="y", scopes=[])
    assert exc.value.code == "dev_attestation_remote_denied"


def test_invalid_token_raises(auth):
    with pytest.raises(InvalidTokenError):
        auth.validate("not-a-jwt")


def test_unknown_agent_raises_not_found(auth):
    with pytest.raises(AgentNotFoundError):
        auth.agent("does-not-exist")


def test_from_envelope_unknown_code_falls_back_to_base():
    err = from_envelope(
        {"error": {"code": "weird", "message": "m", "suggestion": "s"}}, 400
    )
    assert isinstance(err, AgentAuthError)
    assert err.code == "weird"
    assert "m" in str(err) and "s" in str(err)
