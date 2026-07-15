"""Shared pytest fixtures for agent-receipts."""

from __future__ import annotations

import importlib.util

import pytest


def pytest_ignore_collect(collection_path) -> bool:  # type: ignore[no-untyped-def]
    """Skip L2 capability tests when the optional capabilities package is absent."""
    if collection_path.suffix != ".py":
        return False
    if importlib.util.find_spec("agentauth.capabilities") is not None:
        return False
    try:
        text = collection_path.read_text(encoding="utf-8")
    except OSError:
        return False
    l2_patterns = (
        "agentauth.capabilities",
        "ReceiptedMcpGateway",
        "RepoAgentSession",
        "build_fixture_agent",
        "wrap_mcp_session",
    )
    return any(pattern in text for pattern in l2_patterns)


@pytest.fixture(autouse=True)
def _allow_unsigned_step_up(monkeypatch: pytest.MonkeyPatch) -> None:
    """Opt the in-process receipts test suite into the unsigned step-up path.

    The capabilities layer now enforces *signed* ``StepUpApproval`` objects by
    default (a security hardening). These receipts tests exercise the step-up
    *mechanism* with plain approvals in a trusted-local context, so they use the
    documented escape hatch. Production callers must pass a ``SignedStepUpApproval``.
    """
    monkeypatch.setenv("AGENTAUTH_STEP_UP_ALLOW_UNSIGNED", "1")


@pytest.fixture
def allow_stub_proofs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enable stub inference/composed proofs for prove-mode integration tests."""
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_STUB", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_ALLOW_UNSIGNED_CERTIFICATE", "1")
    monkeypatch.setenv("AGENT_RECEIPTS_REQUIRE_BUNDLE_SIGNATURES", "0")


@pytest.fixture
def trusted_signer(monkeypatch: pytest.MonkeyPatch):
    """Pin a generated Ed25519 key as a trusted envelope signer."""
    from agentauth.core.signing import generate_keypair

    key = generate_keypair()
    monkeypatch.setenv("AGENT_RECEIPTS_TRUSTED_SIGNER_PUBLIC_KEYS", key.public_key_hex)
    return key
