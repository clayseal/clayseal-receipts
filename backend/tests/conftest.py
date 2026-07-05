"""Test fixtures.

Environment is pointed at a throwaway temp directory *before* the app is
imported, so the module-level SQLAlchemy engine binds to a temp SQLite file
and the audit log writes to a temp JSONL file.
"""
from __future__ import annotations

import os
import tempfile

_TMPDIR = tempfile.mkdtemp(prefix="agentauth-test-")
os.environ.setdefault("AGENTAUTH_DATABASE_URL", f"sqlite:///{_TMPDIR}/agents.db")
os.environ.setdefault(
    "AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY",
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agentauth.backend.db import init_db  # noqa: E402
from agentauth.backend.main import app  # noqa: E402
from tests.attest import bind_customer_api_key  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _init_db() -> None:
    init_db()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def customer(client: TestClient) -> dict:
    """Create a fresh tenant and return its info incl. api_key + headers."""
    resp = client.post("/v1/customers", json={"name": "Acme AI"})
    assert resp.status_code == 201, resp.text
    data = resp.json()
    data["headers"] = {"X-API-Key": data["api_key"]}
    bind_customer_api_key(data["api_key"], data["customer_id"])
    return data
