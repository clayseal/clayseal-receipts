# ruff: noqa: E402, I001
"""SDK test fixtures.

The whole SDK is exercised end-to-end against the real FastAPI backend running
in-process on a background uvicorn server bound to an ephemeral port - the SDK
talks to it over real HTTP, exactly as a developer's code would. We point the
backend at a throwaway temp DB/audit file (mirroring the backend's own conftest)
before importing ``app.main``.
"""

from __future__ import annotations

import os
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

# --- make the in-repo unified package importable --------------------------- #
_HERE = Path(__file__).resolve()
_REPO_ROOT = _HERE.parents[3]  # repo root

if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# --- isolate backend state BEFORE importing the app ------------------------- #
_TMPDIR = tempfile.mkdtemp(prefix="agentauth-sdk-test-")
os.environ.setdefault("AGENTAUTH_DATABASE_URL", f"sqlite:///{_TMPDIR}/agents.db")

import pytest  # noqa: E402
import uvicorn  # noqa: E402

from clayseal.identity import ClaySeal  # noqa: E402
from clayseal.backend.main import app  # noqa: E402


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def base_url() -> str:
    """Boot a background uvicorn server for the test session."""
    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # Wait for startup (init_db runs on the startup event).
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("Test server failed to start.")
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def api_key(base_url: str) -> str:
    """Create a fresh tenant (no API key needed) and return its key."""
    tenant = ClaySeal.create_tenant("SDK Test Co", base_url=base_url)
    return tenant["api_key"]


@pytest.fixture
def auth(api_key: str, base_url: str) -> ClaySeal:
    client = ClaySeal(api_key=api_key, base_url=base_url, dev_attestation=True)
    yield client
    client.close()


@pytest.fixture
def transport():
    """Back-compat shim: some tests build their own client and only need the
    base URL, so expose ``None`` (real network) here."""
    return None
