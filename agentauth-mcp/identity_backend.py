"""Embedded AgentAuth identity backend.

Minting a JWT-SVID + Biscuit capability token requires the AgentAuth backend.
Rather than depend on a separate service, the gate boots the backend in-process
against a throwaway sqlite DB (the recipe from agent-receipts/examples/common.py)
and holds it for the life of the MCP server. Returns a dev-attestation AgentAuth
client that can issue task-scoped credentials offline-verifiably.
"""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from dataclasses import dataclass


@dataclass
class EmbeddedBackend:
    base_url: str
    api_key: str
    client: object  # agentauth.AgentAuth (dev_attestation=True)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def boot_embedded_backend(org: str) -> EmbeddedBackend:
    """Start the AgentAuth backend in-process and create a fresh tenant.

    Mirrors examples/common.py:_boot_embedded + bootstrap(). The uvicorn server
    runs on a daemon thread, so it dies with the parent process; the sqlite DB is
    a throwaway temp file.
    """
    tmp = tempfile.mkdtemp(prefix="agentauth-mcp-")
    os.environ.setdefault("AGENTAUTH_DATABASE_URL", f"sqlite:///{tmp}/agents.db")

    import uvicorn

    # Imported after the DB env is set, exactly like the example recipe.
    from agentauth.backend.main import app

    port = _free_port()
    # access_log defaults to stdout in uvicorn — disable it so the embedded
    # backend never writes to stdout (stdio transport reserves stdout for JSON-RPC).
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
        )
    )
    threading.Thread(target=server.run, daemon=True).start()

    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("Embedded AgentAuth backend failed to start.")

    base_url = f"http://127.0.0.1:{port}"

    from agentauth import AgentAuth

    tenant = AgentAuth.create_tenant(org, base_url=base_url)
    # dev_attestation is allowed because the backend is on localhost.
    client = AgentAuth(api_key=tenant["api_key"], base_url=base_url, dev_attestation=True)
    return EmbeddedBackend(base_url=base_url, api_key=tenant["api_key"], client=client)
