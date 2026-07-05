"""Optional L1 identity bootstrap for benchmark runs (embedded AgentAuth backend)."""

from __future__ import annotations

import os
import socket
import tempfile
import threading
import time
from typing import Any

from harness.paths import REPO_ROOT, ensure_import_paths


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _boot_embedded_backend() -> str:
    ensure_import_paths()
    tmp = tempfile.mkdtemp(prefix="agentauth-bench-")
    os.environ.setdefault("AGENTAUTH_DATABASE_URL", f"sqlite:///{tmp}/agents.db")

    import uvicorn

    from agentauth.backend.main import app  # noqa: WPS433

    port = _free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 10
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    if not server.started:
        raise RuntimeError("embedded AgentAuth backend failed to start")
    return f"http://127.0.0.1:{port}"


def identify_dev_agent(*, agent_type: str = "benchmark-runner") -> dict[str, Any]:
    ensure_import_paths()
    from agentauth import AgentAuth
    from agentauth.receipts.authority_binding import AuthorityBinding

    base_url = os.getenv("AGENTAUTH_BASE_URL") or _boot_embedded_backend()
    tenant = AgentAuth.create_tenant("Benchmark Harness", base_url=base_url)
    client = AgentAuth(
        api_key=tenant["api_key"],
        base_url=base_url,
        dev_attestation=True,
    )
    session = client.identify(
        agent_type=agent_type,
        owner="benchmark-harness",
        ttl_seconds=3600,
    )
    credential = session.credential
    binding = AuthorityBinding.from_agentauth_credential(credential.to_binding_dict())
    # Embed the signed JWT-SVID + issuer JWKS so receipts authenticate the attested
    # identity offline (identity_evidence.identity_issues).
    from agentauth.receipts.identity_evidence import build_identity_section

    jwks = client._http.get("/v1/jwks.json")
    identity_section = build_identity_section(
        {
            "token": credential.token,
            "spiffe_id": credential.spiffe_id,
            "bound_keyhash": credential.bound_keyhash,
            "biscuit": credential.biscuit,
            "biscuit_root_public_key": credential.biscuit_root_public_key,
            "expires_at": credential.expires_at,
        },
        jwks,
    )
    return {
        "client": client,
        "session": session,
        "credential": credential,
        "authority_binding": binding,
        "identity_section": identity_section,
        "base_url": base_url,
    }
