from __future__ import annotations

import threading
from typing import Any

from harness.bootstrap import _boot_embedded_backend
from harness.paths import ensure_import_paths

_lock = threading.Lock()
_backend_url: str | None = None


def shared_backend_url() -> str:
    """One embedded AgentAuth backend per process (shared SQLite for tenant tests)."""
    global _backend_url
    with _lock:
        if _backend_url is None:
            _backend_url = _boot_embedded_backend()
        return _backend_url


def reset_shared_backend_for_tests() -> None:
    global _backend_url
    with _lock:
        _backend_url = None


def create_tenant_client(tenant_name: str) -> Any:
    ensure_import_paths()
    from agentauth import AgentAuth

    base_url = shared_backend_url()
    tenant = AgentAuth.create_tenant(tenant_name, base_url=base_url)
    return AgentAuth(
        api_key=tenant["api_key"],
        base_url=base_url,
        dev_attestation=True,
    )


def identify_agent(client: Any, *, agent_type: str, owner: str) -> Any:
    return client.identify(agent_type=agent_type, owner=owner, ttl_seconds=3600)
