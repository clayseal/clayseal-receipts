"""Shared HTTP delivery for exporters (httpx, injectable client for tests)."""

from __future__ import annotations

import ipaddress
import os
from typing import Any
from urllib.parse import urlsplit, urlunsplit

_PRODUCTION_ENVS = {"production", "prod"}


def _deployment_is_production() -> bool:
    return any(
        os.environ.get(name, "").strip().lower() in _PRODUCTION_ENVS
        for name in ("AGENTAUTH_ENV", "AGENT_RECEIPTS_ENV")
    )


def _is_loopback_http(url: str) -> bool:
    parts = urlsplit(url)
    if parts.scheme != "http":
        return False
    host = (parts.hostname or "").strip().lower()
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _validate_delivery_url(url: str, *, client: Any | None = None) -> str:
    """Validate exporter delivery URLs without blocking local dev collectors.

    Exporters are often smoke-tested against loopback collectors (for example a
    local OTLP collector). Production remains HTTPS + allowlist via core
    safe_http; injected clients are treated as explicit transports and skip DNS.
    """
    from agentauth.core.safe_http import validate_outbound_url

    if client is None and _is_loopback_http(url) and not _deployment_is_production():
        parts = urlsplit(url)
        if parts.username or parts.password:
            from agentauth.core.safe_http import SafeHttpError

            raise SafeHttpError("outbound URL must not embed credentials")
        if parts.fragment:
            from agentauth.core.safe_http import SafeHttpError

            raise SafeHttpError("outbound URL must not carry a fragment")
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))

    return validate_outbound_url(
        url,
        require_https=client is None,
        resolve_dns=client is None,
    )


def post_json(
    url: str,
    payload: Any,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    client: Any | None = None,
) -> Any:
    """POST JSON and raise on non-2xx. ``client`` accepts any httpx-compatible object."""
    validated = _validate_delivery_url(url, client=client)
    if client is not None:
        response = client.post(validated, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False) as http:
        response = http.post(validated, json=payload, headers=headers or {})
        response.raise_for_status()
        return response


def put_json(
    url: str,
    payload: Any,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    client: Any | None = None,
) -> Any:
    """PUT JSON and raise on non-2xx. ``client`` accepts any httpx-compatible object."""
    validated = _validate_delivery_url(url, client=client)
    if client is not None:
        response = client.put(validated, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False) as http:
        response = http.put(validated, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
