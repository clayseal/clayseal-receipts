"""Shared HTTP delivery for exporters (httpx, injectable client for tests)."""

from __future__ import annotations

from typing import Any


def post_json(
    url: str,
    payload: Any,
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
    client: Any | None = None,
) -> Any:
    """POST JSON and raise on non-2xx. ``client`` accepts any httpx-compatible object."""
    from agentauth.core.safe_http import validate_outbound_url

    validated = validate_outbound_url(url)
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
    from agentauth.core.safe_http import validate_outbound_url

    validated = validate_outbound_url(url)
    if client is not None:
        response = client.put(validated, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
    import httpx

    with httpx.Client(timeout=timeout, follow_redirects=False) as http:
        response = http.put(validated, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
