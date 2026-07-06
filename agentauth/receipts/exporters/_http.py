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
    if client is not None:
        response = client.post(url, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
    import httpx

    with httpx.Client(timeout=timeout) as http:
        response = http.post(url, json=payload, headers=headers or {})
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
    if client is not None:
        response = client.put(url, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
    import httpx

    with httpx.Client(timeout=timeout) as http:
        response = http.put(url, json=payload, headers=headers or {})
        response.raise_for_status()
        return response
