"""Thin HTTP transport around the AgentAuth REST API.

Responsibilities:
- attach the tenant ``X-API-Key`` and base URL,
- translate the backend's ``{error:{code,message,suggestion}}`` envelope into
  typed :class:`~agentauth.errors.AgentAuthError` subclasses,
- stay injectable: tests pass an ``httpx`` transport that targets the FastAPI
  app in-process (``httpx.ASGITransport``) so the whole SDK is exercised with no
  network and no running server.
"""
from __future__ import annotations

from typing import Any, Optional

import httpx

from .errors import TransportError, from_envelope


class HttpClient:
    def __init__(
        self,
        base_url: str,
        api_key: Optional[str] = None,
        *,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        default_headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            default_headers["X-API-Key"] = api_key
        if headers:
            default_headers.update(headers)
        # ``transport`` lets tests bind to the ASGI app; in production httpx
        # opens real connections to ``base_url``.
        self._client = httpx.Client(
            base_url=self.base_url,
            headers=default_headers,
            timeout=timeout,
            transport=transport,
        )

    # --- lifecycle --------------------------------------------------------- #
    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- core request ------------------------------------------------------ #
    def request(
        self,
        method: str,
        path: str,
        *,
        json: Optional[dict] = None,
        params: Optional[dict] = None,
    ) -> Any:
        try:
            resp = self._client.request(method, path, json=json, params=params)
        except httpx.HTTPError as exc:  # network/timeout/connect
            raise TransportError(
                f"Could not reach AgentAuth at {self.base_url}: {exc}",
                suggestion="Check AGENTAUTH_BASE_URL and that the service is reachable.",
            ) from exc

        if resp.status_code >= 400:
            payload: dict = {}
            try:
                payload = resp.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict) and "error" in payload:
                raise from_envelope(payload, resp.status_code)
            raise TransportError(
                f"Request to {path} failed with HTTP {resp.status_code}.",
                suggestion="Inspect the response body; this was not a structured AgentAuth error.",
                status_code=resp.status_code,
            )

        if resp.status_code == 204 or not resp.content:
            return None
        try:
            return resp.json()
        except ValueError:
            return resp.text

    # --- verbs ------------------------------------------------------------- #
    def get(self, path: str, *, params: Optional[dict] = None) -> Any:
        return self.request("GET", path, params=params)

    def post(self, path: str, *, json: Optional[dict] = None, params: Optional[dict] = None) -> Any:
        return self.request("POST", path, json=json, params=params)

    def put(self, path: str, *, json: Optional[dict] = None) -> Any:
        return self.request("PUT", path, json=json)

    def delete(self, path: str) -> Any:
        return self.request("DELETE", path)
