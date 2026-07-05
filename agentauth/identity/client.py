"""``AgentAuth`` - the tenant-level entry point.

Created once per process with your API key. Issues agent identities and exposes
the read/admin surface (agents) that mirrors the backend identity router 1:1, so
dashboards and scripts can use the same client.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import httpx

from ._http import HttpClient
from .errors import AgentAuthError
from .logging import get_logger
from .models import AgentInfo, Credential, ValidationResult
from .session import AgentSession

DEFAULT_BASE_URL = "http://localhost:8000"
DEV_ATTESTOR_ENV = "AGENTAUTH_DEV_ATTESTOR"
UNSAFE_DEV_ATTESTOR_ENV = "AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR"


def _env_truthy(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_local_base_url(base_url: str) -> bool:
    parsed = urlparse(base_url)
    host = (parsed.hostname or "").strip().lower()
    return host in {"localhost", "127.0.0.1", "::1"}


class AgentAuth:
    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        log_format: str | None = None,
        dev_attestation: bool | None = None,
        mtls_cert: str | None = None,
        mtls_key: str | None = None,
        mtls_ca: str | None = None,
    ) -> None:
        api_key = api_key or os.getenv("AGENTAUTH_API_KEY")
        base_url = base_url or os.getenv("AGENTAUTH_BASE_URL") or DEFAULT_BASE_URL
        self.base_url = base_url

        mtls_cert = mtls_cert or os.getenv("AGENTAUTH_MTLS_CERT_FILE")
        mtls_key = mtls_key or os.getenv("AGENTAUTH_MTLS_KEY_FILE")
        mtls_ca = mtls_ca or os.getenv("AGENTAUTH_MTLS_CA_FILE")
        if mtls_cert and mtls_key and transport is None:
            import ssl
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ssl_ctx.load_cert_chain(certfile=mtls_cert, keyfile=mtls_key)
            if mtls_ca:
                ssl_ctx.load_verify_locations(cafile=mtls_ca)
            else:
                ssl_ctx.load_default_certs()
            transport = httpx.HTTPTransport(ssl_context=ssl_ctx)

        self._http = HttpClient(
            base_url, api_key, timeout=timeout, transport=transport
        )
        self._logger = get_logger(log_format=log_format)
        self._dev_attestation = (
            _env_truthy(DEV_ATTESTOR_ENV) if dev_attestation is None else dev_attestation
        )
        self._dev_attestor = None  # created lazily when explicit dev attestation is enabled
        self._biscuit_root_pub: str | None = None  # cached root public key

    # --- lifecycle --------------------------------------------------------- #
    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> AgentAuth:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- tenant bootstrap (no API key required) ---------------------------- #
    @classmethod
    def create_tenant(
        cls,
        name: str,
        *,
        base_url: str | None = None,
        transport: httpx.BaseTransport | None = None,
    ) -> dict:
        """Sign up a new tenant; returns ``{customer_id, name, api_key}``.

        The API key is shown once - persist it. Convenience for first-run
        scripts and tests; production tenants are usually created in the
        dashboard.
        """
        base = base_url or os.getenv("AGENTAUTH_BASE_URL") or DEFAULT_BASE_URL
        http = HttpClient(base, None, transport=transport)
        try:
            return http.post("/v1/customers", json={"name": name})
        finally:
            http.close()

    # --- identity ---------------------------------------------------------- #
    def identify(
        self,
        agent_type: str,
        owner: str,
        scopes: list[str] | None = None,
        *,
        capabilities: list[dict] | None = None,
        ttl_seconds: int | None = None,
        attestation_document: str | None = None,
        workload_private_pem: str | None = None,
    ) -> AgentSession:
        """Issue a fresh agent credential and return a wrapped session.

        Production callers pass ``attestation_document`` from their platform or
        SPIRE-facing agent. The backend derives agent type, owner, scopes, and
        capabilities from the matched registration entry; the local arguments are
        only the developer-facing intent and are used by the opt-in dev attestor.

        For local demos/tests, construct ``AgentAuth(..., dev_attestation=True)``
        or set ``AGENTAUTH_DEV_ATTESTOR=1``. That mode self-registers a throwaway
        node trust anchor + registration entry and is allowed only against a
        localhost backend unless ``AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR=1`` is set.

        Authorization is expressed as fine-grained ``capabilities`` (a list of
        ``{"resource", "action"}`` dicts); legacy ``scopes`` are still accepted
        and parsed into capabilities. The returned session carries a Biscuit
        capability token bound to the workload's SPIFFE key, so the agent can
        attenuate, delegate, and authorize **offline**.
        """
        if attestation_document is None:
            if not self._dev_attestation:
                raise AgentAuthError(
                    "identify() requires an attestation_document.",
                    code="attestation_required",
                    suggestion=(
                        "Pass a platform-issued attestation document, or enable "
                        "AgentAuth(..., dev_attestation=True) for localhost-only demos/tests."
                    ),
                )
            if not _is_local_base_url(self.base_url) and not _env_truthy(UNSAFE_DEV_ATTESTOR_ENV):
                raise AgentAuthError(
                    "Dev attestation is restricted to localhost backends.",
                    code="dev_attestation_remote_denied",
                    suggestion=(
                        "Use platform-issued attestation for remote services. For an isolated "
                        "test environment only, set AGENTAUTH_ALLOW_REMOTE_DEV_ATTESTOR=1."
                    ),
                )
            attestation_document, workload_private_pem = self._dev_attestation_document(
                agent_type=agent_type,
                owner=owner,
                scopes=scopes or [],
                capabilities=capabilities,
            )
        data = self.identify_with_attestation(
            attestation_document,
            ttl_seconds=ttl_seconds,
        )
        return AgentSession(
            self,
            Credential.from_api(data),
            workload_private_pem=workload_private_pem,
        )

    def _dev_attestation_document(
        self,
        *,
        agent_type: str,
        owner: str,
        scopes: list[str],
        capabilities: list[dict] | None,
    ) -> tuple[str, str]:
        if self._dev_attestor is None:
            from ._devattest import DevAttestor

            self._dev_attestor = DevAttestor()
        document = self._dev_attestor.attestation_document(
            self._http, agent_type, scopes, capabilities, owner
        )
        return document, self._dev_attestor.workload_private_pem

    def identify_with_attestation(
        self,
        attestation_document: str,
        *,
        ttl_seconds: int | None = None,
    ) -> dict:
        """Send a platform-issued attestation document to the backend.

        This is the production issuance path. It returns the raw credential
        payload so callers that hold the workload private key can pass it to
        :meth:`session_from_token` with ``workload_private_pem``.
        """
        body: dict = {"attestation_document": attestation_document}
        if ttl_seconds is not None:
            body["ttl_seconds"] = ttl_seconds
        return self._http.post("/v1/identify", json=body)

    def biscuit_root_public_key(self) -> str | None:
        """Fetch (and cache) this customer's active Biscuit root public key, for
        verifying capability tokens offline."""
        if self._biscuit_root_pub is None:
            data = self._http.get("/v1/biscuit-keys.json")
            for key in data.get("keys", []):
                if key.get("status") == "active":
                    self._biscuit_root_pub = key["public_key"]
                    break
        return self._biscuit_root_pub

    def session_from_token(
        self, credential_data: dict, *, workload_private_pem: str | None = None
    ) -> AgentSession:
        """Rehydrate a session from a previously issued credential payload.

        Pass ``workload_private_pem`` to re-enable offline capability operations
        (proof-of-possession needs the workload private key)."""
        return AgentSession(
            self,
            Credential.from_api(credential_data),
            workload_private_pem=workload_private_pem,
        )

    def validate(
        self, token: str, *, pop: dict | None = None
    ) -> ValidationResult:
        """Validate a token (signature + expiry + revocation status).

        Sender-constrained (PoP-bound) tokens additionally require a
        proof-of-possession: pass ``pop={"challenge", "signature", "pubkey_pem"}``
        or, more simply, call :meth:`AgentSession.validate`, which builds it for
        you from the workload key.
        """
        body: dict = {"token": token}
        if pop is not None:
            body["pop"] = pop
        data = self._http.post("/v1/validate", json=body)
        return ValidationResult.from_api(data)

    def server_challenge(self) -> str:
        """Fetch a one-time server challenge for the proof-of-possession path."""
        return self._http.post("/v1/challenge")["challenge"]

    # --- agents (admin/read) ----------------------------------------------- #
    def agents(
        self, *, status: str | None = None, agent_type: str | None = None
    ) -> list[AgentInfo]:
        params = {}
        if status:
            params["status"] = status
        if agent_type:
            params["agent_type"] = agent_type
        data = self._http.get("/v1/agents", params=params or None)
        return [AgentInfo.from_api(a) for a in data]

    def agent(self, agent_id: str) -> AgentInfo:
        return AgentInfo.from_api(self._http.get(f"/v1/agents/{agent_id}"))

    def revoke(self, agent_id: str) -> AgentInfo:
        return AgentInfo.from_api(self._http.post(f"/v1/agents/{agent_id}/revoke"))
