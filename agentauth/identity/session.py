"""The agent-facing wrapper: ``AgentSession``.

This is the object the spec is built around - "the SDK wraps the agent, it
doesn't live inside it." A session holds an issued credential and exposes the
identity accessors and lifecycle verbs the developer needs at the boundary of
their agent:

    auth = AgentAuth(api_key=...)
    agent = auth.identify(agent_type="researcher", owner="alice@acme.ai",
                          capabilities=[{"resource": "db", "action": "read"}])

    agent.token              # the signed JWT-SVID to carry on outbound calls
    agent.can("db", "read")  # offline capability check (proof-of-possession)
    sub = agent.attenuate(capabilities=[...])  # narrow rights, offline
    agent.revoke()           # kill this credential
"""
from __future__ import annotations

import time
import uuid
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import serialization

from . import _capabilities as caps
from .errors import BiscuitError, CapabilityDeniedError, ProofOfPossessionError
from .models import Credential

if TYPE_CHECKING:  # avoid import cycle at runtime
    from .client import AgentAuth


class AgentSession:
    def __init__(
        self,
        client: AgentAuth,
        credential: Credential,
        *,
        workload_private_pem: str | None = None,
    ) -> None:
        self._client = client
        self.credential = credential
        # The workload's SPIFFE private key, used to sign proof-of-possession
        # for offline capability authorization. Present for identify()-issued
        # sessions; absent for rehydrated ones unless supplied.
        self._workload_private_pem = workload_private_pem

    # --- identity accessors ----------------------------------------------- #
    @property
    def token(self) -> str:
        return self.credential.token

    @property
    def agent_id(self) -> str:
        return self.credential.agent_id

    @property
    def scopes(self) -> list[str]:
        return self.credential.scopes

    @property
    def agent_type(self) -> str:
        return self.credential.agent_type

    @property
    def owner(self) -> str:
        return self.credential.owner

    # --- capability accessors ---------------------------------------------- #
    @property
    def biscuit(self) -> str | None:
        """The capability token (base64 Biscuit), if one was minted."""
        return self.credential.biscuit

    @property
    def capabilities(self) -> list[dict]:
        return self.credential.capabilities

    # --- lifecycle --------------------------------------------------------- #
    def revoke(self):
        """Revoke this agent's credential."""
        return self._client._http.post(f"/v1/agents/{self.agent_id}/revoke")

    def validate(self):
        """Validate this session's token (signature + expiry + status).

        If the token is sender-constrained (PoP-bound), this signs a fresh
        server challenge with the workload key so validation succeeds; a
        bare bearer presentation of such a token is rejected by design."""
        pop = None
        if self.credential.bound_keyhash and self._workload_private_pem is not None:
            challenge = self._client.server_challenge()
            iat = int(time.time())
            jti = uuid.uuid4().hex
            signature = caps.sign_request_pop(
                self._workload_private_pem,
                self._bound_keyhash(),
                challenge,
                htm="POST",
                htu="/v1/validate",
                ath=caps.token_hash(self.token),
                iat=iat,
                jti=jti,
                operation=("jwt", "validate"),
            )
            pop = {
                "challenge": challenge,
                "signature": signature,
                "pubkey_pem": self._workload_public_pem(),
                "htm": "POST",
                "htu": "/v1/validate",
                "ath": caps.token_hash(self.token),
                "iat": iat,
                "jti": jti,
            }
        return self._client.validate(self.token, pop=pop)

    # --- receipts (L3/L4) -------------------------------------------------- #
    def wrap(self, model, *, policy, task_mandate=None, **kwargs):
        """Wrap ``model`` in a receipting :class:`AgentWrapper` bound to *this*
        attested identity.

        This is the seam between the two layers: the session already holds a
        live, attested AgentAuth credential, so every receipt this wrapper
        produces carries the agent's verified SPIFFE identity, tenant, scopes,
        and proof-of-possession facts (via
        ``AuthorityBinding.from_agentauth_credential``)::

            agent = auth.identify(agent_type="researcher", owner="alice@acme.ai")
            receipted = agent.wrap(model, policy=policy)
            result = receipted.run({"transaction_id": "t1"})

        Pass ``task_mandate=`` with a signed human authorization envelope or
        AP2 mandate document to compile path scope onto the authority snapshot
        before the first action.

        Any keyword accepted by :class:`AgentWrapper` (``mode``, ``certificate``,
        ``audit_db``, ...) may be passed through. A caller may still override the
        binding per run; absent that, this identity is used.
        """
        from agentauth.receipts import AgentWrapper
        from agentauth.receipts.authority_binding import AuthorityBinding

        binding = AuthorityBinding.from_agentauth_credential(
            self.credential.to_binding_dict()
        )
        capability_authorizer = self.authorize if self.credential.biscuit else None
        if task_mandate is not None:
            kwargs["task_mandate"] = task_mandate
        return AgentWrapper(
            model,
            policy,
            default_authority_binding=binding,
            capability_authorizer=capability_authorizer,
            **kwargs,
        )

    # --- capabilities (offline) -------------------------------------------- #
    def authorize(
        self,
        resource: str,
        action: str,
        *,
        challenge: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> dict:
        """Decide whether this token authorizes ``(resource, action)``, fully
        offline. Signs proof-of-possession with the workload key. Returns
        ``{"allowed": bool, "reason": str}``."""
        token, root_pub = self._require_biscuit()
        if self._workload_private_pem is None:
            raise ProofOfPossessionError(
                "Cannot prove possession: this session has no workload private key.",
                suggestion="Use a session created by identify(), or pass "
                "workload_private_pem to session_from_token().",
            )
        challenge = challenge or caps.issue_challenge()
        keyhash = self._bound_keyhash()
        iat = int(time.time())
        jti = uuid.uuid4().hex
        signature = caps.sign_request_pop(
            self._workload_private_pem,
            keyhash,
            challenge,
            htm="OFFLINE",
            htu="agentauth:authorize",
            ath=caps.token_hash(token),
            iat=iat,
            jti=jti,
            operation=(resource, action),
        )
        pop = caps.PopProof(
            challenge=challenge,
            signature_b64=signature,
            pubkey_pem=self._workload_public_pem(),
            htm="OFFLINE",
            htu="agentauth:authorize",
            ath=caps.token_hash(token),
            iat=iat,
            jti=jti,
        )
        return caps.authorize_biscuit(
            token_b64=token,
            root_public_hex=root_pub,
            operation=(resource, action),
            pop=pop,
            expected_htm="OFFLINE",
            expected_htu="agentauth:authorize",
            file_path=file_path,
        )

    def can(
        self,
        resource: str,
        action: str,
        *,
        file_path: Optional[str] = None,
    ) -> bool:
        """``True`` if this token authorizes ``(resource, action)`` (offline)."""
        return bool(self.authorize(resource, action, file_path=file_path).get("allowed"))

    def can_read_path(self, path: str) -> bool:
        """Shorthand for file read authorization with path-scope facts (SM-7)."""
        from agentauth.biscuit_scope import FILE_RESOURCE

        return self.can(FILE_RESOURCE, "read", file_path=path)

    def enforce(self, resource: str, action: str, *, file_path: Optional[str] = None) -> None:
        """Raise :class:`CapabilityDeniedError` unless the operation is allowed."""
        result = self.authorize(resource, action, file_path=file_path)
        if not result.get("allowed"):
            raise CapabilityDeniedError(
                f"Capability token does not allow {resource}:{action}.",
                code="capability_denied",
                suggestion=result.get("reason", ""),
            )

    def attenuate(
        self,
        *,
        capabilities: Optional[list[dict]] = None,
        path_patterns: Optional[list[str]] = None,
        denied_paths: Optional[list[str]] = None,
        expires_at=None,
    ) -> AgentSession:
        """Return a NEW session whose capability token is narrowed to a subset of
        rights (and/or a tighter expiry), produced offline. The narrowed token
        can never claw back a right -- Biscuit blocks only restrict."""
        token, root_pub = self._require_biscuit()
        narrowed = caps.attenuate_biscuit(
            token_b64=token,
            root_public_hex=root_pub,
            capabilities=capabilities,
            path_patterns=path_patterns,
            denied_paths=denied_paths,
            expires_at=expires_at,
        )
        new_cred = Credential.from_api(
            {
                **self.credential.__dict__,
                "biscuit": narrowed,
                "capabilities": list(capabilities or self.credential.capabilities),
            }
        )
        return AgentSession(
            self._client, new_cred, workload_private_pem=self._workload_private_pem
        )

    def attenuate_for_task_scope(self, mandate: dict) -> "AgentSession":
        """Narrow the Biscuit to path patterns from a signed mandate (SM-7)."""
        from agentauth.capabilities.task_scope import compile_task_scope

        scope = compile_task_scope(mandate)
        return self.attenuate(
            path_patterns=list(scope.allowed_paths) or None,
            denied_paths=list(scope.denied_paths) or None,
        )

    def delegate(self, *, capabilities: list[dict]) -> str:
        """Produce a narrowed capability token (base64) to hand to a sub-agent.

        The delegated token is offline-attenuated to ``capabilities`` and stays
        bound to this workload's SPIFFE key, so the sub-agent operates within
        this workload's key/trust boundary with least privilege."""
        token, root_pub = self._require_biscuit()
        return caps.attenuate_biscuit(
            token_b64=token, root_public_hex=root_pub, capabilities=capabilities
        )

    # --- internal helpers -------------------------------------------------- #
    def _require_biscuit(self) -> tuple[str, str]:
        if not self.credential.biscuit or not self.credential.biscuit_root_public_key:
            raise BiscuitError(
                "This session has no capability token.",
                suggestion="Issue with capabilities and a workload key (the SDK does "
                "this automatically via identify()).",
            )
        return self.credential.biscuit, self.credential.biscuit_root_public_key

    def _bound_keyhash(self) -> str:
        if self.credential.bound_keyhash:
            return self.credential.bound_keyhash
        return caps.keyhash_for_pem(self._workload_public_pem())

    def _workload_public_pem(self) -> str:
        private = serialization.load_pem_private_key(
            self._workload_private_pem.encode(), password=None
        )
        return (
            private.public_key()
            .public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            .decode()
        )
