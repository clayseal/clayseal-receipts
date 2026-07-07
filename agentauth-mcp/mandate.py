"""Human authorization mandate: load, verify, and translate to a capability grant.

The mandate is a human-signed ``agentauth.human_authorization.v1`` envelope whose
scope IS a capability grant: explicit ``{resource, action}`` pairs the maintainer
authorizes for one task. This module verifies its Ed25519 signature and hands those
descriptors to ``AgentAuth.identify`` to mint the Biscuit. Scope lives only in the
token — there is no allow/deny path list, no diff evaluator, and the grant is never
shown to the agent (it discovers scope by calling ``authorize_action``).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentauth.core import signing

MANDATE_SCHEMA = "agentauth.human_authorization.v1"


@dataclass(frozen=True)
class Mandate:
    document: dict[str, Any]
    signature: dict[str, Any]

    # --- scope accessors ------------------------------------------------------ #
    @property
    def mandate_id(self) -> str:
        return str(self.document.get("mandate_id", "unknown"))

    @property
    def scope(self) -> dict[str, Any]:
        return self.document.get("scope", {})

    @property
    def required_tests(self) -> list[str]:
        return [str(t) for t in self.scope.get("required_tests", [])]

    @property
    def task(self) -> dict[str, Any]:
        return self.document.get("task", {})

    @property
    def principal(self) -> str:
        return str(self.document.get("authorized_by", {}).get("principal", "unknown"))

    @property
    def agent_actor_patterns(self) -> list[str]:
        return [str(p) for p in self.document.get("agent", {}).get("github_actor_patterns", [])]

    @property
    def signer_key_id(self) -> str:
        return str(self.signature.get("key_id", ""))

    def capabilities(self) -> list[dict[str, str]]:
        """The human-signed capability grant: explicit ``{resource, action}`` pairs.

        This IS the scope — there is no separate allow/deny path list. It is minted
        into the agent's Biscuit token and is NEVER surfaced to the agent: the agent
        learns what it may touch only by calling ``authorize_action`` and getting an
        allow/deny back from the token itself. Anything not granted is denied.
        """
        grants: list[dict[str, str]] = []
        for cap in self.scope.get("capabilities", []):
            if isinstance(cap, dict) and cap.get("resource") and cap.get("action"):
                grants.append({"resource": str(cap["resource"]), "action": str(cap["action"])})
        return grants

    def scopes(self) -> list[str]:
        """``resource:action`` strings mirroring the capabilities (for the JWT)."""
        return [f"{c['resource']}:{c['action']}" for c in self.capabilities()]


class MandateError(RuntimeError):
    pass


def load_mandate(path: str | Path, *, trusted_key_id: str | None = None) -> Mandate:
    """Load and cryptographically verify a human authorization mandate.

    Verifies the Ed25519 signature over ``document``. If ``trusted_key_id`` (or
    ``AGENTAUTH_MCP_TRUSTED_MANDATE_KEY_ID``) is set, the signer key id must match
    it (provenance pinning); otherwise the embedded-key signature is accepted for
    integrity only.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    document = raw.get("document")
    signature = raw.get("signature")
    if not isinstance(document, dict) or not isinstance(signature, dict):
        raise MandateError(f"malformed mandate at {path}: missing document/signature")

    if document.get("schema") != MANDATE_SCHEMA:
        raise MandateError(
            f"unexpected mandate schema {document.get('schema')!r}; expected {MANDATE_SCHEMA}"
        )

    if not signing.verify(document, signature):
        raise MandateError(
            "mandate signature is invalid — refusing to issue authority (fail closed)"
        )

    pinned = trusted_key_id or os.environ.get("AGENTAUTH_MCP_TRUSTED_MANDATE_KEY_ID")
    if pinned and signature.get("key_id") != pinned:
        raise MandateError(
            "mandate is signed by an untrusted key id (does not match pinned maintainer key)"
        )

    return Mandate(document=document, signature=signature)


def write_signed_mandate(
    path: str | Path, document: dict[str, Any], key: signing.SigningKey
) -> dict[str, Any]:
    """Sign ``document`` and persist the full envelope (helper for setup/tests)."""
    envelope = {"document": document, "signature": key.sign(document)}
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(envelope, indent=2), encoding="utf-8")
    return envelope
