"""Server-side session store.

Devin (a closed agent) cannot perform proof-of-possession crypto, so the live
AgentSession — which holds the workload private key — never leaves this process.
The agent receives only an opaque ``session_token``; every subsequent tool call
re-looks-up the server-side state by that token. PoP signing happens here.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SessionEntry:
    token: str
    agent_session: Any        # agentauth.AgentSession (holds JWT, biscuit, workload key)
    wrapper: Any              # agentauth.AgentWrapper (mode="prove")
    mandate_id: str
    agent_actor: str
    issue_ref: str
    created_at: float
    authority_summary: dict[str, Any]
    # Accumulated per-action signed receipt bundles for this session.
    receipts: list[dict[str, Any]] = field(default_factory=list)


class SessionStore:
    """Thread-safe opaque-token -> SessionEntry map."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, SessionEntry] = {}

    def create(
        self,
        *,
        agent_session: Any,
        wrapper: Any,
        mandate_id: str,
        agent_actor: str,
        issue_ref: str,
        authority_summary: dict[str, Any],
    ) -> SessionEntry:
        token = "aags_" + secrets.token_urlsafe(24)
        entry = SessionEntry(
            token=token,
            agent_session=agent_session,
            wrapper=wrapper,
            mandate_id=mandate_id,
            agent_actor=agent_actor,
            issue_ref=issue_ref,
            created_at=time.time(),
            authority_summary=authority_summary,
        )
        with self._lock:
            self._entries[token] = entry
        return entry

    def get(self, token: str) -> SessionEntry | None:
        with self._lock:
            return self._entries.get(token or "")

    def require(self, token: str) -> SessionEntry:
        entry = self.get(token)
        if entry is None:
            raise KeyError(
                "unknown or expired session_token — call begin_authorized_session first"
            )
        return entry
