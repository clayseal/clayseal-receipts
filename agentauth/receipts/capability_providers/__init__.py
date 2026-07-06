"""Swappable L3 authorization providers for the receipts runtime.

The receipts→capabilities authorization dependency is reachable through one seam: look
up a ``CapabilityProvider`` by name and call ``authorize`` / ``check_path``. The native
``agentauth`` provider wraps the Biscuit layer; ``opa`` / ``cedar`` / ``openfga`` map
onto external policy engines; ``from_callable`` wraps a user function. Bring your own by
implementing ``agentauth.core.identity_protocol.CapabilityProvider`` and either calling
``register_capability_provider`` or declaring an ``agentauth.capability_providers``
entry point.
"""
from __future__ import annotations

from agentauth.core.identity_protocol import CapabilityDecision, CapabilityProvider
from agentauth.receipts.capability_providers.registry import (
    get_capability_provider,
    list_capability_providers,
    register_capability_provider,
)
from agentauth.receipts.capability_providers.user_schema import from_callable

__all__ = [
    "CapabilityDecision",
    "CapabilityProvider",
    "get_capability_provider",
    "list_capability_providers",
    "register_capability_provider",
    "from_callable",
]
