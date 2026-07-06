"""Swappable L3 authorization providers, backed by the shared plugin registry.

Same mechanism as identity providers, one layer up: providers live in the
``capability_providers`` group of ``agentauth.core.plugins``, so a third-party package
adds one by declaring an ``agentauth.capability_providers`` entry point — no edit here.
The built-ins (native Biscuit, OPA, Cedar, OpenFGA) are registered lazily on first use.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from agentauth.core.plugins import get_plugin, list_plugins, register_plugin

if TYPE_CHECKING:
    from agentauth.core.identity_protocol import CapabilityProvider

_GROUP = "capability_providers"
_BUILTINS_LOADED = False


def register_capability_provider(provider: "CapabilityProvider") -> None:
    register_plugin(_GROUP, provider.name, provider)


def get_capability_provider(name: str = "agentauth") -> "CapabilityProvider":
    _ensure_loaded()
    try:
        return get_plugin(_GROUP, name)
    except KeyError:
        known = ", ".join(list_capability_providers())
        raise KeyError(
            f"unknown capability provider {name!r}; known: {known}. Register your own "
            "with register_capability_provider(), or install an extra for a built-in "
            "backend (agentauth-receipts[opa|cedar|openfga])."
        ) from None


def list_capability_providers() -> list[str]:
    _ensure_loaded()
    return list_plugins(_GROUP)


def _ensure_loaded() -> None:
    global _BUILTINS_LOADED
    if _BUILTINS_LOADED:
        return
    _BUILTINS_LOADED = True
    # External engines register unconditionally; their SDKs load lazily on first use.
    from agentauth.receipts.capability_providers import cedar as _cedar
    from agentauth.receipts.capability_providers import openfga as _openfga
    from agentauth.receipts.capability_providers import opa as _opa

    for mod in (_opa, _cedar, _openfga):
        register_capability_provider(mod.provider)

    # Native Biscuit provider only when the capabilities layer is importable, so receipts
    # can authorize through an external engine with no L2 installed.
    try:
        from agentauth.receipts.capability_providers import agentauth as _native
    except ImportError:
        pass
    else:
        register_capability_provider(_native.provider)
