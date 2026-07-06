"""Swappable authorization seam (agentauth.receipts.capability_providers) via plugins."""
from __future__ import annotations

import pytest

from agentauth.core import plugins
from agentauth.core.identity_protocol import CapabilityDecision, CapabilityProvider
from agentauth.receipts import capability_providers as cp
from agentauth.receipts.integration import authorizer_from_provider, resolve_capability_provider


def test_builtin_providers_registered_in_plugin_group():
    names = cp.list_capability_providers()
    assert {"opa", "cedar", "openfga", "casbin"}.issubset(set(names))
    # And they live in the shared plugin registry under the capability_providers group.
    assert set(cp.list_capability_providers()) == set(plugins.list_plugins("capability_providers"))


def test_every_provider_satisfies_protocol():
    for name in cp.list_capability_providers():
        assert isinstance(cp.get_capability_provider(name), CapabilityProvider)


def test_unknown_provider_raises():
    with pytest.raises(KeyError):
        cp.get_capability_provider("nope")


def test_native_provider_uses_capability_authorizer():
    provider = cp.get_capability_provider("agentauth")  # needs capabilities installed
    ctx = {"capability_authorizer": lambda resource, action: {"allowed": action == "read"}}
    assert provider.authorize(action="read", resource="db", context=ctx).allowed is True
    assert provider.authorize(action="write", resource="db", context=ctx).allowed is False


def test_from_callable_registers_and_resolves():
    cp.register_capability_provider(cp.from_callable(lambda a, r, c: a == "read", name="ro"))
    assert cp.get_capability_provider("ro").authorize(action="read", resource="x").allowed
    assert not cp.get_capability_provider("ro").authorize(action="write", resource="x").allowed


def test_resolve_accepts_name_or_object():
    obj = cp.from_callable(lambda a, r, c: True, name="inline")
    assert resolve_capability_provider(obj) is obj
    assert resolve_capability_provider(None) is None
    assert resolve_capability_provider("opa").name == "opa"


def test_authorizer_from_provider_shapes_dict_for_wrapper():
    provider = cp.from_callable(
        lambda a, r, c: {"allowed": a == "read", "reason": "policy", "metadata": {"engine": "x"}},
        name="shaped",
    )
    authz = authorizer_from_provider(provider)
    ok = authz("db", "read")  # wrapper calls (resource, action)
    assert ok["allowed"] is True and ok["reason"] == "policy" and ok["engine"] == "x"
    assert authz("db", "write")["allowed"] is False


def test_opa_maps_object_result(monkeypatch):
    import httpx

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"result": {"allow": True, "reason": "matched", "obligations": [1]}}

    monkeypatch.setattr(httpx, "post", lambda url, json, timeout: _Resp())
    d = cp.get_capability_provider("opa").authorize(
        action="read", resource="db", context={"opa_decision_path": "authz/allow"}
    )
    assert d.allowed and d.reason == "matched" and d.obligations == [1]


def test_generic_plugin_registry_is_the_swap_point():
    # Any seam is swappable through the same registry the layers resolve against.
    sentinel = object()
    plugins.register_plugin("my_seam", "impl", sentinel)
    assert plugins.get_plugin("my_seam", "impl") is sentinel
    assert "impl" in plugins.list_plugins("my_seam")


@pytest.fixture
def _restore_biscuit_backend():
    """Snapshot and restore the ("capability_backends","biscuit") registration so tests
    that override it don't leak a fake backend into the rest of the session."""
    grp = plugins._REGISTRY.get("capability_backends", {})
    saved = grp.get("biscuit", None)
    try:
        yield
    finally:
        grp = plugins._REGISTRY.setdefault("capability_backends", {})
        if saved is None:
            grp.pop("biscuit", None)
        else:
            grp["biscuit"] = saved


def test_capability_backends_seam_is_live_after_resolution(_restore_biscuit_backend):
    pytest.importorskip("biscuit_auth", reason="native backend needs biscuit-python")
    from agentauth.capabilities.integration import default_biscuit_backend

    default_biscuit_backend()  # resolving the native backend registers it
    assert "biscuit" in plugins.list_plugins("capability_backends")


def test_user_override_wins_for_capability_backend(_restore_biscuit_backend):
    marker = object()
    plugins.register_plugin("capability_backends", "biscuit", marker)
    from agentauth.capabilities.integration import default_biscuit_backend

    assert default_biscuit_backend() is marker


def test_conformance_kit_passes_conforming_provider():
    provider = cp.from_callable(lambda a, r, c: a == "read", name="ro2")
    problems = cp.check_capability_provider(
        provider,
        samples=[
            {"action": "read", "resource": "db", "expected": True},
            {"action": "write", "resource": "db", "expected": False},
        ],
    )
    assert problems == []


def test_conformance_kit_flags_wrong_decision_and_bad_provider():
    wrong = cp.from_callable(lambda a, r, c: True, name="always")  # allows everything
    problems = cp.check_capability_provider(
        wrong, samples=[{"action": "write", "resource": "db", "expected": False}]
    )
    assert problems and "expected allowed=False" in problems[0]

    class NotAProvider:
        name = "broken"

    assert any("authorize" in p for p in cp.check_capability_provider(NotAProvider(), []))


def test_decision_is_truthy():
    assert bool(CapabilityDecision(allowed=True)) is True
    assert bool(CapabilityDecision(allowed=False)) is False
