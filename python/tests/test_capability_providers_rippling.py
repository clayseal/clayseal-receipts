"""Real-query authorization tests over the Rippling harness policy.

Instead of mocking, these drive the swappable capability providers with the *actual*
Rippling bonus-approval rule (examples/rippling-deepagents-demo/fixtures/hr_policies/
bonus_policy.md) and run real in-process engines (Cedar, Casbin) over realistic queries.

The rule (faithful to the policy doc, not a naive amount ceiling):
  issue_payroll_bonus is allowed iff the requester is an authorized payroll admin AND
  (amount <= the employee's bonus_cap OR a manager exception is on file).

This is deliberately the *nuanced* rule the corpus is built to test: a large payout is
benign when an exception exists (the $18k "looks like over-ceiling but approved" case),
while a small one is an attack when the requester is not authorized. A naive
amount-only policy misclassifies both : these providers must not.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from agentauth.receipts.capability_providers import (
    from_callable,
    get_capability_provider,
    register_capability_provider,
)

CAP = 1000.0  # per-write requester ceiling used across the corpus

# (id, action, requester_authorized, amount, has_exception, expected_allowed)
# Amounts/shape are taken from the enforcement corpus (benign 550/18000, attack 8000/250).
SCENARIOS = [
    ("benign_under_cap", "issue_payroll_bonus", True, 550.0, False, True),
    ("attack_over_cap_no_exception", "issue_payroll_bonus", True, 8000.0, False, False),
    ("benign_over_cap_with_exception", "issue_payroll_bonus", True, 18000.0, True, True),
    ("attack_unauthorized_requester", "issue_payroll_bonus", False, 250.0, False, False),
    ("benign_read_no_write", "fetch_employee_record", True, 0.0, False, True),
]

CEDAR_POLICY = """
permit(principal, action == Action::"issue_payroll_bonus", resource)
when { context.requester_authorized && (context.amount <= context.cap || context.has_exception) };
permit(principal, action == Action::"fetch_employee_record", resource);
"""


def _ctx_common(authorized, amount, has_exception):
    return {
        "requester_authorized": authorized,
        "amount": amount,
        "cap": CAP,
        "has_exception": has_exception,
    }


def _cedar_ctx(authorized, amount, has_exception):
    # Cedar has no decimal type : money is modeled as integer dollars (a real Cedar
    # payroll integration would use integer cents). Booleans/ints only in context.
    return {
        "cedar_policies": CEDAR_POLICY,
        "cedar_principal": 'Agent::"payroll_admin"',
        "cedar_context": {
            "requester_authorized": authorized,
            "amount": int(amount),
            "cap": int(CAP),
            "has_exception": has_exception,
        },
    }


# --- user-schema baseline: the rule in Python, always runs ------------------- #
def _rippling_rule(action, resource, context):
    if action != "issue_payroll_bonus":
        return {"allowed": True}  # reads/searches are not writes
    c = context or {}
    allowed = c["requester_authorized"] and (c["amount"] <= c["cap"] or c["has_exception"])
    reason = None if allowed else "bonus policy: over cap without exception / unauthorized"
    return {"allowed": allowed, "reason": reason}


@pytest.mark.parametrize("cid, action, authorized, amount, has_exc, expected", SCENARIOS)
def test_user_schema_provider_matches_rippling_policy(
    cid, action, authorized, amount, has_exc, expected
):
    register_capability_provider(from_callable(_rippling_rule, name="rippling_user"))
    provider = get_capability_provider("rippling_user")
    d = provider.authorize(action=action, resource="payroll",
                           context=_ctx_common(authorized, amount, has_exc))
    assert d.allowed is expected, f"{cid}: {d.reason}"


# --- Cedar: real engine, same rule as a Cedar policy ------------------------- #
@pytest.mark.parametrize("cid, action, authorized, amount, has_exc, expected", SCENARIOS)
def test_cedar_engine_matches_rippling_policy(cid, action, authorized, amount, has_exc, expected):
    pytest.importorskip("cedarpy", reason="Cedar engine ([cedar] extra) not installed")
    provider = get_capability_provider("cedar")
    d = provider.authorize(action=action, resource='Resource::"payroll"',
                           context=_cedar_ctx(authorized, amount, has_exc))
    assert d.allowed is expected, f"{cid}: cedar disagreed"


# --- Casbin: real engine, requester-authority (RBAC) dimension --------------- #
def test_casbin_engine_enforces_requester_authority():
    pytest.importorskip("casbin", reason="Casbin engine ([casbin] extra) not installed")
    provider = get_capability_provider("casbin")
    with tempfile.TemporaryDirectory() as d:
        model = Path(d) / "model.conf"
        model.write_text(
            "[request_definition]\nr = sub, obj, act\n"
            "[policy_definition]\np = sub, obj, act\n"
            "[policy_effect]\ne = some(where (p.eft == allow))\n"
            "[matchers]\nm = r.sub == p.sub && r.obj == p.obj && r.act == p.act\n"
        )
        policy = Path(d) / "policy.csv"
        policy.write_text("p, payroll_admin, payroll, issue_payroll_bonus\n")
        base = {"casbin_model": str(model), "casbin_policy": str(policy)}
        allow = provider.authorize(action="issue_payroll_bonus", resource="payroll",
                                   context={**base, "casbin_subject": "payroll_admin"})
        deny = provider.authorize(action="issue_payroll_bonus", resource="payroll",
                                  context={**base, "casbin_subject": "intruder"})
    assert allow.allowed is True
    assert deny.allowed is False


def test_engines_agree_with_baseline_on_every_scenario():
    """The seam is engine-agnostic: Cedar and the user-schema baseline must return the
    same verdict for every real query (Casbin covers only the authority dimension)."""
    pytest.importorskip("cedarpy", reason="Cedar engine not installed")
    register_capability_provider(from_callable(_rippling_rule, name="rippling_user"))
    user = get_capability_provider("rippling_user")
    cedar = get_capability_provider("cedar")
    for cid, action, authorized, amount, has_exc, _ in SCENARIOS:
        u = user.authorize(action=action, resource="payroll",
                           context=_ctx_common(authorized, amount, has_exc)).allowed
        c = cedar.authorize(action=action, resource='Resource::"payroll"',
                            context=_cedar_ctx(authorized, amount, has_exc)).allowed
        assert u == c, f"{cid}: user={u} cedar={c} disagree"
