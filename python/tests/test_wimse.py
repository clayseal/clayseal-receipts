"""WIMSE WIT/WPT + transaction-token envelopes (SOTA-15)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from agentauth.capabilities.mandate import issue_mandate
from agentauth.core.signing import generate_keypair
from agentauth.receipts.wimse import (
    build_wpt,
    issue_wit_from_mandate,
    mandate_ref_from_envelope,
    transaction_token_act_chain,
    verify_wit,
    verify_wpt,
)
from agentauth.capabilities.mandate import Mandate


def test_wit_roundtrip_from_mandate():
    key = generate_keypair()
    envelope = issue_mandate(
        issuer=key.public_key_hex,
        key=key,
        allowed_actions=["payments.refund"],
        ttl_seconds=3600,
    )
    wit = issue_wit_from_mandate(envelope, key)
    claims = verify_wit(wit["token"], key.public_key)
    assert claims["sub"] == envelope["document"]["grant_id"]
    assert claims["agent_receipts"]["grant_id"] == envelope["document"]["grant_id"]


def test_wpt_binds_request():
    key = generate_keypair()
    envelope = issue_mandate(issuer=key.public_key_hex, key=key, ttl_seconds=3600)
    wit = issue_wit_from_mandate(envelope, key)
    wpt = build_wpt(
        wit_token=wit["token"],
        aud="https://tool.example/mcp",
        htm="POST",
        htu="https://tool.example/mcp/call",
        key=key,
    )
    claims = verify_wpt(wpt["token"], key.public_key, aud="https://tool.example/mcp")
    assert claims["htm"] == "POST"
    assert claims["wit"] == wit["token"]


def test_transaction_token_act_chain():
    parent_key = generate_keypair()
    child_key = generate_keypair()
    parent = issue_mandate(
        issuer=parent_key.public_key_hex,
        key=parent_key,
        allowed_actions=["payments"],
        ttl_seconds=3600,
    )
    child = issue_mandate(
        issuer=parent_key.public_key_hex,
        key=parent_key,
        delegate=child_key.public_key_hex,
        allowed_actions=["payments.refund"],
        parent_grant_id=parent["document"]["grant_id"],
        ttl_seconds=3600,
    )
    parent_mandate = Mandate.from_dict(parent["document"])
    child_mandate = Mandate.from_dict(child["document"])
    parent_act = transaction_token_act_chain(parent_mandate)["act"]
    chain = transaction_token_act_chain(child_mandate, parent_act=parent_act)
    assert len(chain["act"]) == 2
    assert chain["act"][-1]["grant_id"] == child_mandate.grant_id


def test_mandate_ref_is_stable_commitment():
    key = generate_keypair()
    envelope = issue_mandate(issuer=key.public_key_hex, key=key, ttl_seconds=3600)
    ref = mandate_ref_from_envelope(envelope)
    assert len(ref) == 64
    assert ref == mandate_ref_from_envelope(envelope)
