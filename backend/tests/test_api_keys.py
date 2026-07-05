"""Focused tests for API key storage and migration behavior."""
from __future__ import annotations

from agentauth.backend.db import SessionLocal
from agentauth.backend.models import Customer


def test_create_customer_stores_only_api_key_hash(client):
    resp = client.post("/v1/customers", json={"name": "Beta Corp"})
    assert resp.status_code == 201
    data = resp.json()
    assert data["api_key"].startswith("aa_")
    assert data["customer_id"]

    with SessionLocal() as db:
        customer = db.get(Customer, data["customer_id"])
        assert customer is not None
        assert customer.api_key != data["api_key"]
        assert customer.api_key_hash is not None


def test_plaintext_api_key_row_is_migrated_on_successful_use(client):
    resp = client.post("/v1/customers", json={"name": "Legacy Corp"})
    assert resp.status_code == 201
    data = resp.json()

    with SessionLocal() as db:
        customer = db.get(Customer, data["customer_id"])
        assert customer is not None
        customer.api_key = data["api_key"]
        customer.api_key_hash = None
        db.add(customer)
        db.commit()

    resp = client.get("/v1/agents", headers={"X-API-Key": data["api_key"]})
    assert resp.status_code == 200, resp.text

    with SessionLocal() as db:
        customer = db.get(Customer, data["customer_id"])
        assert customer is not None
        assert customer.api_key != data["api_key"]
        assert customer.api_key_hash is not None
