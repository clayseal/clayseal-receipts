from agentauth.receipts.authority_binding import AuthorityBinding


def test_authority_binding_roundtrip_and_runtime_mapping():
    binding = AuthorityBinding(
        subject_id="spiffe://agentauth.io/customer/acme/agent/finance",
        authority_id="grant-finance-1",
        issuer="agentauth.io",
        tenant_id="acme",
        subject_type="finance",
        owner_ref="alice@acme.ai",
        workload_principal="spiffe://agentauth.io/customer/acme/agent/finance",
        capabilities=["pay:send", "ledger:read"],
        scope_claims=["pay:send", "ledger:read"],
        capability_rules=[
            {"resource": "pay", "action": "send"},
            {"resource": "ledger", "action": "read"},
        ],
        selectors=["k8s:ns:finance", "k8s:sa:finance-agent"],
        attestation_type="k8s_psat",
        delegation_chain=["root-mandate", "subagent-grant"],
        expires_at="2026-06-20T00:00:00Z",
        trust_tier="attested",
        proof_of_possession=True,
        presenter_key_hash="abc123",
        has_capability_grant=True,
    )

    restored = AuthorityBinding.from_dict(binding.to_dict())
    assert restored == binding

    authority = binding.to_authority_context(
        authority_version=4,
        session_id="sess-123",
        prior_action_count=2,
        resource_scope=["account:payroll"],
        budget_refs=["usd-daily"],
        approval_refs=["approval-77"],
    )

    assert authority.subject_id == binding.subject_id
    assert authority.issuer == "agentauth.io"
    assert authority.tenant_id == "acme"
    assert authority.subject_type == "finance"
    assert authority.owner_ref == "alice@acme.ai"
    assert authority.workload_principal == "spiffe://agentauth.io/customer/acme/agent/finance"
    assert authority.capabilities == ["pay:send", "ledger:read"]
    assert authority.scope_claims == ["pay:send", "ledger:read"]
    assert authority.capability_rules == [
        {"resource": "pay", "action": "send"},
        {"resource": "ledger", "action": "read"},
    ]
    assert authority.selectors == ["k8s:ns:finance", "k8s:sa:finance-agent"]
    assert authority.attestation_type == "k8s_psat"
    assert authority.delegation_chain == ["root-mandate", "subagent-grant"]
    assert authority.expires_at == "2026-06-20T00:00:00Z"
    assert authority.trust_tier == "attested"
    assert authority.proof_of_possession is True
    assert authority.presenter_key_hash == "abc123"
    assert authority.has_capability_grant is True
    assert authority.resource_scope == ["account:payroll"]
    assert authority.budget_refs == ["usd-daily"]
    assert authority.approval_refs == ["approval-77"]


def test_authority_binding_from_agentauth_credential_maps_l1_l2_shape():
    credential = {
        "agent_id": "agent-123",
        "token": "header.payload.signature",
        "spiffe_id": "spiffe://agentauth.io/customer/acme/agent/researcher",
        "agent_type": "researcher",
        "owner": "alice@acme.ai",
        "scopes": ["db:read", "web:*"],
        "selectors": ["k8s:ns:customer-acme", "k8s:sa:researcher"],
        "expires_at": "2026-06-20T00:00:00Z",
        "capabilities": [
            {"resource": "db", "action": "read"},
            {"resource": "web", "action": "*", "constraints": {"rate_limit": 5}},
        ],
        "biscuit": "biscuit-token",
        "biscuit_root_public_key": "root-public",
        "bound_keyhash": "bound-hash",
    }

    binding = AuthorityBinding.from_agentauth_credential(credential)

    assert binding.subject_id == "spiffe://agentauth.io/customer/acme/agent/researcher"
    assert binding.authority_id == "agent-123"
    assert binding.issuer == "agentauth.io"
    assert binding.tenant_id == "acme"
    assert binding.subject_type == "researcher"
    assert binding.owner_ref == "alice@acme.ai"
    assert binding.workload_principal == credential["spiffe_id"]
    assert binding.capabilities == ["db:read", "web:*"]
    assert binding.scope_claims == ["db:read", "web:*"]
    assert binding.capability_rules == credential["capabilities"]
    assert binding.selectors == credential["selectors"]
    assert binding.attestation_type == "jwt_svid"
    assert binding.trust_tier == "sender_constrained"
    assert binding.proof_of_possession is True
    assert binding.presenter_key_hash == "bound-hash"
    assert binding.has_capability_grant is True

    authority = binding.to_authority_context(
        authority_version=7,
        session_id="sess-agentauth",
    )
    assert authority.tenant_id == "acme"
    assert authority.owner_ref == "alice@acme.ai"
    assert authority.workload_principal == credential["spiffe_id"]
    assert authority.capability_rules == credential["capabilities"]
    assert authority.trust_tier == "sender_constrained"
    assert authority.proof_of_possession is True


def test_authority_binding_from_agentauth_credential_without_biscuit_is_attested_not_pop_bound():
    credential = {
        "agent_id": "agent-456",
        "spiffe_id": "spiffe://agentauth.io/customer/beta/agent/finance",
        "agent_type": "finance",
        "owner": "bob@beta.ai",
        "scopes": ["pay:send"],
        "selectors": ["k8s:ns:finance"],
        "expires_at": "2026-06-21T00:00:00Z",
        "capabilities": [{"resource": "pay", "action": "send"}],
        "bound_keyhash": None,
    }

    binding = AuthorityBinding.from_agentauth_credential(
        credential,
        attestation_type="k8s_psat+jwt_svid",
    )

    assert binding.authority_id == "agent-456"
    assert binding.tenant_id == "beta"
    assert binding.capabilities == ["pay:send"]
    assert binding.attestation_type == "k8s_psat+jwt_svid"
    assert binding.trust_tier == "workload_attested"
    assert binding.proof_of_possession is False
    assert binding.has_capability_grant is False
