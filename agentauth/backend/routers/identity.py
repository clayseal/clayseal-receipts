"""HTTP surface for the Identity Service."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import capabilities as cap_service
from .. import identity as identity_service
from ..api_keys import generate_api_key
from ..db import get_db
from ..deps import get_current_customer, verify_mtls_binding
from ..errors import (
    AgentNotFoundError,
    InvalidTokenError,
    NodeAttestorError,
    RegistrationEntryError,
)
from ..models import Agent, BiscuitRootKey, Customer, NodeAttestor, RegistrationEntry, new_id
from ..schemas import (
    AgentOut,
    AuthorizeRequest,
    AuthorizeResponse,
    ChallengeResponse,
    CredentialOut,
    CustomerCreate,
    CustomerOut,
    IdentifyRequest,
    NodeAttestorCreate,
    NodeAttestorOut,
    RegistrationEntryCreate,
    RegistrationEntryOut,
    RegistrationLintReport,
    ValidateRequest,
    ValidateResponse,
)

router = APIRouter(prefix="/v1", tags=["identity"])


def _credential_out(db: Session, agent: Agent, token: str) -> CredentialOut:
    root_public_key = None
    if agent.biscuit_kid:
        root = db.get(BiscuitRootKey, agent.biscuit_kid)
        root_public_key = root.public_hex if root else None
    return CredentialOut(
        agent_id=agent.id,
        token=token,
        spiffe_id=agent.spiffe_id,
        agent_type=agent.agent_type,
        owner=agent.owner,
        capabilities=list(agent.capabilities or []),
        scopes=agent.scopes,
        selectors=list(agent.selectors or []),
        biscuit=agent.biscuit,
        biscuit_root_public_key=root_public_key,
        bound_keyhash=agent.bound_keyhash,
        expires_at=agent.expires_at,
    )


@router.post("/customers", response_model=CustomerOut, status_code=201)
def create_customer(body: CustomerCreate, db: Session = Depends(get_db)) -> CustomerOut:
    """Sign up a tenant. Returns the API key (shown once) and provisions a key."""
    api_key, api_key_lookup, api_key_hash = generate_api_key()
    customer = Customer(
        id=new_id(),
        name=body.name,
        api_key=api_key_lookup,
        api_key_hash=api_key_hash,
    )
    db.add(customer)
    db.commit()
    db.refresh(customer)
    # Provision the first signing key eagerly so the first identify() is fast.
    identity_service.get_active_key(db, customer.id)
    return CustomerOut(customer_id=customer.id, name=customer.name, api_key=api_key)


# --------------------------------------------------------------------------- #
# Node attestors + registration entries (admin: configure who may attest what)
# --------------------------------------------------------------------------- #
@router.post("/node-attestors", response_model=NodeAttestorOut, status_code=201)
def create_node_attestor(
    body: NodeAttestorCreate,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> NodeAttestorOut:
    attestor = identity_service.register_node_attestor(
        db, customer, type=body.type, public_pem=body.public_pem,
        description=body.description,
    )
    return NodeAttestorOut.model_validate(attestor)


@router.get("/node-attestors", response_model=list[NodeAttestorOut])
def list_node_attestors(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> list[NodeAttestorOut]:
    stmt = select(NodeAttestor).where(NodeAttestor.customer_id == customer.id)
    return [NodeAttestorOut.model_validate(a) for a in db.scalars(stmt).all()]


@router.delete("/node-attestors/{attestor_id}", status_code=204)
def delete_node_attestor(
    attestor_id: str,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> None:
    attestor = db.get(NodeAttestor, attestor_id)
    if attestor is None or attestor.customer_id != customer.id:
        raise NodeAttestorError(
            f"No node attestor {attestor_id} for this customer.",
            suggestion="List node attestors at GET /v1/node-attestors.",
        )
    db.delete(attestor)
    db.commit()


@router.post("/registration-entries", response_model=RegistrationEntryOut, status_code=201)
def create_registration_entry(
    body: RegistrationEntryCreate,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> RegistrationEntryOut:
    entry = identity_service.register_entry(
        db, customer, agent_type=body.agent_type, selectors=body.selectors,
        capabilities=[c.model_dump(exclude_none=True) for c in body.capabilities],
        scopes=body.scopes, owner=body.owner, ttl_seconds=body.ttl_seconds,
        description=body.description,
    )
    return RegistrationEntryOut.model_validate(entry)


@router.get("/registration-entries", response_model=list[RegistrationEntryOut])
def list_registration_entries(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> list[RegistrationEntryOut]:
    stmt = select(RegistrationEntry).where(RegistrationEntry.customer_id == customer.id)
    return [RegistrationEntryOut.model_validate(e) for e in db.scalars(stmt).all()]


@router.get("/registration-entries/lint", response_model=RegistrationLintReport)
def lint_registration_entries(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> RegistrationLintReport:
    """Report overlapping registration entries that would tie at identify time."""
    conflicts = identity_service.lint_registration_entries(db, customer)
    return RegistrationLintReport(ok=not conflicts, conflicts=conflicts)


@router.delete("/registration-entries/{entry_id}", status_code=204)
def delete_registration_entry(
    entry_id: str,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> None:
    entry = db.get(RegistrationEntry, entry_id)
    if entry is None or entry.customer_id != customer.id:
        raise RegistrationEntryError(
            f"No registration entry {entry_id} for this customer.",
            suggestion="List entries at GET /v1/registration-entries.",
        )
    db.delete(entry)
    db.commit()


@router.post("/identify", response_model=CredentialOut)
def identify(
    body: IdentifyRequest,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> CredentialOut:
    """Attest a workload and mint a JWT-SVID.

    The workload proves its environment with a signed attestation document; the
    matched registration entry — not the request — determines agent_type/scopes.
    """
    agent, token = identity_service.attest(
        db,
        customer,
        attestation_document=body.attestation_document,
        ttl_seconds=body.ttl_seconds,
    )
    return _credential_out(db, agent, token)


@router.post("/validate", response_model=ValidateResponse)
def validate(
    request: Request,
    body: ValidateRequest,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> ValidateResponse:
    pop = None
    if body.pop is not None:
        challenge_error = cap_service.consume_server_challenge(
            db, customer.id, body.pop.challenge
        )
        if challenge_error is not None:
            raise InvalidTokenError(
                challenge_error,
                suggestion="Fetch a fresh challenge from POST /v1/challenge before validating.",
            )
        pop = cap_service.PopProof(
            challenge=body.pop.challenge,
            signature_b64=body.pop.signature,
            pubkey_pem=body.pop.pubkey_pem,
            htm=body.pop.htm,
            htu=body.pop.htu,
            ath=body.pop.ath,
            iat=body.pop.iat,
            jti=body.pop.jti,
        )
    claims, _agent = identity_service.validate_token(db, customer, body.token, pop=pop)
    verify_mtls_binding(request, claims=claims)
    return ValidateResponse(valid=True, claims=claims)


@router.post("/agents/{agent_id}/revoke", response_model=AgentOut)
def revoke(
    agent_id: str,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> AgentOut:
    agent = identity_service.revoke_agent(db, customer, agent_id)
    if agent is None:
        raise AgentNotFoundError(
            f"No agent {agent_id} for this customer.",
            suggestion="Check the agent_id; list agents at GET /v1/agents.",
        )
    return AgentOut.model_validate(agent)


@router.get("/agents", response_model=list[AgentOut])
def list_agents(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
    status: str | None = None,
    agent_type: str | None = None,
) -> list[AgentOut]:
    stmt = select(Agent).where(Agent.customer_id == customer.id)
    if status:
        stmt = stmt.where(Agent.status == status)
    if agent_type:
        stmt = stmt.where(Agent.agent_type == agent_type)
    stmt = stmt.order_by(Agent.created_at.desc())
    return [AgentOut.model_validate(a) for a in db.scalars(stmt).all()]


@router.get("/agents/{agent_id}", response_model=AgentOut)
def get_agent(
    agent_id: str,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> AgentOut:
    agent = db.get(Agent, agent_id)
    if agent is None or agent.customer_id != customer.id:
        raise AgentNotFoundError(
            f"No agent {agent_id} for this customer.",
            suggestion="Check the agent_id; list agents at GET /v1/agents.",
        )
    return AgentOut.model_validate(agent)


@router.post("/keys/rotate")
def rotate_keys(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> dict:
    key = identity_service.rotate_key(db, customer.id)
    return {"active_kid": key.kid}


@router.get("/jwks.json")
def jwks(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> dict:
    return identity_service.build_jwks(db, customer.id)


# --------------------------------------------------------------------------- #
# Capability tokens (Biscuit): offline-verifiable, attenuable, PoP-bound.
# --------------------------------------------------------------------------- #
@router.get("/biscuit-keys.json")
def biscuit_keys(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> dict:
    """Publish the customer's Biscuit root public keys so capability tokens can
    be verified and authorized offline (the capability analogue of jwks.json)."""
    return cap_service.build_biscuit_jwks(db, customer.id)


@router.post("/biscuit-keys/rotate")
def rotate_biscuit_keys(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> dict:
    key = cap_service.rotate_root_key(db, customer.id)
    return {"active_kid": key.kid, "public_key": key.public_hex}


@router.post("/challenge", response_model=ChallengeResponse)
def challenge(
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> ChallengeResponse:
    """Issue a one-time nonce for the server-side proof-of-possession path."""
    return ChallengeResponse(challenge=cap_service.issue_server_challenge(db, customer.id))


@router.post("/authorize", response_model=AuthorizeResponse)
def authorize(
    request: Request,
    body: AuthorizeRequest,
    customer: Customer = Depends(get_current_customer),
    db: Session = Depends(get_db),
) -> AuthorizeResponse:
    """Authorize an operation against a capability token (server-side path).

    Verifies proof-of-possession and layers in revocation. Fully-offline
    authorization (no revocation check) is also available via the SDK.
    """
    pop = None
    if body.pop is not None:
        challenge_error = cap_service.consume_server_challenge(
            db, customer.id, body.pop.challenge
        )
        if challenge_error is not None:
            return AuthorizeResponse(allowed=False, reason=challenge_error)
        pop = cap_service.PopProof(
            challenge=body.pop.challenge,
            signature_b64=body.pop.signature,
            pubkey_pem=body.pop.pubkey_pem,
            htm=body.pop.htm,
            htu=body.pop.htu,
            ath=body.pop.ath,
            iat=body.pop.iat,
            jti=body.pop.jti,
        )
    result = identity_service.verify_capability(
        db,
        customer,
        token_b64=body.token,
        operation=(body.operation.resource, body.operation.action),
        pop=pop,
        expected_htm="POST",
        expected_htu="/v1/authorize",
    )
    if result["allowed"] and pop is not None:
        # Build a synthetic claims dict so verify_mtls_binding can compare via cnf.jkt.
        from agentauth.workload_keys import keyhash_for_pem
        biscuit_claims = {"cnf": {"jkt": keyhash_for_pem(pop.pubkey_pem)}}
        verify_mtls_binding(request, claims=biscuit_claims)
    return AuthorizeResponse(allowed=result["allowed"], reason=result["reason"])
