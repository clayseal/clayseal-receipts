"""Provider adapters for binding external identity into receipts.

These adapters intentionally live in receipts, not capabilities, so layer 3 can
run by itself with provider claims that were verified by the host application.
Claim-mapping providers do not verify JWT signatures or cloud attestations; pass
``evidence_verified=True`` only after your gateway, IdP middleware, or workload
identity verifier has already done that cryptographic check.

Third-party packages can add providers through the ``agentauth.identity_providers``
entry-point group or by calling ``register_identity_provider`` at startup.
"""

from __future__ import annotations

from agentauth.receipts.identity_providers.agentauth import AgentAuthIdentityProvider
from agentauth.receipts.identity_providers.auth0 import Auth0IdentityProvider
from agentauth.receipts.identity_providers.aws_sts import AwsStsIdentityProvider
from agentauth.receipts.identity_providers.azure_ad import AzureAdIdentityProvider
from agentauth.receipts.identity_providers.gcp import GcpIdentityProvider
from agentauth.receipts.identity_providers.oidc import OidcIdentityProvider
from agentauth.receipts.identity_providers.registry import (
    build_identity_session,
    get_identity_provider,
    list_identity_providers,
    register_identity_provider,
)
from agentauth.receipts.identity_providers.spiffe_jwt import SpiffeJwtIdentityProvider

__all__ = [
    "AgentAuthIdentityProvider",
    "Auth0IdentityProvider",
    "AwsStsIdentityProvider",
    "AzureAdIdentityProvider",
    "GcpIdentityProvider",
    "OidcIdentityProvider",
    "SpiffeJwtIdentityProvider",
    "build_identity_session",
    "get_identity_provider",
    "list_identity_providers",
    "register_identity_provider",
]
