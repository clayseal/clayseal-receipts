The core developer experience

Everything flows from one principle: the SDK wraps the agent, it doesn't live inside it. Developers shouldn't have to scatter identity plumbing throughout their agent code. They wrap their agent at the boundary and the SDK handles everything.

Issuing an identity
At startup, the developer calls auth.identify(). Under the hood the SDK proves the workload's provenance through attestation and receives a short-lived, signed JWT-SVID credential — the agent's verifiable identity. The developer never handles signing keys, key rotation, or JWKS; that all happens server-side.

Validating an identity
Any service that receives a credential can verify it offline against the public JWKS, or call auth.validate() / session.validate() for a full status check (signature, expiry, and whether the agent has been revoked). Revocation is immediate: a single auth.revoke(agent_id) call invalidates the credential, and subsequent validation fails.
