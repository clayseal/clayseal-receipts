# L1/L2 Token Architecture Decision

## Decision

Use Ed25519 for Clay Seal-issued signing paths, and keep the two-artifact model:

- a sender-constrained JWT-SVID for interoperable workload identity;
- a sender-constrained Biscuit token for attenuable capabilities and offline
  authorization.

Do not use RSA for newly issued Clay Seal JWT credentials. The only remaining
RSA path is the prototype node-attestation document, which stands in for an
external platform attestor and should be replaced by real SPIRE/cloud/hardware
attestation.

## Why Not RSA For The JWT Issuer?

RSA was useful as a lowest-common-denominator JWT default, but this project no
longer needs that compatibility trade. Ed25519 is already required for workload
PoP and Biscuit, is supported by JOSE as an OKP key type, and keeps signatures,
public keys, and implementation surface smaller.

The code currently uses the JOSE `EdDSA` algorithm label because PyJWT supports
Ed25519 through that identifier. RFC 9864 has since registered fully specified
`Ed25519` and marked polymorphic `EdDSA` deprecated; when PyJWT supports that
identifier, migrate directly to `Ed25519` as a single-version change. Until
then, the verifier pins the key type (`OKP` / `Ed25519`) and allow-lists only
`EdDSA`, so there is no RSA/EdDSA negotiation surface.

## Why Keep JWT + Biscuit?

The two-token approach is not valuable because "two is more secure." It is
valuable only because the artifacts answer different questions:

- JWT-SVID: who is this workload, in a format existing API gateways, JWKS
  consumers, and SPIFFE-style systems can verify.
- Biscuit: what may this workload do, with offline attenuation/delegation and
  Datalog policy checks that JWT scopes cannot express safely.

The cost is operational complexity: both artifacts must bind to the same
workload key, carry compatible lifetimes, and be revoked consistently. The
current implementation pays that cost by using the same `cnf.jkt`/`bound_key`
thumbprint, request-bound PoP over `ath`, short JWT TTLs, and Biscuit
revocation-id deny-lists.

If all downstream consumers become Biscuit-aware, a single Biscuit carrying
identity facts could be simpler. If all downstream consumers only need coarse
OAuth-style authorization, a single sender-constrained JWT access token could be
simpler. Clay Seal keeps both because it currently targets both identity interop
and attenuable agent delegation.

## Production Requirements

- Verifiers must fail closed on one JWT algorithm and one key type.
- JWT and Biscuit tokens must be useless without the workload private key.
- Authorization-critical requests should use online `/v1/authorize` when live
  revocation and replay resistance matter.
- Offline `agent.can()` is acceptable for local planning and low-risk checks,
  but cannot observe live revocation.
- The next standards-alignment step is to express PoP as a WIMSE WPT/DPoP-style
  proof JWT rather than the current internal canonical payload.
