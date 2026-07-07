# L1/L2 Workload-Key Hardening

This document is the current production contract for the workload key used by
Clay Seal credentials, Biscuit capability grants, and proof-of-possession.

## Workload Key

The workload key is an **Ed25519 holder-of-key credential**, not a long-lived RSA
process secret.

- `identify()` requires `workload_pubkey_pem` in verified attestation evidence.
- The backend rejects non-Ed25519 workload public keys and stores a canonical SPKI PEM.
- JWT-SVIDs carry `cnf.jkt`, computed as a base64url SHA-256 JWK thumbprint of
  the Ed25519 public key.
- Biscuit tokens carry the same thumbprint in `bound_key(...)`.

## Issuer Keys

Clay Seal-issued JWT-SVIDs are also signed with per-customer Ed25519 keys.
The implementation uses the JOSE `EdDSA` algorithm label because that is what
the current Python JWT stack supports for Ed25519 OKP keys; verifiers still
fail closed by allow-listing only that single algorithm and requiring stored
key metadata to match. When the local JOSE library supports RFC 9864's fully
specified `Ed25519` `alg`, this should be a single-version upgrade rather than
a parallel fallback.

The JWT issuer key and Biscuit root key intentionally remain separate keys even
though both use Ed25519. They have different lifecycles and blast radii: the JWT
key signs identity credentials and is published as JWKS; the Biscuit key roots
attenuable capability tokens and publishes raw public-key hex for offline
authorization.

## At-Rest Secret Encryption

JWT signing private keys and Biscuit root private keys are encrypted before they
are stored. Local SQLite development can run without a configured provider, but
any non-SQLite identity database requires secret encryption at startup. Set:

```env
AGENTAUTH_SECRET_ENCRYPTION_PROVIDER=local
AGENTAUTH_SIGNING_KEY_ENCRYPTION_KEY=<64-hex-character-random-key>
```

or use the `aws_kms` / `gcp_kms` providers with the corresponding KMS key
environment variable. Once encryption is enabled, plaintext stored key material
is refused instead of silently accepted, which prevents rollback to legacy
cleartext rows.

Production deployments should generate and hold the private key in the workload
identity layer: SPIRE/SDS, a node-local agent, TPM/TEE-backed signer, KMS/HSM, or
another non-extractable signing service. Application code should request
signatures; it should not persist raw workload private keys or reuse them across
workload instances. The in-process PEM used by the SDK dev attestor is local
development scaffolding only.

## Proof-of-Possession

PoP is request-bound. The signed canonical payload includes:

| Field | Meaning |
|---|---|
| `typ` | `agentauth-pop+jwt` |
| `cnf` | workload key JWK thumbprint |
| `nonce` | server challenge or offline nonce |
| `htm` / `htu` | method and target being authorized |
| `ath` | SHA-256 hash of the presented JWT or Biscuit token |
| `iat` | issued-at timestamp; verifier enforces a bounded clock window |
| `jti` | unique proof id |
| `operation` | Clay Seal resource/action pair |

Server-side validation is fail-closed:

- `/v1/validate` expects `htm=POST`, `htu=/v1/validate`, `ath=hash(jwt)`, and
  operation `jwt:validate`.
- `/v1/authorize` expects `htm=POST`, `htu=/v1/authorize`, `ath=hash(biscuit)`,
  and the requested resource/action.
- `/v1/challenge` issues one-time challenges with a short TTL; replayed or
  expired challenges fail before authorization.

The SDK's offline `agent.can()` path still works without a server round trip, but
offline verifiers cannot enforce global single-use replay protection or live
revocation. Use server-side `/v1/authorize` or an online policy-enforcement point
for production actions where freshness, revocation, or auditability matters.

## Biscuit Revocation

Every issued Biscuit has its block revocation IDs recorded on the `Agent` row.
When an agent credential is revoked:

1. the agent status is set to `revoked`;
2. every revocation ID from the root Biscuit is inserted into the tenant-scoped
   `biscuit_revocations` deny-list;
3. server-side authorization rejects any presented Biscuit whose block IDs
   intersect the deny-list.

Because attenuated Biscuits carry parent block IDs, revoking the root token also
revokes delegated/attenuated descendants.

## Remaining Production Work

- Replace the prototype RS256 node-attestation document with real SPIRE/cloud
  node attestation and, where appropriate, hardware-rooted evidence.
- Re-express the request-bound proof as a WIMSE WPT/DPoP-compatible JWT wire
  format for ecosystem interoperability.
