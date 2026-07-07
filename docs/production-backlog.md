# Production Backlog

This backlog captures the production hardening items from the architecture review of
identity-bound versus standalone receipt generation.

## Decision

Standalone receipt generation should remain valid, but only as an **unbound execution
receipt** for pilots, local auditing, replay, policy debugging, and non-identity
integrations.

For production or consequential agent actions, a receipt should be considered an
**Clay Seal production receipt** only when it is bound to an attested authority identity.
Today that identity-bound path is ``Identity.identify(...)`` (or ``AgentAuth.identify``)
-> ``AgentSession.wrap(...)`` -> ``AgentWrapper.run(...)``, where ``AgentSession.wrap()``
injects an ``AuthorityBinding`` derived from the live Clay Seal credential.

The production goal is to preserve the standalone receipts path while making the trust
boundary explicit and machine-checkable.

## P0: Require Identity Binding For Production Profiles

Current behavior:

- `AgentSession.wrap()` binds receipts to the attested credential through
  `AuthorityBinding.from_agentauth_credential(...)`.
- Direct `AgentWrapper(...)` construction intentionally leaves
  `default_authority_binding=None`.
- Without a binding, `AgentWrapper` falls back to an authority context containing only
  the receipt certificate `agent_id`.
- `partner_factory` and strict `arctl preflight` can still produce production-shaped
  receipts without a Clay Seal identity binding.

Required changes:

- Add a `require_identity_binding` option to `PartnerConfig`.
- Make `config/partner.production.example.yaml` set `require_identity_binding: true`.
- Teach `arctl preflight --strict` to fail when identity binding is required but no
  identity source is configured.
- Add an `AgentWrapper` guard that fails early when `require_identity_binding=True` and
  neither `default_authority_binding` nor a per-run `authority_binding` is present.
- Add tests for strict production config rejecting unbound wrappers.

Relevant code:

- `agentauth/identity/session.py` (`AgentSession.wrap`)
- `agentauth/receipts/wrapper.py` (`default_authority_binding`, fallback authority)
- `agentauth/receipts/partner_config.py`
- `agentauth/receipts/partner_factory.py`
- `agentauth/receipts/preflight.py`
- `config/partner.production.example.yaml`

## P0: Split Execution Assurance From Authority Trust

Current behavior:

- `verify_receipt_bundle(..., min_assurance_tier=...)` thresholds proof, TEE, and
  signature assurance derived from `ExecutionProof`.
- The verifier does not separately require an attested authority identity.
- A high execution-assurance receipt can still be authority-unbound unless the policy or
  consumer checks authority fields separately.

Required changes:

- Rename or document the existing verifier threshold as execution assurance.
- Add a separate verifier parameter such as `min_authority_trust_tier`.
- Verify the authority tier from bundled, verifiable identity evidence rather than from
  caller-supplied authority JSON.
- Return distinct issue codes for execution-assurance failures and authority-trust
  failures.

Relevant code:

- `agentauth/receipts/export.py` (`verify_receipt_bundle`)
- `agentauth/receipts/assurance.py`
- `agentauth/receipts/policy_engine.py`
- `agentauth/receipts/verifier_server.py`
- `agentauth/backend/routers/verifier.py`

## P0: Add Portable Receipt-Bound Workload Proof

Current behavior:

- The proof commits to `execution_context`, so authority fields are integrity-bound once
  included.
- `AuthorityBinding.from_agentauth_credential(...)` marks authority evidence as verified
  inside the runtime.
- That internal `evidence_verified` flag is not serialized.
- Portable verification does not independently validate a JWT-SVID or workload-key
  signature over the receipt.

Required changes:

- Add a receipt-bound proof-of-possession section signed by the workload key.
- Bind the signature to at least `proof_id`, `context_hash`, `output_hash`,
  `policy_commitment`, and the Clay Seal credential/token hash.
- Include enough identity evidence for offline verification, or define an online verifier
  path against the Clay Seal backend.
- Ensure verifier output can distinguish:
  - unbound receipt
  - declared authority only
  - signed authority
  - sender-constrained Clay Seal authority
  - workload-attested Clay Seal authority

Relevant code:

- `agentauth/backend/identity.py` (`cnf.jkt`, sender-constrained validation)
- `agentauth/identity/models.py` (`Credential.to_binding_dict`)
- `agentauth/receipts/authority_binding.py`
- `agentauth/receipts/proof.py`
- `agentauth/receipts/export.py`

## P1: Make Authority Requirements First-Class Policy

Current behavior:

- `Policy.min_trust_tier` is enforced producer-side by `YamlPolicyEngine`.
- Caller-declared high trust is rejected unless authority evidence came through the
  verified Clay Seal credential path.
- Policies that omit `min_trust_tier` allow unbound receipts to satisfy output-only rules.

Required changes:

- Update production policy templates to include `min_trust_tier`.
- Add policy examples for `sender_constrained` and `workload_attested`.
- Add replay/verifier reporting that clearly states when a policy did not require
  identity-bound authority.
- Consider making `min_trust_tier` mandatory in strict production preflight.

Relevant code:

- `agentauth/receipts/policy.py`
- `agentauth/receipts/policy_engine.py`
- `policies/`
- `scripts/scaffold_policy.py`

## P1: Fix Documentation Language Around "Stable Agent Identity"

Current issue:

- `persist_certificate` is described as "Stable agent identity" in the deployment guide.
- That certificate gives a stable receipt/certificate `agent_id`, but it is not the same
  as an attested Clay Seal/SPIFFE workload identity.

Required changes:

- Rename the deployment guide wording to "Stable receipt certificate identity" or
  "Stable receipt producer id".
- Explicitly document that Clay Seal production identity requires
  ``Identity.identify(...)`` and ``AgentSession.wrap(...)`` (``AgentAuth`` remains the
  compatibility SDK class name).
- Update design partner docs to say standalone `AgentWrapper` receipts are unbound unless
  an `AuthorityBinding` is supplied.
- Update verifier docs to explain the difference between execution assurance and
  authority identity assurance.

Relevant docs:

- `README.md`
- `docs/deployment.md`
- `docs/design_partner.md`
- `docs/trust_model.md`
- `docs/assurance_taxonomy.md`
- `docs/http_verifier.md`

## P1: Improve Export And Verification UX For Unbound Receipts

Current behavior:

- Unbound receipts still include an `authority` block because v2 requires it.
- That block can contain only `authority_id` plus version/session metadata, which is easy
  to mistake for a real agent identity.

Required changes:

- Add an explicit authority state in exported bundles, for example
  `authority.binding_state: unbound | declared | signed | agentauth_verified`.
- Add verifier warnings for unbound receipts even when the receipt is otherwise
  internally consistent.
- Add CLI output that names the authority state in `arctl verify-bundle` and
  `arctl explain`.
- Add tests for unbound receipt diagnostics.

Relevant code:

- `agentauth/receipts/receipt_schema.py`
- `agentauth/receipts/export.py`
- `agentauth/receipts/explain.py`
- `agentauth/receipts/cli.py`

## P2: Preserve Standalone Receipts As A Supported Mode

Standalone receipts are useful and should not be removed.

Keep supporting:

- Local development and demos.
- Shadow-mode instrumentation before an identity service is deployed.
- Offline policy and proof experiments.
- Partner pilots that bring their own operator certificate/signing infrastructure.
- Receipts for systems that are not yet Clay Seal-integrated.

But require the system to label them honestly as unbound or lower-assurance, and ensure
production defaults cannot accidentally present them as attested Clay Seal identities.

## Acceptance Criteria

- A strict production config cannot pass preflight while producing unbound receipts.
- A relying party can ask the verifier for both minimum execution assurance and minimum
  authority trust.
- A receipt-bound workload proof is available for Clay Seal-issued credentials.
- Unbound receipts remain easy to create intentionally, but they are labeled clearly in
  exports, verifier output, docs, and CLI explanations.
- Tests cover:
  - identity-bound wrapper path
  - direct unbound wrapper path
  - strict production rejection of unbound wrappers
  - verifier rejection below `min_authority_trust_tier`
  - receipt-bound workload PoP verification
