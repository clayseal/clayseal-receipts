# Security Policy

Clay Seal Receipts is security-sensitive software. Please do not open a public
issue for a suspected vulnerability.

## Reporting

Email the maintainers with:

- a short description of the issue
- affected files, versions, or commits
- reproduction steps or a proof of concept, if you can share one safely
- whether the issue may expose keys, receipts, prompts, tool inputs, user data,
  or verification results

We will acknowledge the report, investigate, and coordinate a fix before public
disclosure.

## Supported Versions

The active development branch and the latest tagged release receive security
fixes.

## Security Notes

Receipts are an audit and verification layer, not a complete sandbox. In
production, use short-lived identities, online validation for sensitive actions,
scoped capabilities, signed receipt bundles, stable signing keys, and explicit
retention rules for prompt/tool data.

Provider adapters under `agentauth.receipts.identity_providers` expect claims
that have already been verified by your identity provider or gateway. They map
trusted claims into receipt authority bindings; they do not verify third-party
JWTs or replace revocation checks by themselves.

