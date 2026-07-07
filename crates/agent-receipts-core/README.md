# clay-seal-receipts-core

Reference Rust implementation of core Clay Seal Receipts types: certificates, policy documents, execution proofs, and hash-chained audit records.

**Runtime path today:** the Python SDK (`agentauth/receipts/`) owns the production types and audit chain. The CLI proving stack uses `clay-seal-receipts-policy-circuit` and `clay-seal-receipts-composed`, not this crate.

This crate remains in the workspace for:

- Rust-native experiments and parity checks
- Future FFI or shared-type consolidation

When adding features, prefer implementing them in Python first unless you are explicitly building a Rust-only integration.
