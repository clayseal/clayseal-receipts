# WIMSE / transaction-token mapping (SOTA-15)

Crosswalk from Agent Receipts mandate and authority evidence to IETF WIMSE and
OAuth transaction-token-for-agents wire formats.

## Mandate → WIT

| Mandate field | WIT claim |
|---------------|-----------|
| `issuer` | `iss` |
| `delegate` or `grant_id` | `sub` |
| `issued_at` / `expires_at` | `iat` / `exp` |
| `grant_id` | `jti` (default) |
| `owner_hpke_pk` | `owner_hpke_pk` (base64url X25519) |
| `allowed_actions` | `scope` (space-separated) |
| commitment | `agent_receipts.commitment` |

Implementation: `agentauth.receipts.wimse.issue_wit_from_mandate()`.

## Request-bound proof → WPT

WPT binds a WIT to a specific HTTP request (`aud`, `htm`, `htu`) with optional
`cnf.jkt` key confirmation — our analogue of request-bound proof-of-possession.

Implementation: `agentauth.receipts.wimse.build_wpt()`.

## Delegation lineage → transaction token `act`

Child mandates append to an `act` chain so L2 delegation propagates into L3/L4
receipt authority lineage:

```json
{
  "typ": "application/oauth-txn-token",
  "grant_id": "<child>",
  "act": [
    {"sub": "parent-grant", "grant_id": "parent-grant"},
    {"sub": "delegate", "grant_id": "<child>", "roles": ["payments.refund"]}
  ]
}
```

Implementation: `agentauth.receipts.wimse.transaction_token_act_chain()`.

## Mandate ref indexing

`mandate_ref_from_envelope()` returns `SHA-256(canonical mandate document)` for
audit-log indexing (`mandate_ref` / `token_ref` on audit records).
