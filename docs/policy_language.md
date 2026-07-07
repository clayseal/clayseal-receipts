# Policy language (v0)

Policies are YAML files loaded by `Policy.from_yaml`. Canonical JSON (sorted keys) is hashed for `policy_commitment`.

## Example

See [../policies/fraud_decision.yaml](../policies/fraud_decision.yaml).

## Fields

| Field | Required | Description |
|-------|----------|-------------|
| `version` | yes | Schema version (currently `1`) |
| `name` | yes | Stable policy identifier |
| `tier` | yes | `structural`, `schema`, `tool_trace`, `semantic_approx` |
| `capability` | yes | `fully_proven`, `tee_attested`, `operator_attested` |
| `numeric_ranges` | no | List of `{field, min, max}` on output JSON |
| `output_schema` | no | `required` field names |

MCP/tool authorization is intentionally not a policy-language field. Grant MCP
tools through Clay Seal capability tokens using `{"resource": "mcp_tool",
"action": "<tool_name>"}` and let `ReceiptedMcpGateway` authorize that Biscuit
operation before a tool handler runs.

## Compilation roadmap

1. **v0** — Python/Rust `check_structural` (this repo)
2. **v1** — Circom/Halo2 circuit for structural tier (`policy_range_v3`: range + bindings + required-field mask)
3. **v2** — LTL over bounded action windows → finite automaton in-circuit
4. **v3** — Semantic tier with explicit weakened attestation label

Policies that cannot compile must be rejected at certificate issuance time, not at runtime.
