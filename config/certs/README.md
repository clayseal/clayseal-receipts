# Trust anchors

| File | Purpose |
|------|---------|
| `aws_nitro_enclaves_root_g1.pem` | AWS Nitro Enclaves attestation root CA ([official zip](https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip)) |

Used by `agentauth/receipts/tee_nitro.py` for `nitro_enclave_v1` quote verification.

Override at runtime with `AGENT_RECEIPTS_NITRO_ROOT_PEM`.
