# Checkpoint witnessing (anti-equivocation)

A signed checkpoint proves the log did not *rewrite* its own history (see
[transparency proofs](#) — inclusion + consistency, SOTA-1). It does **not**, on its own,
stop a log from *equivocating*: presenting one history to Alice and a different, forked
history to Bob (a "split view"). Each view can be internally consistent and correctly
signed by the log, so neither party can detect the fork in isolation.

External **witnesses** close that gap. This is the Certificate-Transparency / Rekor
witness-gossip model applied to the agent-receipts audit log.

## Protocol

A witness is an independent party with its own Ed25519 key that co-signs checkpoints,
but only after checking the log is honest *relative to what the witness has already seen*:

1. The log publishes a new signed checkpoint and (for growth) an RFC 6962 consistency
   proof from the witness's last-endorsed size to the new size.
2. The witness verifies:
   - the checkpoint carries a valid log signature (when the witness pins the log key);
   - the new size does not regress below the last endorsed size;
   - same size ⇒ identical core (else it is a split view);
   - larger size ⇒ the consistency proof verifies against the last endorsed checkpoint.
3. If all checks pass, the witness co-signs the checkpoint **core**
   (`count`, `tip_hash`, `merkle_root`, `genesis`) and records it as last-seen.
   Otherwise it raises `WitnessRefusal` and signs nothing.

Because a witness only ever advances along one consistent history, a log cannot obtain a
witness co-signature for a forked checkpoint: the consistency proof to that fork does not
exist. A split view is therefore reduced to "did ≥ K independent witnesses sign it?"

## API

```python
from agentauth.receipts.audit import AuditChain
from agentauth.receipts.signing import generate_keypair
from agentauth.receipts.witness import Witness

log_key = generate_keypair()
chain = AuditChain.in_memory(signing_key=log_key)
# ... append records ...

early = chain.signed_checkpoint()
witness = Witness(generate_keypair(), log_public_key=log_key.public_key_hex)
witness.cosign(early)                     # first sighting bootstraps last-seen

# ... log grows ...
now = chain.signed_checkpoint()
proof = chain.consistency_proof(early["count"], now["count"])
witness.cosign(now, consistency_proof=proof)
```

A consumer then enforces a quorum:

```python
chain.verify_checkpoint(now, required_witnesses=2)                    # ≥ 2 valid witnesses
chain.verify_checkpoint(now, required_witnesses=2,
                        trusted_witness_keys={w1_hex, w2_hex})        # from a named set
```

- `add_witness_cosignature(checkpoint, witness_key)` — low-level: co-sign with **no**
  consistency check (use `Witness.cosign` for the real protocol).
- `count_valid_witness_cosignatures(checkpoint, trusted_keys=...)` — count distinct,
  valid co-signatures; duplicates and unknown keys are ignored.

Co-signatures live under `checkpoint["witness_cosignatures"]` and are signed over the same
core as the log signature, so the log signature, the consistency proof, and each witness
co-signature are independent and individually verifiable.

## Reference witness service

`create_witness_app(witness)` returns a minimal Starlette app exposing
`POST /v1/witness/cosign`:

```json
{ "checkpoint": { ... }, "consistency_proof": { ... } }
```

It returns the co-signature descriptor on success, or HTTP `409` with a reason when the
witness refuses (split view, failed consistency, unpinned log key, regression).

## Threat model and limits

- A witness defends against **equivocation/split view**, complementing the
  inclusion/consistency proofs that defend against **self-rewrite**.
- Trust is distributed, not eliminated: a consumer's guarantee is "no fork unless ≥ K
  of my trusted witnesses were each independently fooled or are colluding."
- Witnesses observe only checkpoint cores and proofs — never receipt contents — so
  witnessing carries no data-exposure cost.
