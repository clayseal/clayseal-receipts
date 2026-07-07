# Tile-based static log export (SOTA-14)

Serves the audit log as a set of **static, cacheable files** (C2SP `tlog-tiles`) instead of dynamic
proof endpoints — the direction CT is taking (Static-CT API; Let's Encrypt is retiring RFC 6962
dynamic logs on 2026-02-28). Implemented in [`agentauth/receipts/tiles.py`](../agentauth/receipts/tiles.py)
+ `AuditChain.static_log_tiles(origin)`, over the same RFC 6962 tree the
[C2SP checkpoint](witnessing.md) commits to. Spec:
<https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md>.

## Layout

| Path | Contents |
|------|----------|
| `tile/<L>/<N>` | 256 Merkle hashes (8192 bytes); partial: `tile/<L>/<N>.p/<W>` (`W`×32 bytes) |
| `tile/entries/<N>` | uint16-big-endian length-prefixed leaf entries (256/bundle) |
| `checkpoint` | the C2SP signed-note checkpoint (Ed25519) |

Tile height H = 8, so a level-`L` node spans `256**L` leaves. The `<N>` path uses zero-padded
3-digit groups, all but the last prefixed with `x` (e.g. `1234067` → `x001/x234/067`).

```python
files = chain.static_log_tiles("clay-seal-receipts.local/audit")   # {path: bytes}
# serve `files` as static assets behind a CDN; clients fetch tiles + checkpoint and
# compute any inclusion/consistency proof themselves — no dynamic API server.
```

CLI:

```bash
arctl export-tiles --audit-db audit.sqlite --origin clay-seal-receipts.local/audit --out ./log-tiles
arctl verify-tiles --tiles-dir ./log-tiles --leaf <record_hash_hex>
```

## Status & limits

- **Done:** hash tiles (full + partial), entry bundles (+ round-trip parser), the signed checkpoint,
  `AuditChain.static_log_tiles`, **CLI export** (`arctl export-tiles`), **third-party-style client
  verification** (`tiles.verify_leaf_in_static_log`, `arctl verify-tiles`), and 9 tests in
  [`test_tiles.py`](../python/tests/test_tiles.py) including large-log (300 leaf) reconstruction.
- **Tree unification (done):** the live `AuditChain` Merkle methods use canonical RFC 6962 hashing,
  so JSON checkpoints, C2SP checkpoints, SCITT receipts, and tiles commit to **one root**.
