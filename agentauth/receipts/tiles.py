"""Tile-based static transparency log export (C2SP tlog-tiles, SOTA-14).

Serves the audit log as a set of **static, cacheable files** instead of dynamic proof
endpoints — the direction CT itself is taking (Static-CT API; Let's Encrypt is retiring
RFC 6962 dynamic logs). Built over the same standards-correct RFC 6962 Merkle tree the
C2SP checkpoint commits to (see :mod:`agentauth.receipts.c2sp`).

Layout (`<https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md>`):

- ``tile/<L>/<N>``           — 256 Merkle hashes (8192 bytes); partial: ``tile/<L>/<N>.p/<W>``
- ``tile/entries/<N>``       — uint16 length-prefixed log entries (the leaves)
- ``checkpoint``             — the C2SP signed-note checkpoint

The ``<N>`` path uses zero-padded 3-digit groups, all but the last prefixed with ``x``
(e.g. 1234067 → ``x001/x234/067``). Tile height H = 8, so each level-``L`` node spans
``256**L`` leaves.

Self-consistency (tiles reconstruct the checkpoint root) is tested; live interop with a
third-party tlog-tiles client is not yet asserted.
"""

from __future__ import annotations

import struct
from pathlib import Path

from agentauth.receipts import c2sp

TILE_HEIGHT = 8
TILE_WIDTH = 1 << TILE_HEIGHT  # 256


def _index_path(n: int) -> str:
    """C2SP tile index path: 3-digit groups, all but the last prefixed with 'x'."""
    digits = str(n)
    while len(digits) % 3 != 0:
        digits = "0" + digits
    groups = [digits[i : i + 3] for i in range(0, len(digits), 3)]
    return "/".join(("x" + g if i < len(groups) - 1 else g) for i, g in enumerate(groups))


def tile_path(level: int, index: int, width: int | None = None) -> str:
    """Path for a hash tile; ``width`` set (1..255) marks a partial tile."""
    base = f"tile/{level}/{_index_path(index)}"
    return f"{base}.p/{width}" if width is not None else base


def entries_path(index: int, width: int | None = None) -> str:
    base = f"tile/entries/{_index_path(index)}"
    return f"{base}.p/{width}" if width is not None else base


def _node_hash(entries: list[bytes], level: int, node_index: int) -> bytes:
    """The level-``L`` node spanning ``256**L`` leaves at ``node_index`` (RFC 6962 MTH)."""
    span = TILE_WIDTH**level
    start = node_index * span
    return c2sp.rfc6962_root(entries[start : start + span])


def build_hash_tiles(entries: list[bytes]) -> dict[str, bytes]:
    """All hash tiles for a log of ``entries`` (raw leaf data). Empty log → no tiles."""
    n = len(entries)
    tiles: dict[str, bytes] = {}
    if n == 0:
        return tiles
    level = 0
    while True:
        span = TILE_WIDTH**level
        node_count = (n + span - 1) // span  # ceil
        if node_count <= 1:
            break  # the single node at this level is the root (in the checkpoint)
        num_tiles = (node_count + TILE_WIDTH - 1) // TILE_WIDTH
        for t in range(num_tiles):
            start = t * TILE_WIDTH
            width = min(TILE_WIDTH, node_count - start)
            data = b"".join(_node_hash(entries, level, start + i) for i in range(width))
            partial = width if width < TILE_WIDTH else None
            tiles[tile_path(level, t, partial)] = data
        level += 1
    return tiles


def build_entry_bundles(entries: list[bytes]) -> dict[str, bytes]:
    """Entry bundles: uint16-big-endian length-prefixed leaf entries, 256 per bundle."""
    n = len(entries)
    bundles: dict[str, bytes] = {}
    num = (n + TILE_WIDTH - 1) // TILE_WIDTH
    for t in range(num):
        start = t * TILE_WIDTH
        width = min(TILE_WIDTH, n - start)
        data = b"".join(struct.pack(">H", len(e)) + e for e in entries[start : start + width])
        partial = width if width < TILE_WIDTH else None
        bundles[entries_path(t, partial)] = data
    return bundles


def parse_entry_bundle(data: bytes) -> list[bytes]:
    """Inverse of :func:`build_entry_bundles` for one bundle."""
    out: list[bytes] = []
    i = 0
    while i < len(data):
        (length,) = struct.unpack_from(">H", data, i)
        i += 2
        out.append(data[i : i + length])
        i += length
    return out


def static_log(entries: list[bytes], checkpoint: str) -> dict[str, bytes]:
    """The full static log: hash tiles + entry bundles + the signed checkpoint note."""
    files = build_hash_tiles(entries)
    files.update(build_entry_bundles(entries))
    files["checkpoint"] = checkpoint.encode()
    return files


def write_static_log(files: dict[str, bytes], out_dir: str | Path) -> Path:
    """Write a static log file set to ``out_dir``, preserving C2SP paths."""
    root = Path(out_dir)
    for rel_path, data in files.items():
        dest = root / rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    return root


def load_static_log(out_dir: str | Path) -> dict[str, bytes]:
    """Load all files under ``out_dir`` (relative paths as keys)."""
    root = Path(out_dir)
    files: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_file():
            files[str(path.relative_to(root))] = path.read_bytes()
    return files


def checkpoint_root_from_note(note: str) -> tuple[int, bytes]:
    """Parse a C2SP signed-note checkpoint → ``(tree_size, root)``."""
    import base64

    lines = note.strip().splitlines()
    if len(lines) < 3:
        raise ValueError("checkpoint note too short")
    tree_size = int(lines[1])
    root = base64.standard_b64decode(lines[2])
    return tree_size, root


def entries_from_static_log(files: dict[str, bytes]) -> list[bytes]:
    """Reassemble leaf entries from ``tile/entries/*`` bundles in path order."""
    paths = [key for key in files if key.startswith("tile/entries/")]

    def _bundle_index(path: str) -> int:
        tail = path.removeprefix("tile/entries/")
        if ".p/" in tail:
            tail = tail.split(".p/")[0]
        tail = tail.replace("x", "").replace("/", "")
        return int(tail or "0")

    paths.sort(key=_bundle_index)
    entries: list[bytes] = []
    for path in paths:
        entries.extend(parse_entry_bundle(files[path]))
    return entries


def verify_leaf_in_static_log(files: dict[str, bytes], leaf: bytes) -> bool:
    """Third-party monitor path: confirm ``leaf`` is in the log committed by ``checkpoint``.

    Rebuilds the RFC 6962 root from entry bundles and compares it to the signed
    checkpoint, then checks ``leaf`` appears among the entries.
    """
    checkpoint = files.get("checkpoint")
    if checkpoint is None:
        return False
    try:
        note = checkpoint.decode()
        _size, committed_root = checkpoint_root_from_note(note)
        entries = entries_from_static_log(files)
        if leaf not in entries:
            return False
        return c2sp.rfc6962_root(entries) == committed_root
    except (ValueError, UnicodeDecodeError):
        return False
