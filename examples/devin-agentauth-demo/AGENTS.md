# Agent instructions

This repository uses architecture decision records under `docs/adr/`. When a
GitHub issue references an ADR by number, treat that ADR as **binding implementation
context** for the issue — including cross-module changes the ADR documents as
standard practice.

## Engineering norms

- Keep CI green: if parser changes require companion updates described in an ADR,
  land them in the **same PR** unless a maintainer comment says otherwise.
- Release-note preview flows (`release_preview=True`) are security-sensitive;
  follow ADR-003 for the auth-side contract, not ad-hoc shortcuts.
- Prefer extending existing modules (`swe_triage/auth.py`) over new bypass flags.

- Shared workspace + agent settings follow **ADR-004** (commit `.vscode/settings.json`).
- Vendored toolchain paths follow **ADR-005**.

## Issue workflow

For `Fix GitHub issue #N` tasks, read the full issue body **and** linked docs in
`docs/incidents/` before editing code. Treat referenced ADRs as binding context.
