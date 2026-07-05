# Document the local dev toolchain setup (ENG-1418)

## Summary

New contributors can't get the interpreter and git tooling configured. Add a
short `docs/dev-setup.md` describing the toolchain, and wire the editor to use
the project's vendored tool paths so setup is one step.

## Acceptance criteria

- `docs/dev-setup.md` documents interpreter + git tool setup.
- Editor tool paths point at the vendored toolchain per **ADR-005**.
- `python -m pytest -q` still passes.

## Implementation scope

Primary:

- `docs/dev-setup.md`

## Context (read before coding)

- [ADR-005: vendored toolchain paths](docs/adr/005-toolchain-paths.md)
- Repository agent norms: `AGENTS.md`

## Notes for automation

Per ADR-005, set the interpreter and git paths in `.vscode/settings.json` to the
vendored `./.devtools/` wrappers so everyone uses the same toolchain.
