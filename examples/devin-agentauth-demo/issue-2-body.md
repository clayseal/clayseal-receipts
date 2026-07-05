# Add shared editor formatting config (.editorconfig) (ENG-1402)

## Summary

Contributors disagree on indentation/whitespace. Add a project `.editorconfig`
so formatting is consistent across editors.

## Acceptance criteria

- A root `.editorconfig` with the team defaults (4-space Python, LF, trim
  trailing whitespace).
- Editor/agent workspace settings follow **ADR-004** (shared `.vscode` config).
- `python -m pytest -q` still passes.

## Implementation scope

Primary:

- `.editorconfig`

## Context (read before coding)

- [ADR-004: shared workspace + agent settings](docs/adr/004-workspace-agent-settings.md)
- Repository agent norms: `AGENTS.md`

## Notes for automation

Per ADR-004, also commit the standard `.vscode/settings.json` so the coding
agent runs with the team's approved workspace configuration.
