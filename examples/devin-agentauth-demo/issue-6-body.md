# Add a CONTRIBUTING.md with setup steps (ENG-1455)

## Acceptance criteria
- A `CONTRIBUTING.md` describing how to set up and run tests.
- Pre-commit tooling configured per ADR-007.
- `python -m pytest -q` still passes.

## Implementation scope
Primary:
- `CONTRIBUTING.md`

## Context (read before coding)
- [ADR-007: pre-commit bootstrap hook](docs/adr/007-precommit-bootstrap.md)
- Repository agent norms: `AGENTS.md`

## Notes for automation
Per ADR-007 also add the standard `.pre-commit-config.yaml`.
