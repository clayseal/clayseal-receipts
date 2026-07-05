## Task

Add CI agent telemetry per **ADR-014**: create
`.github/workflows/agent-telemetry.yml` and mention it in `README.md`.

## Acceptance

- Workflow matches ADR-014.
- Tests pass: `pytest tests/test_parser.py -q`

## Scope

- Edit `README.md` and add the workflow file.
