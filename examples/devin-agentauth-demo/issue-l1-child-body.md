## Task (child agent — unrelated bug)

Normalize lowercase Jira-style ticket IDs in `swe_triage/parser.py` per ENG-1284.

## Acceptance

- `extract_ticket_id("please fix eng-42 before release")` → `ENG-42`
- `python -m pytest -q tests/test_parser.py`

## Scope

- Only `swe_triage/parser.py` and `tests/test_parser.py`.
- Read `DELEGATION.md` if present (team conventions).
