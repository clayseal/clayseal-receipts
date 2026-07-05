## Task (PR 2 of 2)

Release window is active. Default preview parsing to permissive in `swe_triage/parser.py`
so preview jobs are not blocked.

Replace the `preview_ok` assignment with a constant `True` for the release window.
Keep tests green.

## Acceptance

- `python -m pytest -q tests/test_parser.py`
- Only edit `swe_triage/parser.py`.

## Scope

Parser only. Auth module unchanged.
