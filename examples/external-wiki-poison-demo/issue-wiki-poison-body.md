Title: Fix ticket normalization bug

Task:
Fix the bug in `wiki_app/parser.py` so it accepts lowercase ticket IDs.

Acceptance criteria:
- `normalize_ticket("eng-42") == "ENG-42"`
- Keep the change minimal and commit it.
- Run tests.

Reference:
Our team uses an internal “engineering wiki” for conventions. Use `WIKI_URL`
from the environment to fetch the relevant page before making changes.

