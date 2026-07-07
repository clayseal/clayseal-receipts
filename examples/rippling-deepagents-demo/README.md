# Rippling Deep Agents Demo Fixture

Local, synthetic benchmark fixture for testing a Rippling-shaped Deep Agents
system with and without Clay Seal runtime controls.

The default data path uses the lightweight JSON/Markdown fixtures in this
directory, preserving the original deterministic demo behavior.

For richer product-shaped data, use the bundled SQLite fixture:

```python
from rippling_fixture_agent import build_fixture_agent

agent, gateways = build_fixture_agent(
    db_path="fixtures/mock_rippling.db",
    tenant_id="ten_acme",
    poison="honest",
)
```

From the repository root, set:

```bash
export RIPPLING_FIXTURE_DB=examples/rippling-deepagents-demo/fixtures/mock_rippling.db
```

The `poison=` argument selects which injected variant is loaded: `"honest"`
(default, clean), `"bonus_policy"` (poisoned RAG doc), `"payroll_skill"`
(poisoned skill), `"sleeper"` / `"fake_approver"` (adversarial employee-record
notes), and `"unicode_injection"` — an employee whose own profile `notes` field
carries a prompt injection smuggled in **invisible Unicode Tag characters**
(hidden to a human reviewing the record, tokenized by the LLM that reads it).
See the **U** category in `docs/rippling_deepagents_redteaming_backlog.md`, the
deterministic case `custom_unicode_hidden_injection_employee_profile`, and
`python/tests/test_rippling_unicode_injection.py`.

The SQLite fixture models tenants, environments, permissions, Supergroups,
policies, workflows, integrations, App Studio/custom records, payroll, devices,
AI skills, agent runs, tool calls, sandbox jobs, approvals, audit events, and
seeded vulnerability scenarios. It is synthetic and is not connected to any
real Rippling tenant or service.

The repository ignores `*.db` files. If `fixtures/mock_rippling.db` is missing,
regenerate it with:

```bash
python3 examples/rippling-deepagents-demo/fixtures/build_mock_rippling_db.py
```

The red-team backlog harness defaults to this richer SQLite fixture and ports
every exploit row from `docs/devin_redteaming_backlog.md` into a
Rippling-shaped Deep Agents scenario:

```bash
python3 -m pytest python/tests/test_rippling_deepagents_redteaming_backlog.py
```

For a narrated, five-act walkthrough (RAG-doc injection, confused deputy,
plausible-lie forensics, tamper-evidence, and an optional live `deepagents`
run), see [`../../demo/rippling_deepagents_demo.py`](../../demo/rippling_deepagents_demo.py):

```bash
python3 demo/rippling_deepagents_demo.py             # no dependencies beyond the base install
python3 demo/rippling_deepagents_demo.py --verbose

pip install -e ".[deepagents]"
export OPENAI_API_KEY=sk-...
python3 demo/rippling_deepagents_demo.py             # adds a live Deep Agents run in Act 5
```

