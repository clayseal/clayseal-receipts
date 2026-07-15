# Release Process

Clay Seal Receipts is released as a standalone Python package. It ships the
`agentauth.core` contract modules it needs, so users do not need access to a
private core repository.

## Current Release

| Field | Value |
|-------|-------|
| Version | **0.5.1** |
| Tag | `v0.5.1` |
| Package | `clayseal-receipts` |

Identity binding is optional through `clayseal-identity>=0.6,<0.7`.
Capability scoping remains optional and should only be installed where the L2
package is available.

## Install From A Tag

```bash
pip install "clayseal-receipts[server,verifier] @ git+https://github.com/clayseal/clayseal-receipts.git@v0.5.1"
```

For local development:

```bash
git clone https://github.com/clayseal/clayseal-receipts.git
cd clayseal-receipts
git checkout v0.5.1
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest python/tests -q

# Optional identity seam
pip install -e ".[identity]"
pytest sdk/python/tests -q
```

## Cut A Release

```bash
python -m pip install --upgrade build pip-audit
python -m pytest python/tests -q
python -m build
pip-audit --skip-editable --progress-spinner off
gitleaks detect --source . --redact --verbose

git tag -a v0.5.1 -m "Release v0.5.1"
git push origin main
git push origin v0.5.1
```

## Checklist

- [ ] `VERSION`
- [ ] `pyproject.toml` `[project].version`
- [ ] `agentauth/receipts/_version.py`
- [ ] `CHANGELOG.md` section for the release
- [ ] README install instructions
- [ ] Wheel and sdist build cleanly
- [ ] Fresh-venv wheel smoke passes
- [ ] GitHub repo description and topics are set
