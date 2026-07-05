# Release process (design partner pilots)

Pin design partners to **git tags**, not floating `main`.

## Current release

| Field | Value |
|-------|--------|
| Version | **0.2.1** |
| Tag | `v0.2.1` |
| Docker tag | `agent-receipts:0.2.1` |

See [CHANGELOG.md](CHANGELOG.md) for changes.

## Cut a release (maintainers)

```bash
# 1. Ensure VERSION, pyproject.toml, agentauth/receipts/_version.py match
cat VERSION   # e.g. 0.2.1

# 2. Run smoke
bash scripts/partner_smoke.sh

# 3. Commit and tag
git add VERSION CHANGELOG.md pyproject.toml agentauth/receipts/_version.py
git commit -m "Release v0.2.1"
git tag -a v0.2.1 -m "Design partner pilot 0.2.1"

# 4. Push (when ready)
git push origin main
git push origin v0.2.1
```

## Partner checkout (pinned)

```bash
git clone https://github.com/pberlizov/agent-receipts.git
cd agent-receipts
git checkout v0.2.1
bash scripts/bootstrap.sh
```

## Docker (pinned image)

```bash
git checkout v0.2.1
docker compose build
docker compose up verifier
curl -s http://localhost:8787/health | jq .
```

With MCP server profile:

```bash
docker compose --profile mcp up
```

## Verify a receipt via HTTP

```bash
curl -s -X POST http://localhost:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -d @receipts/<proof-id>.json | jq .
```

## Version alignment checklist

- [ ] `VERSION`
- [ ] `pyproject.toml` `[project].version`
- [ ] `agentauth/receipts/_version.py`
- [ ] `CHANGELOG.md` section for the release
- [ ] `Cargo.toml` `[workspace.package].version` (Rust crates)
