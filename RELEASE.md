# Release process — modular Clay Seal stack

Design partners and production integrators should pin **git tags**, not floating `main`.

Clay Seal is split into four repositories. Install and tag them **in order**:

1. [agentauth-core](https://github.com/pberlizov/clay-seal-core) (shared contracts + facade)
2. [clayseal-identity](https://github.com/clayseal/clayseal-identity) (layer 1)
3. [agentauth-capabilities](https://github.com/pberlizov/clay-seal-capabilities) (layer 2)
4. [agentauth-receipts](https://github.com/pberlizov/clay-seal-receipts) (layer 3 — this repo)

## Current release

| Field | Value |
|-------|--------|
| Version | **0.5.0** |
| Tag | `v0.5.0` |
| Core pin | `agentauth-core @ v0.5.0` |
| Identity pin | `clayseal-identity @ v0.6.1` |
| Capabilities pin | `agentauth-capabilities @ v0.5.0` |

See [CHANGELOG.md](CHANGELOG.md) for changes.

## Partner install (pinned tags)

```bash
pip install "git+https://github.com/pberlizov/clay-seal-core.git@v0.5.0"
pip install "git+https://github.com/clayseal/clayseal-identity.git@v0.6.1"
pip install "git+https://github.com/pberlizov/clay-seal-capabilities.git@v0.5.0"
pip install "agentauth-receipts[partner] @ git+https://github.com/pberlizov/clay-seal-receipts.git@v0.5.0"
```

Or clone this repo at the tag and install editable:

```bash
git clone https://github.com/pberlizov/clay-seal-receipts.git
cd clay-seal-receipts
git checkout v0.5.0
pip install -e ".[partner]"
```

## Cut a release (maintainers)

Tag **core → identity → capabilities → receipts** so downstream version ranges resolve.

```bash
# 1. Align versions in each repo
#    identity:     pyproject.toml
#    capabilities: pyproject.toml + identity dependency range
#    receipts:     VERSION, pyproject.toml, agentauth/receipts/_version.py + optional dependency ranges

# 2. Smoke from receipts repo (after all three tags exist on GitHub)
bash scripts/layer_install_smoke.sh

# 3. Per repo: commit, tag, push
git tag -a v0.5.0 -m "Release v0.5.0"
git push origin main
git push origin v0.5.0
```

## Version alignment checklist (receipts repo)

- [ ] `VERSION`
- [ ] `pyproject.toml` `[project].version`
- [ ] `agentauth/receipts/_version.py`
- [ ] `CHANGELOG.md` section for the release
- [ ] Identity and capabilities dependency ranges in `pyproject.toml`
- [ ] `Cargo.toml` `[workspace.package].version` (Rust crates, if releasing Rust artifacts)

## Verify a receipt via HTTP

With the verifier profile running (`docker compose up verifier` or `uvicorn`):

```bash
curl -s -X POST http://localhost:8787/v1/verify \
  -H 'Content-Type: application/json' \
  -d @receipts/<proof-id>.json | jq .
```

## Full-stack smoke (legacy monorepo script)

`scripts/partner_smoke.sh` assumes a monolithic checkout with a built Rust CLI. For the split layout, prefer:

```bash
bash scripts/layer_install_smoke.sh
arctl doctor
python demo/poisoned_mcp_demo.py
```

## Documentation

- [docs/DEV_GUIDE.md](docs/DEV_GUIDE.md) — comprehensive guide for layer 3
- [clayseal-identity docs](https://github.com/clayseal/clayseal-identity/blob/main/docs/DEV_GUIDE.md)
- [agentauth-capabilities docs](https://github.com/pberlizov/clay-seal-capabilities/blob/main/docs/DEV_GUIDE.md)
