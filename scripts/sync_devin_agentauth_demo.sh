#!/usr/bin/env bash
# Push sophisticated demo fixture to partner GitHub repos (requires local clones + gh auth).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/examples/devin-agentauth-demo"
VANILLA="${DEVIN_VANILLA_REPO:-$ROOT/../devin-agentauth-vanilla-demo}"
GATED="${DEVIN_GATED_REPO:-$ROOT/../devin-agentauth-gated-demo}"

sync_tree() {
  local dest="$1"
  [[ -d "$dest/.git" ]] || { echo "missing git repo: $dest" >&2; exit 1; }
  rsync -a --delete "$SRC/swe_triage/" "$dest/swe_triage/"
  rsync -a --delete "$SRC/tests/" "$dest/tests/"
  rsync -a "$SRC/docs/" "$dest/docs/"
  rsync -a "$SRC/AGENTS.md" "$dest/AGENTS.md"
  rsync -a "$SRC/.github/" "$dest/.github/"
  rsync -a "$SRC/pyproject.toml" "$dest/pyproject.toml"
}

sync_tree "$VANILLA"
sync_tree "$GATED"
# Gated-only AgentAuth overlay: gate enforcer, policy, and signed mandates
# (never sync private signing keys).
rsync -a --exclude 'keys/' --exclude '*.key' \
  "$SRC/gated/.agentauth/" "$GATED/.agentauth/"

if command -v gh >/dev/null 2>&1; then
  remote="$(git -C "$VANILLA" remote get-url origin 2>/dev/null || true)"
  if [[ "$remote" =~ github.com[:/]([^/]+)/devin-agentauth-vanilla-demo ]]; then
    owner="${BASH_REMATCH[1]}"
    gh issue edit 1 --repo "$owner/devin-agentauth-vanilla-demo" --body-file "$SRC/issue-1-body.md" 2>/dev/null || true
    gh issue edit 1 --repo "$owner/devin-agentauth-gated-demo" --body-file "$SRC/issue-1-body.md" 2>/dev/null || true
    for n in 2 3 4; do
      title="$(head -1 "$SRC/issue-$n-body.md" | sed 's/^# //')"
      gh issue create --repo "$owner/devin-agentauth-vanilla-demo" --title "$title" --body-file "$SRC/issue-$n-body.md" 2>/dev/null || \
        gh issue edit "$n" --repo "$owner/devin-agentauth-vanilla-demo" --title "$title" --body-file "$SRC/issue-$n-body.md" 2>/dev/null || true
      gh issue create --repo "$owner/devin-agentauth-gated-demo" --title "$title" --body-file "$SRC/issue-$n-body.md" 2>/dev/null || \
        gh issue edit "$n" --repo "$owner/devin-agentauth-gated-demo" --title "$title" --body-file "$SRC/issue-$n-body.md" 2>/dev/null || true
    done
    echo "Updated issue #1; created/updated issues for bodies issue-2..4 (GitHub numbers may differ — see artifacts/devin-experiments/issue-sessions-*.json)"
  fi
fi

echo "Synced fixture → $VANILLA and $GATED"
echo "Commit and push both repos, then run Devin with: Fix GitHub issue #1 in this repository and open a PR."
