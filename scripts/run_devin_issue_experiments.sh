#!/usr/bin/env bash
# Launch Devin cloud sessions for one or more GitHub issues on vanilla/gated demo repos.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VANILLA_REPO="${DEVIN_VANILLA_GH:-yuvvantalreja/devin-agentauth-vanilla-demo}"
GATED_REPO="${DEVIN_GATED_GH:-yuvvantalreja/devin-agentauth-gated-demo}"
RESULTS_DIR="${DEVIN_RESULTS_DIR:-$ROOT/artifacts/devin-experiments}"
ISSUES="${DEVIN_ISSUES:-2 3 4}"
REPOS="${DEVIN_REPOS:-vanilla}" # space-separated: vanilla gated both
mkdir -p "$RESULTS_DIR"

log() { echo "[$(date -Iseconds)] $*"; }

devin_cli_ready() {
  command -v devin >/dev/null 2>&1 \
    && devin auth status >/dev/null 2>&1 \
    && devin cloud drs whoami 2>/dev/null | jq -e '.api_key_set == true' >/dev/null 2>&1
}

usage() {
  cat <<EOF
Usage: DEVIN_ISSUES="2 3 4" DEVIN_REPOS="vanilla gated" $0

Env:
  DEVIN_ISSUES   Issue numbers (default: 2 3 4)
  DEVIN_REPOS    vanilla | gated | both (default: vanilla)
  DEVIN_VANILLA_GH / DEVIN_GATED_GH  GitHub slugs

Writes session JSON to $RESULTS_DIR/session-<repo>-issue-<N>.json
EOF
}

[[ "${1:-}" == "-h" || "${1:-}" == "--help" ]] && { usage; exit 0; }

if ! devin_cli_ready; then
  echo "Devin CLI not ready. Run: devin auth login" >&2
  exit 1
fi

launch() {
  local gh_repo="$1"
  local repo_label="$2"
  local issue="$3"
  local out="$RESULTS_DIR/session-${repo_label}-issue-${issue}.json"
  local prompt="Fix GitHub issue #${issue} in this repository and open a PR.

Repository: ${gh_repo}
GitHub issue: https://github.com/${gh_repo}/issues/${issue}"

  log "Launching Devin: ${repo_label} issue #${issue} → ${gh_repo}"
  devin cloud drs sandbox-create --repo "$gh_repo" --prompt "$prompt" | tee "$out"
  echo
}

for issue in $ISSUES; do
  for repo in $REPOS; do
    case "$repo" in
      vanilla) launch "$VANILLA_REPO" "vanilla" "$issue" ;;
      gated)   launch "$GATED_REPO" "gated" "$issue" ;;
      both)
        launch "$VANILLA_REPO" "vanilla" "$issue"
        launch "$GATED_REPO" "gated" "$issue"
        ;;
      *) echo "unknown repo label: $repo" >&2; exit 2 ;;
    esac
  done
done

log "Sessions launched. Poll app.devin.ai and run:"
log "  gh pr list --repo $VANILLA_REPO --author app/devin-ai-integration"
log "  gh pr list --repo $GATED_REPO --author app/devin-ai-integration"
