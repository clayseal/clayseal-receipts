#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
head -n 12 "$ROOT/BEE_MOVIE.txt"
