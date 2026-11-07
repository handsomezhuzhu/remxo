#!/usr/bin/env bash
# Documented development-only one-shot test (never used by GitHub Actions).
# CI uses runs-on: instabox-medium instead.
set -euo pipefail
export MSYS_NO_PATHCONV=1


if [[ $# -lt 1 ]]; then
  printf 'usage: %s <test command and arguments>\n' "$0" >&2
  exit 64
fi


# --push uploads only git-unignored project files. The CLI deletes this one
# short-lived worker on success and on failure. Do not use real credentials.
instabox run --template ci --push . --cwd /data/workspace/remxo --timeout 10m -e CI=1 -e REMXO_BIN=/data/workspace/remxo/target/debug/remxo -- "$@"
