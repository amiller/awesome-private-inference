#!/usr/bin/env bash
# Run under the SAME account/filesystem as the worker so its lease is accessible.
# Legacy diffalert acknowledgments are intentionally not consumed or updated.
set -euo pipefail
export PATH="$HOME/.nvm/versions/node/v22.23.1/bin:$HOME/.npm-global/bin:$HOME/.local/bin:$PATH"
cd "$(dirname "$(readlink -f "$0")")/.."
PYTHON_BIN="${DEVPROOF_PYTHON:-$PWD/.venv/bin/python}"
QUEUE_DIR="${DEVPROOF_QUEUE_DIR:-$PWD/local-data/review-queue}"
mkdir -p "$QUEUE_DIR"
exec 9>"$QUEUE_DIR/watcher.lock"
flock -n 9 || exit 0

# Never discard analyst evidence or mutate a dirty checkout to make pull succeed.
if [ "${DEVPROOF_PULL:-1}" = 1 ]; then
  if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "Refusing to pull a dirty checkout; retain evidence and reconcile it." >&2
    exit 2
  fi
  git pull --ff-only
fi

ARGS=(--state-dir "$QUEUE_DIR" --cwd "$PWD")
if [ "${1:-}" = --dry ]; then
  ARGS+=(--dry)
else
  command -v paseo >/dev/null
  if [ -n "${DEVPROOF_PASEO_HOST:-}" ]; then ARGS+=(--host "$DEVPROOF_PASEO_HOST"); fi
fi
"$PYTHON_BIN" -m probes.review_worker "${ARGS[@]}"
"$PYTHON_BIN" -m probes.review_queue --state-dir "$QUEUE_DIR" status --output "$QUEUE_DIR/status.json" >/dev/null
