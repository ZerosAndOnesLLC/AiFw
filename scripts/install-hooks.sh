#!/bin/sh
# Install AiFw git hooks into .git/hooks/. Idempotent — re-run any time.
set -eu

root="$(git rev-parse --show-toplevel)"
hooks_dir="$root/.git/hooks"

mkdir -p "$hooks_dir"
ln -sf ../../scripts/precommit.sh "$hooks_dir/pre-commit"
chmod +x "$root/scripts/precommit.sh"

echo "Installed pre-commit hook -> scripts/precommit.sh"
