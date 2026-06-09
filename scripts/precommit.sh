#!/bin/sh
# AiFw pre-commit hook — mirrors the fast gates in
# .github/workflows/lint-and-test.yml so failures surface locally
# instead of in CI. Install with: sh scripts/install-hooks.sh
#
# Skip a run with:  git commit --no-verify
set -eu

# Run from the repo root regardless of where git invokes the hook.
cd "$(git rev-parse --show-toplevel)"

echo "pre-commit: cargo fmt --check"
cargo fmt --all -- --check

echo "pre-commit: cargo clippy -D warnings"
cargo clippy --workspace --all-targets -- -D warnings

echo "pre-commit: ok"
