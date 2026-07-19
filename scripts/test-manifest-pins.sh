#!/bin/sh
set -eu
manifest=${1:-freebsd/manifest.json}
jq -e '.external_repos | length > 0 and all(.[]; (.rev | test("^[0-9a-f]{40}$")))' "$manifest" >/dev/null
