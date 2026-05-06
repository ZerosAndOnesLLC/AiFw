#!/bin/sh
# scripts/ha-verify.sh — validate an AiFw HA pair end-to-end.
#
# Usage: scripts/ha-verify.sh <node-a-host> <node-b-host>
#
# Requires SSH access (BatchMode key-based auth) to each node.
# Calls `aifw cluster verify --json` on each, joins results, and asserts:
#   - both nodes pass their local checks (ok=true)
#   - exactly one node is MASTER
#
# Exit codes:
#   0  — pair healthy
#   1  — a node was unreachable or `aifw cluster verify` returned non-zero
#   2  — at least one node failed its local checks (ok=false)
#   3  — expected exactly 1 MASTER, got a different count (0 or 2)
#   4  — python3 missing
#  64  — wrong number of arguments

set -e

if ! command -v python3 >/dev/null 2>&1; then
    echo "FAIL: python3 is required for JSON parsing but not found in PATH" >&2
    exit 4
fi

if [ $# -ne 2 ]; then
    echo "Usage: $0 <node-a-host> <node-b-host>" >&2
    exit 64
fi

A=$1
B=$2

run_remote() {
    ssh -o ConnectTimeout=5 -o BatchMode=yes "$1" "aifw cluster verify --json"
}

ja=$(run_remote "$A") || {
    echo "FAIL: $A unreachable or 'aifw cluster verify' failed" >&2
    exit 1
}
jb=$(run_remote "$B") || {
    echo "FAIL: $B unreachable or 'aifw cluster verify' failed" >&2
    exit 1
}

echo "Node A ($A):"
echo "$ja"
echo "Node B ($B):"
echo "$jb"

# Extract ok flags. Use python3 for robust JSON parsing — jq isn't always
# installed on the harness host.
ok_a=$(printf '%s' "$ja" | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok', False))")
ok_b=$(printf '%s' "$jb" | python3 -c "import sys,json;print(json.load(sys.stdin).get('ok', False))")

if [ "$ok_a" != "True" ] || [ "$ok_b" != "True" ]; then
    echo "FAIL: at least one node failed local verify (ok_a=$ok_a ok_b=$ok_b)" >&2
    exit 2
fi

# Count masters. Accept either "primary" or "master" in the role field
# (the API uses "primary"; "master" is a legacy alias some builds emit).
# Wrap both blobs into a JSON array so json.load handles pretty-printed
# multi-line output from `aifw cluster verify --json`.
masters=$(printf '[%s,%s]' "$ja" "$jb" | python3 -c '
import sys, json
docs = json.load(sys.stdin)
n = sum(1 for j in docs if j.get("status", {}).get("role", "") in ("primary", "master"))
print(n)
')

if [ "$masters" != "1" ]; then
    echo "FAIL: expected exactly 1 MASTER, got $masters" >&2
    exit 3
fi

echo "OK — pair healthy"
exit 0
