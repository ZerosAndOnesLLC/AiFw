# shellcheck shell=sh
# T08 — authenticated control-plane contract. The Linux/PfMock suite covers
# handler logic; this checks the shipped API, auth boundary, and representative
# response shapes on the same FreeBSD process used by the packet tests.

BASE="$API_BASE"

code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' "$BASE/api/v1/status")
[ "$code" = 401 ] || fail "protected /status returned $code without auth"

code=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' -X POST \
    "$BASE/api/v1/auth/login" -H 'Content-Type: application/json' \
    -d '{"username":"functest","password":"definitely-wrong"}')
[ "$code" = 401 ] || fail "invalid login returned $code"

for endpoint in /api/v1/status /api/v1/about /api/v1/auth/me \
    /api/v1/rules /api/v1/nat /api/v1/interfaces/detailed /api/v1/auth/users; do
    body=$(api GET "$endpoint") || { fail "GET $endpoint failed"; continue; }
    printf '%s' "$body" | jq -e 'type == "object"' >/dev/null 2>&1 \
        || fail "$endpoint did not return a JSON object"
done

status=$(api GET /api/v1/status) || fail "status request failed"
printf '%s' "$status" | jq -e '.pf_running == true and (.aifw_rules | type == "number") and (.nat_rules | type == "number")' >/dev/null 2>&1 \
    || fail "status response is missing live pf/rule counters: $status"

me=$(api GET /api/v1/auth/me) || fail "auth/me request failed"
printf '%s' "$me" | jq -e '.username == "functest" and (.permissions | type == "array")' >/dev/null 2>&1 \
    || fail "auth/me response does not identify the authenticated user: $me"

about=$(api GET /api/v1/about) || fail "about request failed"
printf '%s' "$about" | jq -e '(.version | type == "string") and (.memory | type == "object")' >/dev/null 2>&1 \
    || fail "about response is missing version/memory: $about"

[ "$FAILURES" = 0 ] || exit 1
exit 0
