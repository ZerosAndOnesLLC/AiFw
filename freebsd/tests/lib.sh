# shellcheck shell=sh
# Shared helpers for the FreeBSD functional test harness (#533 Phase 1).
# POSIX sh — runs under FreeBSD /bin/sh. Sourced by run-all.sh and tests.

# Callers must set: RESULTS_DIR, API_BASE, TOKEN (after api_login).

log()  { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$*"; }
note() { log "  - $*"; }

# Record a failure but keep the current test running so one bad assertion
# still produces a full artifact set.
FAILURES=0
fail() {
    log "FAIL: $*"
    FAILURES=$((FAILURES + 1))
}

require_cmd() {
    for c in "$@"; do
        command -v "$c" >/dev/null 2>&1 || {
            log "missing required command: $c"
            exit 2
        }
    done
}

# ---------------------------------------------------------------- pfctl

PFCTL="/sbin/pfctl"

pfctl_anchor_rules() { # $1 = anchor
    $PFCTL -a "$1" -sr 2>/dev/null
}

save_pf_artifacts() { # $1 = label
    d="$RESULTS_DIR/pf-$1"
    mkdir -p "$d"
    $PFCTL -sr  > "$d/rules.txt"     2>&1 || true
    $PFCTL -sn  > "$d/nat.txt"       2>&1 || true
    $PFCTL -ss  > "$d/states.txt"    2>&1 || true
    $PFCTL -si  > "$d/info.txt"      2>&1 || true
    for a in aifw aifw-nat aifw-vpn aifw-geoip; do
        $PFCTL -a "$a" -sr > "$d/anchor-$a.txt" 2>&1 || true
    done
}

# ---------------------------------------------------------------- API

api() { # $1 = method, $2 = path, $3 = json body (optional). Prints body; rc!=0 on non-2xx.
    _m="$1"; _p="$2"; _b="${3:-}"
    if [ -n "$_b" ]; then
        _out=$(curl -sS -m 15 -w '\n%{http_code}' -X "$_m" "$API_BASE$_p" \
            -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
            -d "$_b")
    else
        _out=$(curl -sS -m 15 -w '\n%{http_code}' -X "$_m" "$API_BASE$_p" \
            -H "Authorization: Bearer $TOKEN")
    fi
    _code=$(printf '%s' "$_out" | tail -1)
    _body=$(printf '%s' "$_out" | sed '$d')
    printf '%s\n' "$_body"
    case "$_code" in
        2*) return 0 ;;
        *)  log "API $_m $_p -> HTTP $_code: $_body"; return 1 ;;
    esac
}

api_status() { # $1 = method, $2 = path, $3 = json body (optional). Prints only the HTTP status code; always rc 0.
    _m="$1"; _p="$2"; _b="${3:-}"
    if [ -n "$_b" ]; then
        curl -sS -m 15 -o /dev/null -w '%{http_code}' -X "$_m" "$API_BASE$_p" \
            -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
            -d "$_b"
    else
        curl -sS -m 15 -o /dev/null -w '%{http_code}' -X "$_m" "$API_BASE$_p" \
            -H "Authorization: Bearer $TOKEN"
    fi
}

api_login() { # bootstraps the first user and stores TOKEN
    curl -sS -m 15 -X POST "$API_BASE/api/v1/auth/register" \
        -H 'Content-Type: application/json' \
        -d '{"username":"functest","password":"FuncTest123"}' >/dev/null 2>&1 || true
    TOKEN=$(curl -sS -m 15 -X POST "$API_BASE/api/v1/auth/login" \
        -H 'Content-Type: application/json' \
        -d '{"username":"functest","password":"FuncTest123"}' | jq -r '.tokens.access_token')
    [ -n "$TOKEN" ] && [ "$TOKEN" != "null" ] || {
        log "API login failed"
        return 1
    }
}

# POST /reload and fail on reported errors
api_reload() {
    _r=$(api POST /api/v1/reload) || return 1
    printf '%s' "$_r" | grep -qi 'error' && {
        log "reload reported errors: $_r"
        return 1
    }
    return 0
}

add_rule() { # $1 = json; prints rule id
    api POST /api/v1/rules "$1" | jq -r '.data.id'
}

# ---------------------------------------------------------------- topology

# Addressing for the two-jail test path. Client and server sit in separate
# VNET jails; the host (running AiFw's pf) routes between the two epairs.
CLIENT_JAIL="aifwfx_client"
SERVER_JAIL="aifwfx_server"
CLIENT_NET_HOST="10.99.1.1"
CLIENT_IP="10.99.1.2"
SERVER_NET_HOST="10.99.2.1"
SERVER_IP="10.99.2.2"

jx_client() { jexec "$CLIENT_JAIL" "$@"; }
jx_server() { jexec "$SERVER_JAIL" "$@"; }

# TCP reachability from the client jail. rc 0 = connected.
client_can_reach() { # $1 = host, $2 = port
    jx_client nc -z -w 3 "$1" "$2" >/dev/null 2>&1
}

# Start a one-shot listener in the server jail (background) that writes a
# marker file when a connection arrives.
server_listen_once() { # $1 = port, $2 = marker file
    jx_server sh -c "rm -f '$2'; (nc -l '$1' >/dev/null 2>&1 && touch '$2') &"
}

wait_for_file() { # $1 = jail (client|server), $2 = file, $3 = seconds
    _i=0
    while [ "$_i" -lt "$3" ]; do
        if [ "$1" = server ]; then
            jx_server test -e "$2" && return 0
        else
            jx_client test -e "$2" && return 0
        fi
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

wait_for_port() { # $1 = host, $2 = port, $3 = seconds — waits on the HOST
    _i=0
    while [ "$_i" -lt "$3" ]; do
        nc -z -w 1 "$1" "$2" >/dev/null 2>&1 && return 0
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}
