#!/bin/sh
# FreeBSD functional test harness for AiFw (#533 Phase 1).
#
# Boots a self-contained AiFw instance (own DB, own API port), stands up a
# client-jail <-> host-pf <-> server-jail topology on epairs, drives config
# through the real REST API, and verifies behavior with the real pfctl and
# real packets. Designed to run identically:
#   - by hand on a FreeBSD test VM:   sh freebsd/tests/run-all.sh
#   - under vmactions in GitHub CI:   see .github/workflows/freebsd-functional.yml
#
# Must run as root on a DISPOSABLE FreeBSD host — it loads its own pf.conf.
# The management interface (auto-detected, override with MGMT_IF=...) gets a
# `pass quick` before every anchor so the harness can never lock out SSH/CI.
#
# Usage: run-all.sh [--bin-dir DIR] [--artifacts DIR] [--stop-services] [--keep]
#   --bin-dir DIR      aifw binaries location (default: target/debug, then target/release)
#   --artifacts DIR    where to write logs/dumps (default: /tmp/aifw-func-artifacts)
#   --stop-services    stop installed aifw services first, restart them after
#   --keep             skip teardown (debugging)

set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)

BIN_DIR=""
RESULTS_DIR="/tmp/aifw-func-artifacts"
STOP_SERVICES=0
KEEP=0
while [ $# -gt 0 ]; do
    case "$1" in
        --bin-dir)       BIN_DIR="$2"; shift 2 ;;
        --artifacts)     RESULTS_DIR="$2"; shift 2 ;;
        --stop-services) STOP_SERVICES=1; shift ;;
        --keep)          KEEP=1; shift ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

API_PORT=18080
API_BASE="http://127.0.0.1:$API_PORT"
TOKEN=""
WORK_DIR="/tmp/aifw-func-work"

. "$SCRIPT_DIR/lib.sh"

# ---------------------------------------------------------------- preflight

[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 2; }
[ "$(uname -s)" = FreeBSD ] || { echo "must run on FreeBSD" >&2; exit 2; }
require_cmd curl jq nc jail jexec ifconfig route sysctl

# aifw's pf backend shells out via /usr/local/bin/sudo (matching the
# appliance's narrow-grant model), so sudo must exist even when we're root.
[ -x /usr/local/bin/sudo ] || { echo "/usr/local/bin/sudo missing (pkg install sudo)" >&2; exit 2; }

if [ -z "$BIN_DIR" ]; then
    if [ -x "$REPO_ROOT/target/debug/aifw-api" ]; then BIN_DIR="$REPO_ROOT/target/debug"
    elif [ -x "$REPO_ROOT/target/release/aifw-api" ]; then BIN_DIR="$REPO_ROOT/target/release"
    else echo "no aifw-api binary found; build first or pass --bin-dir" >&2; exit 2
    fi
fi
for b in aifw-api aifw-daemon; do
    [ -x "$BIN_DIR/$b" ] || { echo "missing binary: $BIN_DIR/$b" >&2; exit 2; }
done

# Management interface: never lock it out. Prefer the default-route iface.
MGMT_IF="${MGMT_IF:-$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')}"
[ -n "$MGMT_IF" ] || { echo "cannot detect management interface; set MGMT_IF" >&2; exit 2; }

mkdir -p "$RESULTS_DIR" "$WORK_DIR"
: > "$RESULTS_DIR/summary.txt"
log "harness starting: bin=$BIN_DIR mgmt_if=$MGMT_IF artifacts=$RESULTS_DIR"

# ---------------------------------------------------------------- teardown

API_PID=""
DAEMON_PID=""
PF_WAS_ENABLED=0

teardown() {
    [ "$KEEP" = 1 ] && { log "--keep: leaving topology in place"; return; }
    log "teardown"
    [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    # Give services a moment to exit before yanking the network out
    sleep 1
    jail -r "$CLIENT_JAIL" 2>/dev/null
    jail -r "$SERVER_JAIL" 2>/dev/null
    for ep in "$EPAIR_C" "$EPAIR_S"; do
        [ -n "$ep" ] && ifconfig "${ep}a" destroy 2>/dev/null
    done
    # Restore pf to its pre-harness state
    $PFCTL -F all >/dev/null 2>&1
    if [ -f /usr/local/etc/aifw/pf.conf.aifw ]; then
        $PFCTL -f /usr/local/etc/aifw/pf.conf.aifw >/dev/null 2>&1
    elif [ -f /etc/pf.conf ]; then
        $PFCTL -f /etc/pf.conf >/dev/null 2>&1
    fi
    [ "$PF_WAS_ENABLED" = 0 ] && $PFCTL -d >/dev/null 2>&1
    if [ "$STOP_SERVICES" = 1 ]; then
        for svc in aifw_daemon aifw_api; do
            service "$svc" start >/dev/null 2>&1 || true
        done
    fi
}
EPAIR_C=""
EPAIR_S=""
trap teardown EXIT INT TERM

# ---------------------------------------------------------------- host prep

if [ "$STOP_SERVICES" = 1 ]; then
    log "stopping installed aifw services"
    for svc in aifw_api aifw_daemon; do
        service "$svc" stop >/dev/null 2>&1 || true
    done
    sleep 1
fi

# Refuse to fight another aifw instance (single-instance lock aside, two
# daemons applying rules to the same anchors makes results meaningless).
if pgrep -x aifw-daemon >/dev/null 2>&1 || pgrep -x aifw-api >/dev/null 2>&1; then
    echo "an aifw instance is already running; use --stop-services on a test VM" >&2
    exit 2
fi

kldload pf 2>/dev/null || true
if $PFCTL -si 2>/dev/null | grep -q '^Status: Enabled'; then
    PF_WAS_ENABLED=1
else
    $PFCTL -e >/dev/null 2>&1 || true
fi
sysctl net.inet.ip.forwarding=1 >/dev/null

# ---------------------------------------------------------------- topology

log "creating jails + epairs"
EPAIR_C=$(ifconfig epair create | sed 's/a$//')
EPAIR_S=$(ifconfig epair create | sed 's/a$//')

jail -c name="$CLIENT_JAIL" vnet persist path=/ >/dev/null
jail -c name="$SERVER_JAIL" vnet persist path=/ >/dev/null

ifconfig "${EPAIR_C}b" vnet "$CLIENT_JAIL"
ifconfig "${EPAIR_S}b" vnet "$SERVER_JAIL"

ifconfig "${EPAIR_C}a" inet "$CLIENT_NET_HOST/24" up
ifconfig "${EPAIR_S}a" inet "$SERVER_NET_HOST/24" up

jx_client ifconfig "${EPAIR_C}b" inet "$CLIENT_IP/24" up
jx_client ifconfig lo0 127.0.0.1/8 up
jx_client route -q add default "$CLIENT_NET_HOST" >/dev/null

jx_server ifconfig "${EPAIR_S}b" inet "$SERVER_IP/24" up
jx_server ifconfig lo0 127.0.0.1/8 up
jx_server route -q add default "$SERVER_NET_HOST" >/dev/null

# ---------------------------------------------------------------- pf.conf

# Mirrors the anchor layout aifw-setup generates for the appliance
# (generate_pf_conf in aifw-setup/src/apply.rs), scoped to the test path:
# management is passed unconditionally BEFORE the anchors so no test rule
# can cut off SSH/CI; the epair test path is default-deny after them.
PF_CONF="$WORK_DIR/pf.conf"
cat > "$PF_CONF" <<EOF
# AiFw functional-test pf.conf (harness-generated)
set skip on lo0
set block-policy drop

scrub in all

nat-anchor "aifw"
nat-anchor "aifw-nat"
rdr-anchor "aifw-nat"
nat-anchor "aifw-vpn"

pass quick on $MGMT_IF keep state
anchor "aifw-pbr"
anchor "aifw-mwan-leak"
anchor "aifw-mwan-reply"
anchor "aifw"
anchor "aifw-nat"
anchor "aifw-ratelimit"
anchor "aifw-vpn"
anchor "aifw-geoip"
anchor "aifw-tls"
anchor "aifw-ha"

pass keep state
block in log on { ${EPAIR_C}a ${EPAIR_S}a }
EOF
# Note rule order above: pf is last-match-wins for non-quick rules, so the
# trailing `block in` default-denies INBOUND on the epair test path while
# the earlier `pass` keeps outbound forwarding and host traffic working —
# mirroring the appliance's Standard policy (block in / pass out). `quick`
# rules in the anchors override both.

$PFCTL -nf "$PF_CONF" || { log "harness pf.conf rejected by pfctl"; exit 2; }
$PFCTL -f "$PF_CONF" || { log "harness pf.conf failed to load"; exit 2; }
cp "$PF_CONF" "$RESULTS_DIR/pf.conf"

# ---------------------------------------------------------------- services

log "starting aifw-api + aifw-daemon (db in $WORK_DIR)"
DB="$WORK_DIR/aifw.db"
rm -f "$DB"

AIFW_JWT_SECRET=functest-secret "$BIN_DIR/aifw-api" \
    --db "$DB" --listen "127.0.0.1:$API_PORT" --no-tls \
    > "$RESULTS_DIR/aifw-api.log" 2>&1 &
API_PID=$!

wait_for_port 127.0.0.1 "$API_PORT" 30 || {
    log "aifw-api did not come up (see aifw-api.log)"
    exit 2
}

# AIFW_NO_PF_AUTO_HEAL: on an appliance-provisioned VM the daemon's drift
# auto-heal would reload pf.conf.aifw over the harness pf.conf.
AIFW_NO_PF_AUTO_HEAL=1 "$BIN_DIR/aifw-daemon" --db "$DB" > "$RESULTS_DIR/aifw-daemon.log" 2>&1 &
DAEMON_PID=$!
sleep 2
kill -0 "$DAEMON_PID" 2>/dev/null || {
    log "aifw-daemon exited early (see aifw-daemon.log)"
    exit 2
}

api_login || exit 2
log "API up, authenticated"

# ---------------------------------------------------------------- run tests

TESTS="${TESTS:-t01-pfctl-acceptance t02-pass-block t03-schedule-gating t04-nat t05-restore-roundtrip t06-wireguard t07-ipsec}"
TOTAL=0
FAILED_TESTS=""

for t in $TESTS; do
    TOTAL=$((TOTAL + 1))
    log "=== $t ==="
    FAILURES=0
    # shellcheck disable=SC1090
    if ( . "$SCRIPT_DIR/$t.sh" ) > "$RESULTS_DIR/$t.log" 2>&1; then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" = 0 ]; then
        log "=== $t OK ==="
        echo "PASS $t" >> "$RESULTS_DIR/summary.txt"
    elif [ "$rc" = 3 ]; then
        log "=== $t SKIPPED ==="
        echo "SKIP $t" >> "$RESULTS_DIR/summary.txt"
    else
        log "=== $t FAILED (see $t.log) ==="
        echo "FAIL $t" >> "$RESULTS_DIR/summary.txt"
        FAILED_TESTS="$FAILED_TESTS $t"
    fi
done

save_pf_artifacts final

log "---------------------------------------------"
cat "$RESULTS_DIR/summary.txt"
if [ -n "$FAILED_TESTS" ]; then
    log "FAILED:$FAILED_TESTS"
    exit 1
fi
log "all tests passed"
exit 0
