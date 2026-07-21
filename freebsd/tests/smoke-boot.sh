#!/bin/sh
# Appliance boot smoke test (#533 Phase 2). Runs on a LINUX host with qemu.
#
# Boots the built USB IMG unmodified under qemu (KVM when available), with a
# small seed ISO attached as a CD — aifw_firstboot finds aifw-seed.json on
# the media and runs unattended setup. Asserts that:
#   1. the image boots and first-boot setup completes on its own;
#   2. the API answers on the LAN side and the seeded admin can log in
#      (one real packet path: host -> slirp -> vtnet1 -> pf -> aifw-api);
#   3. the same port is NOT reachable from the WAN side (default-deny).
#
# Usage: smoke-boot.sh --img PATH [--artifacts DIR] [--timeout SECS]
# Requires: qemu-system-x86_64, genisoimage (or mkisofs), curl, jq

set -u

IMG=""
RESULTS_DIR="/tmp/aifw-smoke-artifacts"
TIMEOUT=600
while [ $# -gt 0 ]; do
    case "$1" in
        --img)       IMG="$2"; shift 2 ;;
        --artifacts) RESULTS_DIR="$2"; shift 2 ;;
        --timeout)   TIMEOUT="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done
[ -n "$IMG" ] && [ -f "$IMG" ] || { echo "usage: smoke-boot.sh --img PATH" >&2; exit 2; }

for c in qemu-system-x86_64 curl jq ssh ssh-keygen; do
    command -v "$c" >/dev/null 2>&1 || { echo "missing: $c" >&2; exit 2; }
done
MKISO=""
for c in genisoimage mkisofs xorrisofs; do
    command -v "$c" >/dev/null 2>&1 && { MKISO="$c"; break; }
done
[ -n "$MKISO" ] || { echo "missing genisoimage/mkisofs/xorrisofs" >&2; exit 2; }

WORK=$(mktemp -d)
mkdir -p "$RESULTS_DIR"
log() { printf '%s %s\n' "$(date -u '+%H:%M:%S')" "$*"; }

ADMIN_USER="admin"
ADMIN_PASS="SmokeTest123"
LAN_PORT=18443   # host port forwarded to the appliance LAN address
WAN_PORT=18081   # host port forwarded to the appliance WAN address (must stay blocked)
SSH_PORT=18422   # root SSH on the LAN side, used for reboot persistence

# ---------------------------------------------------------------- seed ISO

ssh-keygen -q -t ed25519 -N '' -f "$WORK/id_ed25519" \
    || { echo "ephemeral SSH key generation failed" >&2; exit 2; }
SSH_PUB=$(cat "$WORK/id_ed25519.pub")

cat > "$WORK/aifw-seed.json" <<EOF
{
  "hostname": "aifw-smoke",
  "wan_interface": "vtnet0",
  "wan_mode": "dhcp",
  "wan_ip": null,
  "wan_gateway": null,
  "lan_interface": "vtnet1",
  "lan_ip": "192.168.1.1/24",
  "admin_username": "$ADMIN_USER",
  "admin_password": "$ADMIN_PASS",
  "admin_password_hash": "",
  "root_password": null,
  "totp_secret": "",
  "totp_enabled": false,
  "recovery_codes": [],
  "api_listen": "0.0.0.0",
  "api_port": 8080,
  "ui_enabled": true,
  "dns_servers": ["9.9.9.9"],
  "dhcp_enabled": false,
  "default_policy": "standard",
  "nat_enabled": true,
  "ssh_auth_method": "keys",
  "ssh_github_user": null,
  "ssh_authorized_keys": ["$SSH_PUB"],
  "db_path": "/var/db/aifw/aifw.db",
  "config_dir": "/usr/local/etc/aifw"
}
EOF
mkdir -p "$WORK/seedroot"
cp "$WORK/aifw-seed.json" "$WORK/seedroot/"
"$MKISO" -quiet -o "$WORK/seed.iso" -V AIFWSEED -R -J "$WORK/seedroot" \
    || { echo "seed iso build failed" >&2; exit 2; }

# ---------------------------------------------------------------- boot

ACCEL="tcg"
[ -w /dev/kvm ] && ACCEL="kvm"
log "booting $IMG (accel=$ACCEL, timeout=${TIMEOUT}s)"

qemu-system-x86_64 \
    -machine q35,accel=$ACCEL \
    -cpu max -m 2048 -smp 2 \
    -drive "file=$IMG,format=raw,if=virtio" \
    -cdrom "$WORK/seed.iso" \
    -netdev "user,id=wan,hostfwd=tcp:127.0.0.1:$WAN_PORT-:8080" \
    -device virtio-net-pci,netdev=wan \
    -netdev "user,id=lan,net=192.168.1.0/24,hostfwd=tcp:127.0.0.1:$LAN_PORT-192.168.1.1:8080,hostfwd=tcp:127.0.0.1:$SSH_PORT-192.168.1.1:22" \
    -device virtio-net-pci,netdev=lan \
    -display none \
    -serial "file:$RESULTS_DIR/serial.log" \
    -pidfile "$WORK/qemu.pid" \
    -daemonize \
    || { echo "qemu failed to start" >&2; exit 2; }

cleanup() {
    if [ -f "$WORK/qemu.pid" ]; then
        kill "$(cat "$WORK/qemu.pid")" 2>/dev/null
    fi
    cp "$WORK/aifw-seed.json" "$RESULTS_DIR/" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- poll

# First boot does real work (service user, DB init, cert generation, pf
# load, service starts) — poll the LAN-side login until it answers.
login_body="{\"username\":\"$ADMIN_USER\",\"password\":\"$ADMIN_PASS\"}"
TOKEN=""
elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
    for scheme in https http; do
        resp=$(curl -k -s -m 5 -X POST "$scheme://127.0.0.1:$LAN_PORT/api/v1/auth/login" \
            -H 'Content-Type: application/json' -d "$login_body" 2>/dev/null) || continue
        TOKEN=$(printf '%s' "$resp" | jq -r '.tokens.access_token // empty' 2>/dev/null)
        if [ -n "$TOKEN" ]; then
            SCHEME="$scheme"
            break 2
        fi
    done
    sleep 5
    elapsed=$((elapsed + 5))
done

if [ -z "$TOKEN" ]; then
    log "FAIL: appliance API never became reachable/loginable within ${TIMEOUT}s"
    tail -50 "$RESULTS_DIR/serial.log" 2>/dev/null
    exit 1
fi
log "first boot complete after ~${elapsed}s; admin login OK via LAN ($SCHEME)"

# Exercise the unauthenticated boundary and the shipped static UI before
# relying on the authenticated status response below.
invalid=$(curl -k -s -m 10 -o /dev/null -w '%{http_code}' \
    -X POST "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/auth/login" \
    -H 'Content-Type: application/json' \
    -d '{"username":"admin","password":"definitely-wrong"}')
[ "$invalid" = 401 ] || {
    log "FAIL: invalid login returned HTTP $invalid (expected 401)"
    exit 1
}
ui=$(curl -k -s -m 10 "$SCHEME://127.0.0.1:$LAN_PORT/")
printf '%s' "$ui" | grep -q 'AiFw' || {
    log "FAIL: LAN-served UI did not contain the AiFw marker"
    exit 1
}
log "auth boundary and served UI checks OK"

# Authenticated status call — proves the API is actually serving, not just
# terminating connections.
status=$(curl -k -s -m 10 "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/status" \
    -H "Authorization: Bearer $TOKEN")
printf '%s\n' "$status" > "$RESULTS_DIR/status.json"
printf '%s' "$status" | jq -e . >/dev/null 2>&1 || {
    log "FAIL: /api/v1/status did not return JSON: $status"
    exit 1
}
printf '%s' "$status" | jq -e '.pf_running == true and (.aifw_rules | type == "number") and (.nat_rules | type == "number")' >/dev/null 2>&1 || {
    log "FAIL: status response did not report live PF/rule counters: $status"
    exit 1
}
log "status endpoint OK"

# Create a distinctive rule, reboot the real appliance, and prove both the DB
# record and live PF anchor recover. This catches boot ordering and disabled-PF
# regressions that an API-only restart cannot expose.
rule=$(curl -k -s -m 15 -X POST \
    "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/rules" \
    -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
    -d '{"action":"block","direction":"in","protocol":"tcp","src_addr":"203.0.113.77","dst_addr":"192.0.2.77","dst_port_start":65530,"dst_port_end":65530,"label":"smoke-reboot-persist"}')
RULE_ID=$(printf '%s' "$rule" | jq -r '.data.id // empty')
[ -n "$RULE_ID" ] || {
    log "FAIL: could not create reboot-persistence rule: $rule"
    exit 1
}
curl -k -s -m 30 -X POST "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/reload" \
    -H "Authorization: Bearer $TOKEN" >/dev/null || {
    log "FAIL: reload before reboot failed"
    exit 1
}

SSH="ssh -i $WORK/id_ed25519 -p $SSH_PORT -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
ssh_elapsed=0
while [ "$ssh_elapsed" -lt 60 ]; do
    # shellcheck disable=SC2086
    $SSH root@127.0.0.1 true >/dev/null 2>&1 && break
    sleep 2
    ssh_elapsed=$((ssh_elapsed + 2))
done
[ "$ssh_elapsed" -lt 60 ] || { log "FAIL: appliance SSH never became reachable"; exit 1; }

log "requesting appliance reboot"
# A successful reboot normally drops the SSH transport before it can return.
# shellcheck disable=SC2086
$SSH root@127.0.0.1 /sbin/shutdown -r now >/dev/null 2>&1 || true
sleep 10

TOKEN=""
elapsed=0
while [ "$elapsed" -lt "$TIMEOUT" ]; do
    resp=$(curl -k -s -m 5 -X POST "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/auth/login" \
        -H 'Content-Type: application/json' -d "$login_body" 2>/dev/null) || true
    TOKEN=$(printf '%s' "$resp" | jq -r '.tokens.access_token // empty' 2>/dev/null)
    [ -n "$TOKEN" ] && break
    sleep 5
    elapsed=$((elapsed + 5))
done
[ -n "$TOKEN" ] || { log "FAIL: API did not recover after reboot"; exit 1; }

post_status=$(curl -k -s -m 10 "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/status" \
    -H "Authorization: Bearer $TOKEN")
printf '%s' "$post_status" | jq -e '.pf_running == true' >/dev/null 2>&1 || {
    log "FAIL: post-reboot status reports PF is not running: $post_status"
    exit 1
}
post_rules=$(curl -k -s -m 10 "$SCHEME://127.0.0.1:$LAN_PORT/api/v1/rules" \
    -H "Authorization: Bearer $TOKEN")
printf '%s' "$post_rules" | jq -e --arg id "$RULE_ID" '.data[] | select(.id == $id and .label == "smoke-reboot-persist")' >/dev/null 2>&1 || {
    log "FAIL: persisted rule missing from API after reboot: $post_rules"
    exit 1
}
# shellcheck disable=SC2086
$SSH root@127.0.0.1 "pfctl -a aifw -sr" 2>/dev/null | grep -q 'smoke-reboot-persist' || {
    log "FAIL: persisted rule missing from live PF anchor after reboot"
    exit 1
}
log "reboot recovery OK; PF enabled and persisted rule live"

# Default-deny on WAN: the management API port via the WAN interface must
# NOT answer — the seed configures a LAN, so generate_pf_conf scopes the
# SSH/API pass rules to it (#560). A reachable WAN-side API means that
# scoping regressed.
if curl -k -s -m 8 "$SCHEME://127.0.0.1:$WAN_PORT/api/v1/status" >/dev/null 2>&1; then
    log "FAIL: management API is reachable via the WAN interface — LAN scoping regressed (#560)"
    exit 1
fi
log "WAN-side default-deny OK (port $WAN_PORT unreachable)"

log "boot smoke PASSED"
exit 0
