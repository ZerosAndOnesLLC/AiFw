# shellcheck shell=sh
# T07 — IPsec (#530) on the real kernel: create an IKEv2 tunnel through the
# API and verify the swanctl conf is rendered root-only, charon loads the
# conn (IKEv2 / TUNNEL / correct traffic selectors), the live-status
# endpoint reports real charon state, the IKE/ESP/enc0 pass rules land in
# the aifw-vpn anchor, and delete unloads + removes everything. Skips
# (rc 3) when strongSwan isn't installed. Peer handshake + encrypted
# traffic needs a charon peer in a jail — covered by the manual two-box
# matrix (#530 Phase 6); this test gates the single-host contract.

if ! command -v swanctl >/dev/null 2>&1; then
    echo "strongswan not installed; skipping"
    exit 3
fi
service strongswan onestatus >/dev/null 2>&1 || service strongswan onestart >/dev/null 2>&1 || true
swanctl --version >/dev/null 2>&1 || { echo "charon/vici unavailable; skipping"; exit 3; }

CONF_DIR=/usr/local/etc/swanctl/conf.d

TUN=$(api POST /api/v1/vpn/ipsec/tunnels '{
  "name": "t07-tunnel",
  "remote_addr": "203.0.113.77",
  "local_ts": ["10.99.7.0/24"],
  "remote_ts": ["10.98.7.0/24"],
  "psk": "t07-functional-harness-psk",
  "start_action": "none"
}') || fail "create tunnel"
TUN_ID=$(printf '%s' "$TUN" | jq -r '.data.id')
[ -n "$TUN_ID" ] && [ "$TUN_ID" != null ] || fail "tunnel id missing from create response"

# Secrets must never leave the API
printf '%s' "$TUN" | jq -e '.data.psk == "REDACTED"' >/dev/null || fail "PSK not redacted in create response"

# Rendered conf: present, root-owned, mode 600 (contains the PSK)
CONF="$CONF_DIR/aifw-$TUN_ID.conf"
[ -f "$CONF" ] || fail "swanctl conf not rendered at $CONF"
PERMS=$(stat -f '%Lp %Su' "$CONF" 2>/dev/null)
[ "$PERMS" = "600 root" ] || fail "conf perms/owner wrong: $PERMS (want 600 root)"

# charon actually loaded the conn with the right shape
swanctl --list-conns > "$RESULTS_DIR/t07-list-conns.txt" 2>&1 || fail "swanctl --list-conns"
grep -q "aifw-$TUN_ID: IKEv2" "$RESULTS_DIR/t07-list-conns.txt" || fail "conn not loaded as IKEv2"
grep -q "aifw-$TUN_ID-1: TUNNEL" "$RESULTS_DIR/t07-list-conns.txt" || fail "child not TUNNEL mode"
grep -q "10.99.7.0/24" "$RESULTS_DIR/t07-list-conns.txt" || fail "local TS missing from loaded conn"

# Live status comes from charon, not the DB — no SA yet means DOWN
STATUS=$(api GET "/api/v1/vpn/ipsec/tunnels/$TUN_ID/status") || fail "status endpoint"
printf '%s' "$STATUS" | jq -e '.data.ike_state == "DOWN"' >/dev/null || fail "expected DOWN, got: $STATUS"
swanctl --list-sas --raw > "$RESULTS_DIR/t07-list-sas-raw.txt" 2>&1 || true

# pf: IKE/ESP/enc0 pass rules in the aifw-vpn anchor
api_reload || fail "reload"
pfctl_anchor_rules aifw-vpn > "$RESULTS_DIR/t07-vpn-anchor.txt" 2>&1 || true
grep -q "proto esp" "$RESULTS_DIR/t07-vpn-anchor.txt" || fail "ESP pass rule missing from aifw-vpn anchor"
# pfctl renders `port { 500 4500 }` as the service names isakmp / ipsec-nat-t
grep -q "isakmp" "$RESULTS_DIR/t07-vpn-anchor.txt" || fail "IKE (500/isakmp) rule missing from aifw-vpn anchor"
grep -q "ipsec-nat-t" "$RESULTS_DIR/t07-vpn-anchor.txt" || fail "NAT-T (4500) rule missing from aifw-vpn anchor"
grep -q "enc0" "$RESULTS_DIR/t07-vpn-anchor.txt" || fail "enc0 pass rule missing from aifw-vpn anchor"

# Legacy surface: creating pre-#530 SA records is gone
LEGACY_CODE=$(api_status POST /api/v1/vpn/ipsec '{"name":"t07-legacy","local_addr":"1.2.3.4","remote_addr":"5.6.7.8","protocol":"esp","mode":"tunnel"}')
[ "$LEGACY_CODE" = "410" ] || fail "legacy SA POST should be 410 Gone, got $LEGACY_CODE"

# Delete: conf removed, conn unloaded
api DELETE "/api/v1/vpn/ipsec/tunnels/$TUN_ID" >/dev/null || fail "delete tunnel"
[ ! -f "$CONF" ] || fail "conf file survived delete"
swanctl --list-conns 2>/dev/null | grep -q "aifw-$TUN_ID" && fail "conn still loaded after delete"

[ "$FAILURES" = 0 ] || exit 1
exit 0
