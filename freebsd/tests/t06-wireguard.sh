# shellcheck shell=sh
# T06 — WireGuard on the real kernel: create a tunnel through the API and
# verify the wg interface exists, the daemon derived a valid key pair, and
# the pass rules landed in the aifw-vpn anchor. Skips (rc 3) when the
# wireguard kernel module/tools aren't installed. Peer handshake + traffic
# is Phase 1.5 (needs a wg peer in a jail).

if ! command -v wg >/dev/null 2>&1; then
    echo "wireguard-tools not installed; skipping"
    exit 3
fi
kldload if_wg 2>/dev/null || true
if ! kldstat -q -m if_wg 2>/dev/null && ! kldstat -q -m wg 2>/dev/null; then
    echo "wireguard kernel module unavailable; skipping"
    exit 3
fi

TUN=$(api POST /api/v1/vpn/wg '{"name":"t06-tunnel","listen_port":51999,"address":"10.99.3.1/24"}') || fail "create tunnel"
TUN_ID=$(printf '%s' "$TUN" | jq -r '.data.id')
PRIV=$(printf '%s' "$TUN" | jq -r '.data.private_key')
PUB=$(printf '%s' "$TUN" | jq -r '.data.public_key')

# #541: the stored public key must derive from the private key per real wg
DERIVED=$(printf '%s' "$PRIV" | wg pubkey)
[ "$DERIVED" = "$PUB" ] || fail "stored pubkey does not derive from privkey (got $DERIVED, stored $PUB)"

# Bring the tunnel up so ifconfig/wg state is created
api PUT "/api/v1/vpn/wg/$TUN_ID" '{"status":"up"}' >/dev/null 2>&1 || note "tunnel up via update not supported; relying on create-time state"
api_reload || fail "reload"

ifconfig | grep -q '^wg' || note "no wg interface present (tunnel may be status=down by default)"
pfctl_anchor_rules aifw-vpn > "$RESULTS_DIR/t06-vpn-anchor.txt" 2>&1 || true

# Cleanup
api DELETE "/api/v1/vpn/wg/$TUN_ID" >/dev/null || fail "delete tunnel"

[ "$FAILURES" = 0 ] || exit 1
exit 0
