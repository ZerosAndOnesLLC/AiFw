# shellcheck shell=sh
# T09 — cross-family translation (pf af-to, #531).
#
# NAT64: the v6-only client reaches the v4-only server through the
# well-known prefix (TCP, UDP, and ICMPv6→ICMP echo), with return traffic
# riding the pf state. NAT46: the v4 client reaches a v6 service bound to
# the RFC 6052 embedded address. Plus a negative case: the API must reject
# a wrong-family rule with 400.

# --- NAT64: v6 client -> v4 server ---------------------------------
# Translation source is the host's server-leg v4 address, so the server
# jail routes replies straight back to the firewall.
api POST /api/v1/nat '{"nat_type":"nat64","interface":"'"${EPAIR_C}a"'","protocol":"any","src_addr":"2001:db8:1::/64","dst_addr":"'"$NAT64_PREFIX"'","redirect_addr":"'"$SERVER_NET_HOST"'","label":"t09-nat64"}' >/dev/null || fail "create nat64"
api_reload || fail "reload nat64"

# The af-to rule is filter-class: it must appear in the anchor's -sr output.
pfctl -a aifw-nat -sr > "$RESULTS_DIR/t09-afto-rules.txt" 2>&1
grep -q 'af-to' "$RESULTS_DIR/t09-afto-rules.txt" || fail "af-to rule not in aifw-nat filter ruleset"

# Route the NAT64 prefix from the client jail via the firewall.
jx_client route -q add -inet6 "$NAT64_PREFIX" "$CLIENT6_NET_HOST" >/dev/null 2>&1

# TCP through the translator.
PORT=8091
MARKER=/tmp/aifwfx-t09-tcp-marker
server_listen_once $PORT $MARKER
if client_can_reach "$SERVER_IP_EMBEDDED" $PORT; then
    wait_for_file server $MARKER 5 || fail "nat64 tcp: connected but server never saw it"
else
    fail "nat64 tcp: client cannot reach $SERVER_IP_EMBEDDED:$PORT"
fi

# The state table must show the cross-family translation: the server-side
# state talks v4 to the server, sourced from the translation address.
/sbin/pfctl -ss > "$RESULTS_DIR/t09-states.txt" 2>&1
grep "$SERVER_IP:$PORT" "$RESULTS_DIR/t09-states.txt" | grep -q "$SERVER_NET_HOST" \
    || fail "nat64 tcp: no v4-side state sourced from $SERVER_NET_HOST"

# UDP through the translator.
UDP_PORT=8092
UDP_MARKER=/tmp/aifwfx-t09-udp-marker
server_listen_udp_once $UDP_PORT $UDP_MARKER
client_send_udp "$SERVER_IP_EMBEDDED" $UDP_PORT
wait_for_file server $UDP_MARKER 5 || fail "nat64 udp: server never saw the datagram"

# ICMPv6 echo -> ICMP echo (RFC 7915 translation) and the reply back.
if jx_client ping -6 -c 2 -t 5 "$SERVER_IP_EMBEDDED" > "$RESULTS_DIR/t09-ping6.txt" 2>&1; then
    :
else
    fail "nat64 icmp: ICMPv6 echo through the translator got no reply"
fi

# --- NAT46: v4 client -> v6 service --------------------------------
# The client reaches proxy v4 192.0.2.80; the translated destination is its
# RFC 6052 embedding in the /96 subnet of the translation source
# (SERVER6_NET_HOST) = 2001:db8:2::c000:250, which the server jail holds.
NAT46_V4="192.0.2.80"
NAT46_EMBEDDED="2001:db8:2::c000:250"
jx_server ifconfig "${EPAIR_S}b" inet6 -ifdisabled "$NAT46_EMBEDDED/64" alias
jx_client route -q add "$NAT46_V4" "$CLIENT_NET_HOST" >/dev/null 2>&1

api POST /api/v1/nat '{"nat_type":"nat46","interface":"'"${EPAIR_C}a"'","protocol":"tcp","src_addr":"10.99.1.0/24","dst_addr":"'"$NAT46_V4"'","redirect_addr":"'"$SERVER6_NET_HOST"'","label":"t09-nat46"}' >/dev/null || fail "create nat46"
api_reload || fail "reload nat46"

PORT46=8093
MARKER46=/tmp/aifwfx-t09-nat46-marker
# Explicit -6: plain `nc -l` binds the IPv4 wildcard only, so the translated
# IPv6 SYN would be RST'd and the test would fail with no listener at fault.
jx_server sh -c "rm -f '$MARKER46'; (nc -6 -l '$PORT46' >/dev/null 2>&1 && touch '$MARKER46') &"
if client_can_reach "$NAT46_V4" $PORT46; then
    wait_for_file server $MARKER46 5 || fail "nat46 tcp: connected but server never saw it"
else
    fail "nat46 tcp: v4 client cannot reach $NAT46_V4:$PORT46"
fi

# --- negative: wrong-family rules are rejected with a message ------
CODE=$(api_status POST /api/v1/nat '{"nat_type":"nat64","interface":"'"${EPAIR_C}a"'","protocol":"any","dst_addr":"'"$NAT64_PREFIX"'","redirect_addr":"2001:db8::1"}')
[ "$CODE" = "400" ] || fail "nat64 with IPv6 redirect must 400 (got $CODE)"

CODE=$(api_status POST /api/v1/nat '{"nat_type":"nat64","interface":"'"${EPAIR_C}a"'","protocol":"any","dst_addr":"64:ff9b::/64","redirect_addr":"'"$SERVER_NET_HOST"'"}')
[ "$CODE" = "400" ] || fail "nat64 with /64 prefix must 400 (got $CODE)"

save_pf_artifacts t09

# --- cleanup -------------------------------------------------------
for id in $(api GET /api/v1/nat | jq -r '.data[] | select(.label != null and (.label | startswith("t09-"))) | .id'); do
    api DELETE "/api/v1/nat/$id" >/dev/null || fail "delete nat $id"
done
api_reload || fail "cleanup reload"
jx_client route -q delete -inet6 "$NAT64_PREFIX" >/dev/null 2>&1
jx_client route -q delete "$NAT46_V4" >/dev/null 2>&1
jx_server ifconfig "${EPAIR_S}b" inet6 "$NAT46_EMBEDDED" -alias 2>/dev/null

[ "$FAILURES" = 0 ] || exit 1
exit 0
