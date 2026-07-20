# shellcheck shell=sh
# T04 — NAT with return traffic: outbound source NAT (client subnet
# masqueraded to the host's server-side address) and a port forward (rdr on
# the client-side interface into the server jail).

# --- outbound SNAT -------------------------------------------------
PORT=8082
api POST /api/v1/nat '{"nat_type":"snat","interface":"'"${EPAIR_S}a"'","protocol":"tcp","src_addr":"10.99.1.0/24","redirect_addr":"'"$SERVER_NET_HOST"'","label":"t04-snat"}' >/dev/null || fail "create snat"
PASS_ID=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"label":"t04-pass"}') || fail "create pass"
api_reload || fail "reload snat"

pfctl -a aifw-nat -sn > "$RESULTS_DIR/t04-nat-anchor.txt" 2>&1
grep -q 't04\|10.99.1.0/24' "$RESULTS_DIR/t04-nat-anchor.txt" || fail "snat rule not in aifw-nat anchor"

MARKER=/tmp/aifwfx-t04-marker
server_listen_once $PORT $MARKER
if client_can_reach "$SERVER_IP" $PORT; then
    wait_for_file server $MARKER 5 || fail "snat: server never saw the connection"
    # The pf state table is authoritative for the translation: the client's
    # connection must appear translated to the host's server-side address.
    /sbin/pfctl -ss > "$RESULTS_DIR/t04-states.txt" 2>&1
    grep "$SERVER_IP:$PORT" "$RESULTS_DIR/t04-states.txt" | grep -q "$SERVER_NET_HOST" \
        || fail "snat: no state shows translation to $SERVER_NET_HOST"
else
    fail "snat: client cannot reach server at all"
fi

# --- port forward (rdr) --------------------------------------------
FWD_PORT=8083
DEST_PORT=8084
api POST /api/v1/nat '{"nat_type":"dnat","interface":"'"${EPAIR_C}a"'","protocol":"tcp","dst_addr":"'"$CLIENT_NET_HOST"'","dst_port_start":'$FWD_PORT',"dst_port_end":'$FWD_PORT',"redirect_addr":"'"$SERVER_IP"'","redirect_port_start":'$DEST_PORT',"redirect_port_end":'$DEST_PORT',"label":"t04-rdr"}' >/dev/null || fail "create rdr"
PASS2_ID=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$DEST_PORT',"dst_port_end":'$DEST_PORT',"label":"t04-pass-fwd"}') || fail "create fwd pass"
api_reload || fail "reload rdr"

MARKER2=/tmp/aifwfx-t04-rdr-marker
server_listen_once $DEST_PORT $MARKER2
if client_can_reach "$CLIENT_NET_HOST" $FWD_PORT; then
    wait_for_file server $MARKER2 5 || fail "rdr: connected to host port but server jail never saw it"
else
    fail "rdr: client cannot connect to forwarded port"
fi

save_pf_artifacts t04

# Cleanup: NAT rules + pass rules
for id in $(api GET /api/v1/nat | jq -r '.data[] | select(.label != null and (.label | startswith("t04-"))) | .id'); do
    api DELETE "/api/v1/nat/$id" >/dev/null || fail "delete nat $id"
done
api DELETE "/api/v1/rules/$PASS_ID" >/dev/null || fail "delete pass"
api DELETE "/api/v1/rules/$PASS2_ID" >/dev/null || fail "delete fwd pass"
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
