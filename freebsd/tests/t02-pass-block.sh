# shellcheck shell=sh
# T02 — live packets: default-deny on the test path, explicit pass opens it,
# explicit block (higher precedence) closes it again.

PORT=8080
MARKER=/tmp/aifwfx-t02-marker

# 1. Baseline: nothing in the anchor passes client->server, harness pf.conf
#    default-denies the epair path.
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT && fail "default-deny: client reached server with no pass rule"

# 2. Pass rule opens the path
PASS_ID=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"label":"t02-pass"}') || fail "create pass"
api_reload || fail "reload pass"
server_listen_once $PORT $MARKER
if client_can_reach "$SERVER_IP" $PORT; then
    wait_for_file server $MARKER 5 || fail "connect succeeded but server never saw it"
else
    fail "pass rule: client still cannot reach server"
fi

# 3. Block rule with higher precedence (lower priority number) wins.
#    Re-arm the listener first: the one-shot nc exits after each accepted
#    connection, and without a listener a "refused" reply is
#    indistinguishable from "blocked".
BLOCK_ID=$(add_rule '{"action":"block","direction":"in","protocol":"tcp","src_addr":"'"$CLIENT_IP"'","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"priority":10,"label":"t02-block"}') || fail "create block"
api_reload || fail "reload block"
# Established states outlive rule changes by design; flush test-path states
/sbin/pfctl -k "$CLIENT_IP" >/dev/null 2>&1 || true
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT && fail "block rule: client can still reach server"

# 4. Remove the block, path opens again
api DELETE "/api/v1/rules/$BLOCK_ID" >/dev/null || fail "delete block"
api_reload || fail "reload unblock"
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT || fail "after removing block, path did not reopen"

save_pf_artifacts t02
api DELETE "/api/v1/rules/$PASS_ID" >/dev/null || fail "delete pass"
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
