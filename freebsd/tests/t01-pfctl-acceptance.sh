# shellcheck shell=sh
# T01 — the real pf parser accepts everything the rule engine renders.
# Creates a battery of diverse rules through the API, applies, and verifies
# pfctl loaded every one of them into the anchor. Catches the entire class
# of "rendered text that pf rejects" bugs the mock backend can't see.

count_before=$(pfctl_anchor_rules aifw | grep -c .)

# label => request-json battery. Diversity over volume: each entry exercises
# a different renderer path (actions, ports, ranges, invert, families,
# state options, logging).
add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":80,"dst_port_end":80,"label":"t01-pass-tcp"}' >/dev/null || fail "create pass-tcp"
add_rule '{"action":"block","direction":"in","protocol":"udp","src_addr":"'"$CLIENT_IP"'","dst_port_start":53,"dst_port_end":53,"label":"t01-block-udp"}' >/dev/null || fail "create block-udp"
add_rule '{"action":"block_drop","direction":"any","protocol":"any","src_addr":"192.0.2.0/24","label":"t01-drop-net"}' >/dev/null || fail "create drop-net"
add_rule '{"action":"block_return","direction":"in","protocol":"tcp","dst_port_start":8000,"dst_port_end":9000,"label":"t01-return-range"}' >/dev/null || fail "create return-range"
add_rule '{"action":"pass","direction":"out","protocol":"icmp","label":"t01-icmp-out"}' >/dev/null || fail "create icmp-out"
add_rule '{"action":"pass","direction":"in","protocol":"tcp","ip_version":"inet6","dst_port_start":443,"dst_port_end":443,"label":"t01-v6-https"}' >/dev/null || fail "create v6"
add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_port_start":22,"dst_port_end":22,"state_tracking":"synproxy_state","label":"t01-synproxy"}' >/dev/null || fail "create synproxy"
add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_port_start":25,"dst_port_end":25,"state_tracking":"modulate_state","log":true,"label":"t01-modulate-log"}' >/dev/null || fail "create modulate"
add_rule '{"action":"pass","direction":"in","protocol":"udp","dst_port_start":5000,"dst_port_end":5010,"quick":false,"label":"t01-noquick"}' >/dev/null || fail "create noquick"
EXPECTED=9

api_reload || fail "reload"

rules=$(pfctl_anchor_rules aifw)
loaded=$(printf '%s\n' "$rules" | grep -c 't01-')
note "anchor holds $loaded/$EXPECTED battery rules (pre-existing: $count_before)"
printf '%s\n' "$rules" > "$RESULTS_DIR/t01-anchor.txt"

[ "$loaded" = "$EXPECTED" ] || fail "expected $EXPECTED t01 rules in pf anchor, found $loaded"

# The API log must not contain load errors for this apply
grep -i 'pfctl.*error\|failed to load' "$RESULTS_DIR/aifw-api.log" >/dev/null 2>&1 \
    && fail "aifw-api.log reports pf load errors"

# Cleanup battery so later tests see a clean anchor
for id in $(api GET /api/v1/rules | jq -r '.data[] | select(.label != null and (.label | startswith("t01-"))) | .id'); do
    api DELETE "/api/v1/rules/$id" >/dev/null || fail "delete $id"
done
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
