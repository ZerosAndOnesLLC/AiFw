# shellcheck shell=sh
# T03 — schedule gating (#537) against the real pf: a rule inside its window
# is loaded and passes packets; a rule outside its window is not compiled
# and packets stay blocked.

PORT=8081

# Always-active window: 00:00-00:00 = full day, all days.
ALWAYS=$(api POST /api/v1/schedules '{"name":"t03-always","time_ranges":"00:00-00:00","days_of_week":"mon,tue,wed,thu,fri,sat,sun"}' | jq -r '.data.id') || fail "create always schedule"

# Closed window: a one-minute range starting two hours from now (local time,
# same evaluation the engine uses), so it is deterministically inactive.
H=$(date +%H)
H=${H#0} # strip leading zero — POSIX $(( )) reads "08"/"09" as bad octal
CLOSED_H=$(( (H + 2) % 24 ))
CLOSED_RANGE=$(printf '%02d:00-%02d:01' "$CLOSED_H" "$CLOSED_H")
CLOSED=$(api POST /api/v1/schedules "{\"name\":\"t03-closed\",\"time_ranges\":\"$CLOSED_RANGE\",\"days_of_week\":\"mon,tue,wed,thu,fri,sat,sun\"}" | jq -r '.data.id') || fail "create closed schedule"
note "closed window: $CLOSED_RANGE"

OPEN_RULE=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"schedule_id":"'"$ALWAYS"'","label":"t03-open"}') || fail "create open rule"
GATED_RULE=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":8085,"dst_port_end":8085,"schedule_id":"'"$CLOSED"'","label":"t03-gated"}') || fail "create gated rule"
api_reload || fail "reload"

rules=$(pfctl_anchor_rules aifw)
printf '%s\n' "$rules" > "$RESULTS_DIR/t03-anchor.txt"
printf '%s\n' "$rules" | grep -q 't03-open' || fail "in-window rule missing from pf anchor"
printf '%s\n' "$rules" | grep -q 't03-gated' && fail "out-of-window rule was compiled into pf"

# Packet-level: the open rule passes, the gated port stays default-denied
client_can_reach "$SERVER_IP" $PORT || { server_listen_once $PORT /tmp/aifwfx-t03; client_can_reach "$SERVER_IP" $PORT || fail "in-window rule does not pass traffic"; }
client_can_reach "$SERVER_IP" 8085 && fail "out-of-window port is reachable"

# Cleanup
api DELETE "/api/v1/rules/$OPEN_RULE" >/dev/null || fail "delete open"
api DELETE "/api/v1/rules/$GATED_RULE" >/dev/null || fail "delete gated"
api DELETE "/api/v1/schedules/$ALWAYS" >/dev/null || fail "delete always"
api DELETE "/api/v1/schedules/$CLOSED" >/dev/null || fail "delete closed"
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
