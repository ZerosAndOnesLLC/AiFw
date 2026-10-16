# shellcheck shell=sh
# T11 — plugins on real pf. The Threat Intel Feeds plugin renders
# `block … quick from <plugin_threat_feeds>` into the `aifw-plugins`
# anchor, which pf.conf hooks before every other filter anchor. Two things
# only a real kernel can prove:
#   1. pf accepts the rendered rules in that anchor while the table lives
#      at the root (`pfctl -t … -T replace`), i.e. the anchor rule resolves
#      the root table (pfr_attach_table fallback, see security-review M7);
#   2. a plugin block wins over an operator `pass` in `aifw`, and disabling
#      the plugin removes the rules and empties the table so the path
#      reopens.
# The plugin downloads its default feeds in the background right after it
# starts (the CI VM has internet). Every refresh ends with `-T replace`, so
# the test waits for that first refresh to finish before seeding the table
# by hand — the seed bypasses the plugin's private-range filter on purpose.

PORT=8086
MARKER=/tmp/aifwfx-t11-marker
TABLE=plugin_threat_feeds
ANCHOR=aifw-plugins

plugin_state() { api GET /api/v1/plugins/threat-feeds | jq -r '.state'; }

wait_for_state() { # $1 = state, $2 = seconds
    _i=0
    while [ "$_i" -lt "$2" ]; do
        [ "$(plugin_state)" = "$1" ] && return 0
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

# 0. Baseline: the anchor is empty and the operator pass rule opens the path.
[ -z "$(pfctl_anchor_rules $ANCHOR)" ] || fail "anchor $ANCHOR not empty before the test"
PASS_ID=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"label":"t11-pass"}') || fail "create pass"
api_reload || fail "reload pass"
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT || fail "baseline: pass rule did not open the path"

# 1. Enable the plugin with its defaults. start() loads whatever the KV
#    store holds (nothing yet) into the table, then the rules.
api PUT /api/v1/plugins/threat-feeds/enabled '{"enabled":true}' >/dev/null || fail "enable threat-feeds"
wait_for_state running 10 || fail "plugin did not reach 'running': $(api GET /api/v1/plugins/threat-feeds | jq -c '{state,last_error}')"

# Wait for the first refresh to settle so a late `-T replace` can't wipe
# the seed below. A failed download still ends in a replace.
_i=0
while [ "$_i" -lt 90 ]; do
    STATUS=$(api GET /api/v1/plugins/threat-feeds/status)
    if printf '%s' "$STATUS" | jq -e '.refreshing == false and .last_applied != null and all(.feeds[]; .last_attempt != null)' >/dev/null 2>&1; then
        break
    fi
    sleep 1
    _i=$((_i + 1))
done
[ "$_i" -lt 90 ] || fail "first feed refresh did not finish within 90s: $(printf '%s' "$STATUS" | jq -c '{refreshing,last_applied}')"
note "feeds after first refresh: $(printf '%s' "$STATUS" | jq -c '[.feeds[] | {name, entries, last_error}]')"
note "table entries (plugin view): $(printf '%s' "$STATUS" | jq -r '.pf_table_entries')"

RULES=$(pfctl_anchor_rules $ANCHOR)
note "anchor rules:"; printf '%s\n' "$RULES" | sed 's/^/      /'
N=$(printf '%s\n' "$RULES" | grep -c "<$TABLE>")
[ "$N" = 3 ] || fail "expected 3 rules referencing <$TABLE> in $ANCHOR, got $N"
$PFCTL -sT 2>/dev/null | grep -qx "$TABLE" || fail "root table $TABLE does not exist"
# The anchor's view of the table: with the fallback in place pf shows a
# copy flagged 'r' (referenced) pointing at the root table.
$PFCTL -vvsT > "$RESULTS_DIR/t11-tables.txt" 2>&1 || true
grep -A2 "$TABLE" "$RESULTS_DIR/t11-tables.txt" | sed 's/^/      /' || true

# 2. Seed the table with the client jail and prove the block beats the pass.
$PFCTL -t "$TABLE" -T add "$CLIENT_IP" >/dev/null 2>&1 || fail "could not add $CLIENT_IP to $TABLE"
$PFCTL -t "$TABLE" -T test "$CLIENT_IP" >/dev/null 2>&1 || fail "$CLIENT_IP not found in $TABLE after add"
$PFCTL -k "$CLIENT_IP" >/dev/null 2>&1 || true
server_listen_once $PORT $MARKER
if client_can_reach "$SERVER_IP" $PORT; then
    fail "plugin block did not win over the operator pass rule"
    # Diagnostics: root vs anchor table views, rule counters, states.
    {
        echo "--- pfctl -a $ANCHOR -vvsr"; $PFCTL -a "$ANCHOR" -vvsr
        echo "--- pfctl -a $ANCHOR -vvsT"; $PFCTL -a "$ANCHOR" -vvsT
        echo "--- pfctl -vvsT"; $PFCTL -vvsT
        echo "--- root -T show"; $PFCTL -t "$TABLE" -T show
        echo "--- anchor -T show"; $PFCTL -a "$ANCHOR" -t "$TABLE" -T show
        echo "--- states"; $PFCTL -ss | grep "$CLIENT_IP"
    } > "$RESULTS_DIR/t11-diag.txt" 2>&1
    sed 's/^/      /' "$RESULTS_DIR/t11-diag.txt"
fi

# 3. The lookup action agrees (the address is allow-listed by nobody and
#    was added by hand, so it is not 'listed_in' any feed — only pf knows).
api POST /api/v1/plugins/threat-feeds/actions/lookup '{"ip":"'"$CLIENT_IP"'"}' >/dev/null || fail "lookup action"

save_pf_artifacts t11

# 4. Disable: rules gone, table empty, path open again.
api PUT /api/v1/plugins/threat-feeds/enabled '{"enabled":false}' >/dev/null || fail "disable threat-feeds"
wait_for_state stopped 10 || fail "plugin did not stop"
[ -z "$(pfctl_anchor_rules $ANCHOR)" ] || fail "anchor $ANCHOR still has rules after disable"
LEFT=$($PFCTL -t "$TABLE" -T show 2>/dev/null | wc -l | tr -d ' ')
[ "$LEFT" = 0 ] || fail "$TABLE still holds $LEFT entries after disable"
$PFCTL -k "$CLIENT_IP" >/dev/null 2>&1 || true
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT || fail "path did not reopen after disabling the plugin"

api DELETE "/api/v1/rules/$PASS_ID" >/dev/null || fail "delete pass"
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
