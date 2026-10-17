# shellcheck shell=sh
# T12 — Geo-IP on real pf (#704). A tiny GeoLite2 Country CSV release is
# uploaded through the API, a block rule for its country is added, and the
# client jail (listed in that release) must be unable to reach the server
# while an operator pass rule is in place. Proves on a real kernel that:
#   1. the anchor rule references the ROOT table the engine fills (no
#      `table` line in the anchor shadowing it — the #704 defect);
#   2. uploads, rule writes and deletes all reach pf without a restart.

PORT=8087
MARKER=/tmp/aifwfx-t12-marker
ANCHOR=aifw-geoip
TABLE=geoip_aq
T12_DIR="$WORK_DIR/t12-geoip"
mkdir -p "$T12_DIR"

# Antarctica is a real ISO code nobody's traffic comes from; map the client
# jail's /24 to it. 1.2.3.0/24 proves aggregation leaves it alone.
cat > "$T12_DIR/GeoLite2-Country-Blocks-IPv4.csv" <<CSV
network,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,is_satellite_provider
${CLIENT_IP%.*}.0/24,6697173,6697173,,0,0
1.2.3.0/24,6697173,6697173,,0,0
CSV
cat > "$T12_DIR/GeoLite2-Country-Locations-en.csv" <<CSV
geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union
6697173,en,AN,Antarctica,AQ,Antarctica,0
CSV

# 0. Baseline: nothing in the geo-IP anchor; operator pass opens the path.
[ -z "$(pfctl_anchor_rules $ANCHOR)" ] || fail "anchor $ANCHOR not empty before the test"
PASS_ID=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"label":"t12-pass"}') || fail "create pass"
api_reload || fail "reload pass"
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT || fail "baseline: pass rule did not open the path"

# 1. Upload the release (CSV files, multipart).
UP=$(curl -sS -m 30 -w '\n%{http_code}' -X POST "$API_BASE/api/v1/geoip/database/upload" \
    -H "Authorization: Bearer $TOKEN" \
    -F "blocks=@$T12_DIR/GeoLite2-Country-Blocks-IPv4.csv" \
    -F "locations=@$T12_DIR/GeoLite2-Country-Locations-en.csv")
UP_CODE=$(printf '%s' "$UP" | tail -1)
UP_BODY=$(printf '%s' "$UP" | sed '$d')
[ "$UP_CODE" = 200 ] || fail "upload returned HTTP $UP_CODE: $UP_BODY"
note "upload: $(printf '%s' "$UP_BODY" | jq -c '{cidrs, loaded: .status.loaded, countries: .status.countries}')"
[ "$(printf '%s' "$UP_BODY" | jq -r '.cidrs')" = 2 ] || fail "expected 2 networks after upload"

LOOKUP=$(api GET "/api/v1/geoip/lookup/$CLIENT_IP" | jq -r '.country')
[ "$LOOKUP" = "AQ" ] || fail "lookup of $CLIENT_IP gave '$LOOKUP', expected AQ"

# 2. Block AQ. The rule write applies to pf immediately.
RULE_ID=$(api POST /api/v1/geoip '{"country_code":"AQ","action":"block","label":"t12-aq"}' | jq -r '.data.id') || fail "create geo-ip rule"
RULES=$(pfctl_anchor_rules $ANCHOR)
note "anchor rules:"; printf '%s\n' "$RULES" | sed 's/^/      /'
printf '%s\n' "$RULES" | grep -q "block drop in quick from <$TABLE>" || fail "block rule for <$TABLE> missing from $ANCHOR"
printf '%s\n' "$RULES" | grep -q "^table" && fail "anchor defines the table itself — root entries would be shadowed (#704)"
N=$($PFCTL -t "$TABLE" -T show 2>/dev/null | wc -l | tr -d ' ')
[ "$N" = 2 ] || fail "root table $TABLE holds $N entries, expected 2"
$PFCTL -t "$TABLE" -T test "$CLIENT_IP" >/dev/null 2>&1 || fail "$CLIENT_IP not in $TABLE"
VIEW=$(api GET /api/v1/geoip | jq -c '.data[] | select(.country=="AQ") | {country, cidr_count, table}')
note "rule view: $VIEW"
[ "$(printf '%s' "$VIEW" | jq -r '.cidr_count')" = 2 ] || fail "API reports wrong cidr_count: $VIEW"

pf_snapshot() { # $1 = label; root + anchor table views and the anchor rules
    {
        echo "=== $1 @ $(date -u '+%H:%M:%S.%N')"
        echo "--- root -T show"; $PFCTL -t "$TABLE" -T show
        echo "--- pfctl -vvsT (root)"; $PFCTL -vvsT
        echo "--- pfctl -a $ANCHOR -vvsT"; $PFCTL -a "$ANCHOR" -vvsT
        echo "--- pfctl -a $ANCHOR -t $TABLE -T show"; $PFCTL -a "$ANCHOR" -t "$TABLE" -T show
        echo "--- pfctl -a $ANCHOR -vvsr"; $PFCTL -a "$ANCHOR" -vvsr
    } >> "$RESULTS_DIR/t12-diag.txt" 2>&1
}
: > "$RESULTS_DIR/t12-diag.txt"
pf_snapshot before-connect
$PFCTL -k "$CLIENT_IP" >/dev/null 2>&1 || true
server_listen_once $PORT $MARKER
if client_can_reach "$SERVER_IP" $PORT; then
    fail "geo-ip block did not win over the operator pass rule"
    pf_snapshot after-connect
    # Is the table really empty now, or was the lookup wrong? Re-check
    # membership and try once more.
    if $PFCTL -t "$TABLE" -T test "$CLIENT_IP" >/dev/null 2>&1; then
        note "root table still lists $CLIENT_IP after the connect"
    else
        note "root table NO LONGER lists $CLIENT_IP after the connect"
    fi
    $PFCTL -k "$CLIENT_IP" >/dev/null 2>&1 || true
    server_listen_once $PORT $MARKER
    if client_can_reach "$SERVER_IP" $PORT; then note "second connect also passed"; else note "second connect was blocked"; fi
    pf_snapshot after-second-connect
    sed 's/^/      /' "$RESULTS_DIR/t12-diag.txt"
else
    pf_snapshot after-block
fi
save_pf_artifacts t12

# 3. Disable the rule: anchor and table empty, path open again.
api PUT "/api/v1/geoip/$RULE_ID" '{"country_code":"AQ","action":"block","status":"disabled"}' >/dev/null || fail "disable rule"
[ -z "$(pfctl_anchor_rules $ANCHOR)" ] || fail "anchor still has rules after disabling"
N=$($PFCTL -t "$TABLE" -T show 2>/dev/null | wc -l | tr -d ' ')
[ "$N" = 0 ] || fail "$TABLE still holds $N entries after disabling"
$PFCTL -k "$CLIENT_IP" >/dev/null 2>&1 || true
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT || fail "path did not reopen after disabling the rule"

# 4. Delete the rule; cleanup.
api DELETE "/api/v1/geoip/$RULE_ID" >/dev/null || fail "delete rule"
api DELETE "/api/v1/rules/$PASS_ID" >/dev/null || fail "delete pass"
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
