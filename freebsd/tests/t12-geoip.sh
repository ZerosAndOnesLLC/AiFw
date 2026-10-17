# shellcheck shell=sh
# T12 — Geo-IP on real pf (#704). A tiny GeoLite2 Country CSV release is
# uploaded through the API and a rule for its country is added. The
# geo-IP anchor is hooked after the operator rule set in pf.conf, so an
# operator `pass quick` always wins over a geo-IP block; the proof here is
# therefore an ALLOW rule: with nothing else opening the test path, the
# client jail (listed in the release) reaches the server only if the
# anchor rule matched it against the ROOT table the engine filled. Then a
# block closes the path again and disabling empties anchor and table.
#   1. the anchor rule references the ROOT table (no `table` line in the
#      anchor shadowing it — the #704 defect);
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

# 0. Baseline: nothing in the geo-IP anchor, no pass rule, so the harness
#    default-deny closes the test path.
[ -z "$(pfctl_anchor_rules $ANCHOR)" ] || fail "anchor $ANCHOR not empty before the test"
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT && fail "baseline: client reached server with no pass rule"

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

pf_snapshot() { # $1 = label; root + anchor table views and the anchor rules
    {
        echo "=== $1 @ $(date -u '+%H:%M:%S')"
        echo "--- root -T show"; $PFCTL -t "$TABLE" -T show
        echo "--- pfctl -a $ANCHOR -vvsT"; $PFCTL -a "$ANCHOR" -vvsT
        echo "--- pfctl -a $ANCHOR -vvsr"; $PFCTL -a "$ANCHOR" -vvsr
    } >> "$RESULTS_DIR/t12-diag.txt" 2>&1
}
: > "$RESULTS_DIR/t12-diag.txt"

# 2. ALLOW Antarctica. The geo-IP anchor is evaluated after the operator
#    rule set, so an allow is the only way a geo-IP rule can be the thing
#    that opens the path: if the client gets through, the anchor rule
#    matched the client against the ROOT table the engine filled (#704).
RULE_ID=$(api POST /api/v1/geoip '{"country_code":"AQ","action":"allow","label":"t12-aq"}' | jq -r '.data.id') || fail "create geo-ip rule"
RULES=$(pfctl_anchor_rules $ANCHOR)
note "anchor rules:"; printf '%s\n' "$RULES" | sed 's/^/      /'
printf '%s\n' "$RULES" | grep -q "pass in quick from <$TABLE>" || fail "pass rule for <$TABLE> missing from $ANCHOR"
printf '%s\n' "$RULES" | grep -q "^table" && fail "anchor defines the table itself — root entries would be shadowed (#704)"
N=$($PFCTL -t "$TABLE" -T show 2>/dev/null | wc -l | tr -d ' ')
[ "$N" = 2 ] || fail "root table $TABLE holds $N entries, expected 2"
$PFCTL -t "$TABLE" -T test "$CLIENT_IP" >/dev/null 2>&1 || fail "$CLIENT_IP not in $TABLE"
VIEW=$(api GET /api/v1/geoip | jq -c '.data[] | select(.country=="AQ") | {country, cidr_count, table}')
note "rule view: $VIEW"
[ "$(printf '%s' "$VIEW" | jq -r '.cidr_count')" = 2 ] || fail "API reports wrong cidr_count: $VIEW"

pf_snapshot before-allow-connect
server_listen_once $PORT $MARKER
if client_can_reach "$SERVER_IP" $PORT; then
    note "geo-ip allow let the listed client through — root-table lookup from the anchor works"
else
    fail "geo-ip allow did not open the path: the anchor rule did not match the root table"
    pf_snapshot after-failed-allow
    sed 's/^/      /' "$RESULTS_DIR/t12-diag.txt"
fi

# 3. Flip to BLOCK: the path closes again (block + default deny).
api PUT "/api/v1/geoip/$RULE_ID" '{"country_code":"AQ","action":"block"}' >/dev/null || fail "switch rule to block"
pfctl_anchor_rules $ANCHOR | grep -q "block drop in quick from <$TABLE>" || fail "block rule missing after switch"
$PFCTL -k "$CLIENT_IP" >/dev/null 2>&1 || true
server_listen_once $PORT $MARKER
client_can_reach "$SERVER_IP" $PORT && fail "client still reaches server after switching the rule to block"
save_pf_artifacts t12

# 4. Disable the rule: anchor and table empty.
api PUT "/api/v1/geoip/$RULE_ID" '{"country_code":"AQ","action":"block","status":"disabled"}' >/dev/null || fail "disable rule"
[ -z "$(pfctl_anchor_rules $ANCHOR)" ] || fail "anchor still has rules after disabling"
N=$($PFCTL -t "$TABLE" -T show 2>/dev/null | wc -l | tr -d ' ')
[ "$N" = 0 ] || fail "$TABLE still holds $N entries after disabling"

# 5. Delete the rule; cleanup.
api DELETE "/api/v1/geoip/$RULE_ID" >/dev/null || fail "delete rule"

[ "$FAILURES" = 0 ] || exit 1
exit 0
