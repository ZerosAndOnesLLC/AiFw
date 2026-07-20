# shellcheck shell=sh
# T05 — config save/restore against the live system (#535): snapshot a
# known state, mutate it, restore, and verify both the DB (via API) and the
# live pf anchor came back — with the strict-apply contract (a restore that
# succeeds reports success only when pf actually reloaded).

PORT=8090

# Known state: one distinctive rule
KEEP_ID=$(add_rule '{"action":"pass","direction":"in","protocol":"tcp","dst_addr":"'"$SERVER_IP"'","dst_port_start":'$PORT',"dst_port_end":'$PORT',"label":"t05-keeper"}') || fail "create keeper"
api_reload || fail "reload keeper"
pfctl_anchor_rules aifw | grep -q 't05-keeper' || fail "keeper not in pf before snapshot"

VERSION=$(api POST /api/v1/config/save '{"comment":"t05 snapshot"}' | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p') || fail "save version"
[ -n "$VERSION" ] || fail "could not parse saved version number"
note "saved config version $VERSION"

# Mutate: delete the keeper, add an impostor
api DELETE "/api/v1/rules/$KEEP_ID" >/dev/null || fail "delete keeper"
add_rule '{"action":"block","direction":"in","protocol":"tcp","dst_port_start":9999,"dst_port_end":9999,"label":"t05-impostor"}' >/dev/null || fail "create impostor"
api_reload || fail "reload mutated"
pfctl_anchor_rules aifw | grep -q 't05-keeper' && fail "keeper still in pf after delete"

# Restore the snapshot
api POST /api/v1/config/restore "{\"version\":$VERSION}" >/dev/null || fail "restore failed"

rules_after=$(pfctl_anchor_rules aifw)
printf '%s\n' "$rules_after" > "$RESULTS_DIR/t05-anchor-after-restore.txt"
printf '%s\n' "$rules_after" | grep -q 't05-keeper' || fail "restore did not bring the keeper back into live pf"
printf '%s\n' "$rules_after" | grep -q 't05-impostor' && fail "restore left the impostor in live pf"

api GET /api/v1/rules | jq -r '.data[].label' | grep -q 't05-keeper' || fail "keeper missing from DB after restore"

# Packet-level: the restored rule actually passes traffic
client_can_reach "$SERVER_IP" $PORT || { server_listen_once $PORT /tmp/aifwfx-t05; client_can_reach "$SERVER_IP" $PORT || fail "restored rule does not pass traffic"; }

# Cleanup
for id in $(api GET /api/v1/rules | jq -r '.data[] | select(.label != null and (.label | startswith("t05-"))) | .id'); do
    api DELETE "/api/v1/rules/$id" >/dev/null || fail "delete $id"
done
api_reload || fail "cleanup reload"

[ "$FAILURES" = 0 ] || exit 1
exit 0
