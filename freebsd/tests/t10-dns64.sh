# shellcheck shell=sh
# T10 — DNS64 synthesis (RFC 6147, #531): a hermetic two-instance rDNS
# setup. An authoritative upstream serves an A-only zone; the front
# resolver forwards to it with dns64 enabled. A AAAA query for the A-only
# name must return the RFC 6052 embedding in 64:ff9b::/96; names with no
# records must stay NXDOMAIN (never synthesized).
#
# SKIPs (exit 0 with a note) when no rdns binary is available or the
# installed one predates DNS64 — the harness must stay green on hosts
# where only the AiFw binaries are under test. Override the binary with
# RDNS_BIN=/path/to/rdns.

RDNS_BIN="${RDNS_BIN:-/usr/local/sbin/rdns}"
if [ ! -x "$RDNS_BIN" ]; then
    note "SKIP: no rdns binary at $RDNS_BIN (set RDNS_BIN to test DNS64)"
    exit 0
fi

# Capability probe on the BINARY, not the runtime log: a build that knows
# DNS64 embeds the enable-log string. This keeps "binary predates DNS64"
# (skip) distinct from "DNS64 configured but failed to enable" (fail) —
# otherwise a regression in the enable path would go green-by-skip.
if ! strings "$RDNS_BIN" 2>/dev/null | grep -q "DNS64 synthesis enabled"; then
    note "SKIP: rdns at $RDNS_BIN has no DNS64 support (pre-#531 build)"
    exit 0
fi

T10_DIR="$WORK_DIR/t10-dns64"
mkdir -p "$T10_DIR/zones"

cat > "$T10_DIR/zones/t10test.internal.zone" <<EOF
\$TTL 60
\$ORIGIN t10test.internal.
@   IN  SOA ns.t10test.internal. admin.t10test.internal. (1 3600 900 604800 60)
@   IN  NS  ns.t10test.internal.
ns      IN  A   127.0.0.1
v4only  IN  A   10.99.2.2
alias   IN  CNAME v4only.t10test.internal.
EOF

cat > "$T10_DIR/upstream.toml" <<EOF
[server]
mode = "authoritative"
pidfile = "/dev/null"
[listeners]
udp = ["127.0.0.1:15355"]
tcp = ["127.0.0.1:15355"]
[authoritative]
source = "zone-files"
directory = "$T10_DIR/zones"
[control]
socket = "$T10_DIR/upstream.sock"
[security]
sandbox = false
EOF

cat > "$T10_DIR/front.toml" <<EOF
[server]
mode = "resolver"
pidfile = "/dev/null"
[listeners]
udp = ["127.0.0.1:15354"]
tcp = ["127.0.0.1:15354"]
[resolver]
forwarders = ["127.0.0.1:15355"]
dnssec = false
dns64 = true
dns64_prefix = "64:ff9b::/96"
[control]
socket = "$T10_DIR/front.sock"
[security]
allow_recursion = ["127.0.0.0/8"]
sandbox = false
EOF

"$RDNS_BIN" --config "$T10_DIR/upstream.toml" > "$RESULTS_DIR/t10-upstream.log" 2>&1 &
T10_UP_PID=$!
"$RDNS_BIN" --config "$T10_DIR/front.toml" > "$RESULTS_DIR/t10-front.log" 2>&1 &
T10_FRONT_PID=$!
t10_cleanup() { kill "$T10_UP_PID" "$T10_FRONT_PID" 2>/dev/null; }
sleep 2

# The binary supports DNS64 (probed above), so a missing enable line here
# is a real failure, not a skip.
if ! grep -q "DNS64 synthesis enabled" "$RESULTS_DIR/t10-front.log"; then
    fail "dns64: binary supports DNS64 but it did not enable (see t10-front.log)"
    t10_cleanup
    exit 1
fi

# A-only name through DNS64: expect the RFC 6052 embedding of 10.99.2.2.
drill -p 15354 @127.0.0.1 AAAA v4only.t10test.internal > "$RESULTS_DIR/t10-aaaa.txt" 2>&1
grep -q "64:ff9b::a63:202" "$RESULTS_DIR/t10-aaaa.txt" \
    || fail "dns64: AAAA for A-only name not synthesized (see t10-aaaa.txt)"

# CNAME to an A-only target must ALSO synthesize (RFC 6147 §5.1.6) — the
# answer section is non-empty (the chain), which the original gate got
# wrong; this is the CDN-hosted-site shape (#531 review H1).
drill -p 15354 @127.0.0.1 AAAA alias.t10test.internal > "$RESULTS_DIR/t10-cname.txt" 2>&1
grep -q "64:ff9b::a63:202" "$RESULTS_DIR/t10-cname.txt" \
    || fail "dns64: CNAME'd A-only name not synthesized (see t10-cname.txt)"

# The A record itself must still resolve normally.
drill -p 15354 @127.0.0.1 A v4only.t10test.internal > "$RESULTS_DIR/t10-a.txt" 2>&1
grep -q "10.99.2.2" "$RESULTS_DIR/t10-a.txt" || fail "dns64: A lookup broken"

# NXDOMAIN is never synthesized.
drill -p 15354 @127.0.0.1 AAAA missing.t10test.internal > "$RESULTS_DIR/t10-nx.txt" 2>&1
grep -q "NXDOMAIN" "$RESULTS_DIR/t10-nx.txt" || fail "dns64: NXDOMAIN must not be synthesized"
grep -q "64:ff9b" "$RESULTS_DIR/t10-nx.txt" && fail "dns64: synthesized an answer for NXDOMAIN"

# Cached second query keeps the synthesized answer (positive AAAA cache).
drill -p 15354 @127.0.0.1 AAAA v4only.t10test.internal > "$RESULTS_DIR/t10-aaaa2.txt" 2>&1
grep -q "64:ff9b::a63:202" "$RESULTS_DIR/t10-aaaa2.txt" \
    || fail "dns64: synthesized answer lost on cache hit"

t10_cleanup

[ "$FAILURES" = 0 ] || exit 1
exit 0
