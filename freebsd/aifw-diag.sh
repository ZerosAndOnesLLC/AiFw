#!/bin/sh
# aifw-diag.sh — capture AiFw + pf forensic state to /var/tmp/
#
# Run before AND after a risky upgrade to diff what changed.
# Usage: sh aifw-diag.sh [pre|post|manual]
#
# Output: /var/tmp/aifw-diag-<phase>-<timestamp>.txt (self-contained text file)

set -u

PHASE="${1:-manual}"
TS=$(date +%Y%m%d-%H%M%S)
OUT="/var/tmp/aifw-diag-${PHASE}-${TS}.txt"
DB="/var/db/aifw/aifw.db"
DB_SNAP="/tmp/aifw-diag-${TS}.db"

hdr()  { echo; echo "=== $* ==="; }
cmd()  { hdr "$1"; shift; "$@" 2>&1 || true; }
show() { hdr "$1"; [ -r "$2" ] && cat "$2" 2>&1 || echo "(absent: $2)"; }

{
echo "AiFw diagnostic dump"
echo "Phase:    $PHASE"
echo "Host:     $(hostname)"
echo "When:     $(date)"
echo "Script:   $0 ($TS)"

cmd "OS"                   uname -a
cmd "aifw version"         /usr/local/sbin/aifw --version
cmd "sysrc resolver"       sh -c 'sysrc -n rdns_enable; sysrc -n local_unbound_enable'
cmd "sysrc aifw"           sh -c 'for k in aifw_api_enable aifw_daemon_enable trafficcop_enable gateway_enable pf_enable; do echo "$k=$(sysrc -n $k 2>/dev/null)"; done'
cmd "services"             sh -c 'for s in aifw_api aifw_daemon rdns local_unbound trafficcop pf; do printf "%-16s " "$s"; service $s status 2>&1 | head -1; done'

cmd "interfaces"           ifconfig -a
cmd "routes (v4)"          netstat -rn -f inet
cmd "default gw"           route -n get default
cmd "listeners :53"        sockstat -4l -p 53
cmd "listeners :8080"      sockstat -4l -p 8080
cmd "ARP"                  arp -an

cmd "pf info"              pfctl -s info
cmd "pf anchors"           pfctl -s Anchors
cmd "pf main rules"        pfctl -s rules
cmd "pf main NAT"          pfctl -s nat
cmd "aifw anchor rules"       pfctl -a aifw -s rules
cmd "aifw-nat anchor nat"     pfctl -a aifw-nat -s nat
cmd "aifw-nat anchor rules"   pfctl -a aifw-nat -s rules
cmd "aifw-vpn anchor rules"   pfctl -a aifw-vpn -s rules
cmd "aifw-geoip anchor"       pfctl -a aifw-geoip -s rules
cmd "aifw-ratelimit anchor"   pfctl -a aifw-ratelimit -s rules
cmd "aifw-tls anchor"         pfctl -a aifw-tls -s rules
cmd "aifw-ha anchor"          pfctl -a aifw-ha -s rules
cmd "pf tables"            pfctl -s Tables
cmd "pf timeouts"          pfctl -s timeouts
cmd "pf memory"            pfctl -s memory
cmd "pf states (head)"     sh -c 'pfctl -s state 2>&1 | head -20'

hdr "DB snapshot (read-only copy)"
if [ -r "$DB" ]; then
  sqlite3 "$DB" ".backup $DB_SNAP" 2>&1 || echo "snapshot failed"
  if [ -r "$DB_SNAP" ]; then
    for tbl in rules nat_rules geoip_rules wg_tunnels wg_peers ipsec_sas \
               queues rate_limits sni_rules ja3_blocklist carp_vips \
               pfsync_config cluster_nodes dns_resolver_config \
               dns_host_overrides dns_domain_overrides dns_access_lists \
               static_routes gateways instances policies \
               config_versions auth_config; do
      cnt=$(sqlite3 "$DB_SNAP" "SELECT COUNT(*) FROM $tbl" 2>/dev/null || echo "n/a")
      printf "  %-26s  %s\n" "$tbl" "$cnt"
    done

    hdr "dns_resolver_config (all rows)"
    sqlite3 -header -column "$DB_SNAP" "SELECT key, substr(value,1,200) AS value FROM dns_resolver_config ORDER BY key" 2>&1

    hdr "nat_rules (all — matters for outbound)"
    sqlite3 -header -column "$DB_SNAP" "SELECT id, nat_type, interface, protocol, src_addr, dst_addr, redirect_addr, label, status FROM nat_rules" 2>&1

    hdr "rules (filter, first 50)"
    sqlite3 -header -column "$DB_SNAP" "SELECT substr(id,1,8) AS id, priority, action, direction, protocol, interface, src_addr, dst_addr, status, substr(label,1,30) AS label FROM rules ORDER BY priority LIMIT 50" 2>&1

    hdr "gateways"
    sqlite3 -header -column "$DB_SNAP" "SELECT * FROM gateways" 2>&1

    hdr "policies (first 20)"
    sqlite3 -header -column "$DB_SNAP" "SELECT * FROM policies LIMIT 20" 2>&1

    hdr "last 10 config_versions"
    sqlite3 -header -column "$DB_SNAP" "SELECT version, applied, rolled_back, created_by, created_at, substr(comment,1,60) AS comment FROM config_versions ORDER BY version DESC LIMIT 10" 2>&1

    rm -f "$DB_SNAP"
  fi
else
  echo "(no DB at $DB)"
fi

show "/usr/local/etc/rdns/rdns.toml"           /usr/local/etc/rdns/rdns.toml
cmd  "rdns zone files"                         ls -la /usr/local/etc/rdns/zones/
cmd  "rdns RPZ files"                          ls -la /usr/local/etc/rdns/rpz/
cmd  "/var/unbound/unbound.conf (head 80)"     sh -c 'head -80 /var/unbound/unbound.conf 2>&1 || echo "(absent)"'

cmd  "/usr/local/etc/aifw/"                    ls -la /usr/local/etc/aifw/
show "/usr/local/etc/aifw/pf.conf.aifw"        /usr/local/etc/aifw/pf.conf.aifw

hdr  "rc.conf (aifw + pf relevant)"
grep -E 'pf|aifw|rdns|unbound|gateway_enable|trafficcop|firstboot' /etc/rc.conf 2>&1 || echo "(no matches)"

hdr  "recent /var/log/messages (filtered)"
tail -500 /var/log/messages 2>/dev/null | grep -iE 'aifw|rdns|unbound|pf |nat |panic|error|fail' | tail -120

cmd  "aifw log dir"                            ls -la /var/log/aifw/
for f in /var/log/aifw/*.log; do
  [ -r "$f" ] || continue
  hdr "tail 80 of $f"
  tail -80 "$f" 2>&1 || true
done

hdr  "binary mtimes"
ls -la /usr/local/sbin/aifw* /usr/local/etc/rc.d/aifw* 2>&1
} > "$OUT" 2>&1

sz=$(wc -c < "$OUT" 2>/dev/null | tr -d ' ')
echo "Diag written to $OUT (${sz} bytes)"
