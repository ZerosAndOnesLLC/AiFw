#!/bin/sh
# T08: real FreeBSD FQ-CoDel lifecycle and ownership qualification.
set -eu

CONTROL=/usr/local/libexec/aifw-dummynet-control
WORK=$(mktemp -d /tmp/aifw-fq-codel.XXXXXX)
UNMANAGED_PIPE=9999
MANAGED_PIPE=10001
trap 'ipfw -q delete 30001 40001 29999 2>/dev/null || true; dnctl -q queue delete 10001 9999 2>/dev/null || true; dnctl -q sched delete 10001 9999 2>/dev/null || true; dnctl -q pipe delete 10001 9999 2>/dev/null || true; rm -rf "$WORK"' EXIT INT TERM HUP

[ "$(id -u)" -eq 0 ] || { echo "T08 requires root" >&2; exit 77; }
kldload dummynet 2>/dev/null || true
sysctl net.inet.ip.fw.enable=1 >/dev/null

cat > "$WORK/desired" <<EOF
pipe $MANAGED_PIPE config bw 10000000bit/s
sched $MANAGED_PIPE config pipe $MANAGED_PIPE type fq_codel target 5ms interval 100ms quantum 1514 limit 10240 flows 1024 ecn
queue $MANAGED_PIPE config sched $MANAGED_PIPE
ipfw add 30001 queue $MANAGED_PIPE ip from any to any out
ipfw add 40001 queue $MANAGED_PIPE ip6 from any to any out
EOF

# Administrator-owned state outside AiFw's ranges must survive every action.
dnctl pipe $UNMANAGED_PIPE config bw 1Mbit/s
ipfw add 29999 allow ip from any to any

"$CONTROL" apply "$WORK/desired"
"$CONTROL" verify "$WORK/desired"
dnctl sched list | grep -Eq "${MANAGED_PIPE}.*fq_codel|fq_codel.*${MANAGED_PIPE}"
ipfw list 30001 | grep -q "queue $MANAGED_PIPE"
ipfw list 40001 | grep -q "queue $MANAGED_PIPE"
dnctl pipe list | grep -q "^${UNMANAGED_PIPE}"
ipfw list 29999 >/dev/null

# A rejected command must not be able to escape the reserved ranges.
cat > "$WORK/hostile" <<EOF
pipe 1 config bw 1Mbit/s
EOF
if "$CONTROL" apply "$WORK/hostile"; then
    echo "controller accepted an unmanaged pipe id" >&2
    exit 1
fi
dnctl pipe list | grep -q "^${UNMANAGED_PIPE}"

# Empty desired state removes AiFw objects without touching admin objects.
printf 'clear\n' > "$WORK/clear"
"$CONTROL" apply "$WORK/clear"
"$CONTROL" verify "$WORK/clear"
! ipfw list 30001 >/dev/null 2>&1
! dnctl pipe list | grep -q "^${MANAGED_PIPE}"
dnctl pipe list | grep -q "^${UNMANAGED_PIPE}"
ipfw list 29999 >/dev/null

echo "T08 PASS: FQ-CoDel live lifecycle, IPv4/IPv6 classifiers, and ownership boundaries"
