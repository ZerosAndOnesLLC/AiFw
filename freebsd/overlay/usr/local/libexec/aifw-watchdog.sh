#!/bin/sh
#
# aifw-watchdog.sh — defense-in-depth self-heal loop.
#
# For each AiFw service whose rcvar is YES, ensure the service is actually
# running. Catches every "should be running, isn't" condition, regardless
# of cause: failed update bounce, panic during init, OOM kill, daemon(8)
# supervisor giving up after 5 fast restarts, future bugs.
#
# This is the safety net; aifw-restart.sh is the primary path. The two
# together let us trade the old "if the bounce fails, the appliance is
# down until someone notices" behaviour for "the worst case is a 60s
# outage, which the operator may not even see."

set -u

LOG=/var/log/aifw/watchdog.log
INTERVAL="${AIFW_WATCHDOG_INTERVAL:-60}"

mkdir -p /var/log/aifw 2>/dev/null

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') aifw-watchdog: $*" >> "$LOG"
}

heal_one()
{
    svc="$1"
    rcvar="${svc}_enable"
    enabled=$(/usr/sbin/sysrc -n "${rcvar}" 2>/dev/null || echo "NO")
    if [ "${enabled}" != "YES" ]; then
        return 0
    fi
    if /usr/sbin/service "${svc}" status >/dev/null 2>&1; then
        return 0
    fi
    log "${svc} not running, starting"
    if /usr/sbin/service "${svc}" start >> "$LOG" 2>&1; then
        log "${svc} started"
    else
        log "WARN ${svc} start returned non-zero"
    fi
}

log "starting (pid $$, interval ${INTERVAL}s)"

while true; do
    # Order: daemon first, then ids (aifw_api REQUIREs ids), then api.
    # Companions (rdns/rdhcpd/rtime/trafficcop) are intentionally not in
    # this loop — they have their own daemon(8) supervisors with -R 5
    # auto-restart, and we don't want the watchdog second-guessing
    # operator decisions to disable them.
    for svc in aifw_daemon aifw_ids aifw_api; do
        heal_one "${svc}"
    done
    sleep "${INTERVAL}"
done
