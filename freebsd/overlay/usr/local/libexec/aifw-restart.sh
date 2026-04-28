#!/bin/sh
#
# aifw-restart.sh — detached service-restart driver.
#
# Spawned via `daemon -f` from aifw-api after install/rollback. The previous
# implementation ran an in-process tokio loop inside aifw-api, so when the
# loop reached `service aifw_api restart` the rc.d stop killed aifw-api and
# took the loop with it — recoverable failures during the start half had no
# driver left to retry. This script lives in its own session, parented to
# init, so it outlives aifw-api dying mid-iteration.
#
# Idempotent. Safe to invoke even when there's nothing to bounce.

set -u

LOG=/var/log/aifw/restart.log
mkdir -p /var/log/aifw 2>/dev/null

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') aifw-restart: $*" >> "$LOG"
}

log "starting (pid $$)"

# Settle: let the API HTTP response leave the box and the caller's tokio
# runtime tear down before we touch services. Matches the 2-second delay
# used by the previous in-process implementation.
sleep 2

# Idempotent rcvar enable. New services (notably aifw_ids in 5.76.0)
# arrive as binary+rc.d via the update tarball but inherit the shipped
# default of NO. Without flipping the rcvar, `service start` is a silent
# no-op and the bounce that follows quietly skips the new service.
for var in aifw_daemon_enable aifw_ids_enable aifw_api_enable aifw_watchdog_enable; do
    /usr/sbin/sysrc "${var}=YES" >> "$LOG" 2>&1
done

# Order matters:
#  - companions first (cheapest, isolated)
#  - aifw_daemon next
#  - aifw_ids before aifw_api (aifw_api REQUIREs aifw_ids)
#  - aifw_api last so HTTP stays up as long as possible
#  - aifw_watchdog last-last so it doesn't observe the api down and
#    redundantly try to start it during the bounce window
for svc in rdns rdhcpd rtime trafficcop aifw_daemon aifw_ids aifw_api aifw_watchdog; do
    log "restarting ${svc}"
    if /usr/sbin/service "${svc}" restart >> "$LOG" 2>&1; then
        log "${svc} restart ok"
    else
        log "WARN ${svc} restart returned non-zero"
    fi
done

log "complete"
