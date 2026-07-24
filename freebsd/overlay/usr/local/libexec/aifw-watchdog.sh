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

# --- sudoers self-heal (defense-in-depth) ----------------------------------
# Mirror of the refresh in aifw-restart.sh. The restart driver is the primary
# path (runs on every update/bounce); this runs once at watchdog startup — and
# the watchdog restarts on every reboot — so a box heals even if it never sees
# another update or the restart driver fell back to the in-process loop. Runs
# as root via the `daemon -f` grant. Content comes from the signed aifw-setup
# binary (SEC-C1: aifw uid cannot write sudoers, root can). Idempotent and
# validated; a no-op once the file already matches.
refresh_sudoers() {
    [ -x /usr/local/sbin/aifw-setup ] || return 0
    # Absolute path (#601): visudo lives in /usr/local/sbin, which is NOT in
    # the daemon(8) default PATH the watchdog runs under — the bare name
    # made this check fail command-not-found on every boot, so the refresh
    # never ran and the failure was misreported as a validation error.
    VISUDO=/usr/local/sbin/visudo
    [ -x "$VISUDO" ] || VISUDO=$(command -v visudo) || {
        log "WARN visudo not found; sudoers refresh skipped"
        return 0
    }
    _tmp=$(mktemp /tmp/aifw-sudoers.XXXXXX) || return 0
    if /usr/local/sbin/aifw-setup --print-sudoers > "$_tmp" 2>/dev/null && [ -s "$_tmp" ]; then
        if "$VISUDO" -cf "$_tmp" >/dev/null 2>&1; then
            if ! cmp -s "$_tmp" /usr/local/etc/sudoers.d/aifw 2>/dev/null; then
                if install -m 440 -o root -g wheel "$_tmp" /usr/local/etc/sudoers.d/aifw; then
                    log "refreshed /usr/local/etc/sudoers.d/aifw from aifw-setup"
                else
                    log "WARN failed to install refreshed sudoers"
                fi
            fi
        else
            log "WARN aifw-setup --print-sudoers failed visudo validation; sudoers unchanged"
        fi
    fi
    rm -f "$_tmp"
}
refresh_sudoers

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
