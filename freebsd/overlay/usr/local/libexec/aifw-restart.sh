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

if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
    sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
    sleep 1
fi

LOG=/var/log/aifw/restart.log
mkdir -p /var/log/aifw 2>/dev/null

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') aifw-restart: $*" >> "$LOG"
}

log "starting (pid $$)"

# --- sudoers self-heal (in-place upgrade gap) ------------------------------
# In-place tarball upgrades install new binaries and the narrow aifw-sudo-*
# helpers, but the updater runs as the aifw uid and by design (SEC-C1) cannot
# write /usr/local/etc/sudoers.d/aifw. This driver runs as root via the
# `daemon -f` grant, so it is the correct privileged step to refresh the
# sudoers file from the canonical, CI-tested definition baked into the signed
# aifw-setup binary. Without this, an upgraded box keeps a stale sudoers that
# lacks the helper grants the new code calls (e.g. aifw-sudo-service), and
# operations like the DNS resolver apply/probe fail with
# "sudo: a password is required". Idempotent and validated. Runs before the
# service bounce so the restarted services come up with correct grants.
refresh_sudoers() {
    [ -x /usr/local/sbin/aifw-setup ] || return 0
    _tmp=$(mktemp /tmp/aifw-sudoers.XXXXXX) || return 0
    if /usr/local/sbin/aifw-setup --print-sudoers > "$_tmp" 2>/dev/null && [ -s "$_tmp" ]; then
        # Validate before installing — a malformed sudoers file would void
        # every NOPASSWD grant the appliance depends on.
        if visudo -cf "$_tmp" >/dev/null 2>&1; then
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

# --- package self-heal (in-place upgrade gap #565) --------------------------
# The updater's own ensure-packages loop reads the manifest embedded in the
# RUNNING (old) binary, so the first upgrade to a release that adds an OS
# package never installs it (strongswan, #530). This driver executes the NEW
# tarball's code as root, so it asks the freshly-installed aifw-setup for the
# authoritative package list and installs whatever is missing — before the
# bounce, so restarted services find their dependencies present.
ensure_packages() {
    [ -x /usr/local/sbin/aifw-setup ] || return 0
    for _pkg in $(/usr/local/sbin/aifw-setup --print-packages 2>/dev/null); do
        if ! pkg info -q "$_pkg" 2>/dev/null; then
            log "installing missing dependency: $_pkg"
            if ! env ASSUME_ALWAYS_YES=yes pkg install "$_pkg" >> "$LOG" 2>&1; then
                log "WARN pkg install $_pkg failed — dependent features may not start"
            fi
        fi
    done
}
ensure_packages

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
