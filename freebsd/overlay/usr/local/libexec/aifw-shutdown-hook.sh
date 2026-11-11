#!/bin/sh
# Fired by the rc.d aifw_demote_on_shutdown KEYWORD: shutdown.
# Demotes CARP just before final teardown so the peer takes the VIPs over
# (preemption is on) before our interfaces go down. The kernel counter and
# the demotion ledger both reset on the next boot.
[ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ] || exit 0
/usr/local/libexec/aifw-sudo-carp demote shutdown >/dev/null 2>&1 || true
# One advertisement interval for the peer to see our demoted skew and preempt.
sleep 2
exit 0
