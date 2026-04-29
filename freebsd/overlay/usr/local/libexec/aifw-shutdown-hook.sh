#!/bin/sh
# Fired by the rc.d aifw_demote_on_shutdown KEYWORD: shutdown.
# Demotes CARP just before final teardown so peer takes over before us.
[ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ] || exit 0
sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
sleep 1
exit 0
