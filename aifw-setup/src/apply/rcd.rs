//! rc.d service scripts for every AiFw service.

use crate::config::SetupConfig;

use super::system::{warn_on_err, write_file};

/// Write FreeBSD rc.d service scripts. Pattern follows `rdns` — supervisor
/// pidfile + child pidfile + start_precmd reaping orphans.
pub(super) fn write_rcd_scripts(config: &SetupConfig) -> Result<(), String> {
    let daemon_script = format!(
        r#"#!/bin/sh
#
# PROVIDE: aifw_daemon
# REQUIRE: NETWORKING pf devfs
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_daemon"
rcvar="aifw_daemon_enable"

load_rc_config $name

: ${{aifw_daemon_enable:="NO"}}
: ${{aifw_daemon_pidfile:="/var/run/aifw_daemon.pid"}}
: ${{aifw_daemon_supervisor_pidfile:="/var/run/aifw_daemon-supervisor.pid"}}
: ${{aifw_daemon_env:=""}}

pidfile="${{aifw_daemon_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_daemon_binary="/usr/local/sbin/aifw-daemon"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_daemon_pidfile}} -P ${{aifw_daemon_supervisor_pidfile}} -R 5 -S -T aifw_daemon -o /var/log/aifw/daemon.log -u aifw ${{aifw_daemon_binary}} --db {db} --log-level info"

start_precmd="aifw_daemon_precmd"
stop_cmd="aifw_daemon_stop"
stop_postcmd="aifw_daemon_poststop"

aifw_demote_if_clustered()
{{
    if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
        sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
        sleep 1
    fi
}}

aifw_daemon_precmd()
{{
    /bin/mkdir -p /var/log/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-daemon" 2>/dev/null
    /usr/bin/pkill -x aifw-daemon 2>/dev/null
    /bin/rm -f ${{aifw_daemon_pidfile}} ${{aifw_daemon_supervisor_pidfile}}
    # Pre-create singleton lockfile owned by aifw — /var/run is root-only,
    # so the binary (running as aifw via daemon -u aifw) can't create it.
    /usr/bin/touch /var/run/aifw-daemon.lock
    /usr/sbin/chown aifw:aifw /var/run/aifw-daemon.lock
    # Read the loopback API key from a 640 file (mode root:aifw) rather than
    # from /etc/rc.conf (which is world-readable mode 644).  The file is
    # written by aifw-setup; the daemon process needs it to authenticate
    # background tasks (RoleWatcher, HealthProber, ClusterReplicator) to the
    # local API.
    if [ -r /usr/local/etc/aifw/daemon.key ]; then
        export AIFW_LOOPBACK_API_KEY="$(cat /usr/local/etc/aifw/daemon.key)"
    fi
    # Fallback: honour legacy rc.conf aifw_daemon_env for nodes that have not
    # yet been re-provisioned with the new daemon.key path.
    if [ -z "${{AIFW_LOOPBACK_API_KEY}}" ] && [ -n "${{aifw_daemon_env}}" ]; then
        export ${{aifw_daemon_env}}
    fi
}}

aifw_daemon_stop()
{{
    aifw_demote_if_clustered
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${{aifw_daemon_supervisor_pidfile}}" ]; then
        sup_pid=$(cat "${{aifw_daemon_supervisor_pidfile}}")
        echo "Stopping aifw_daemon (supervisor pid ${{sup_pid}})."
        if kill -TERM "${{sup_pid}}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${{sup_pid}}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${{sup_pid}}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${{sup_pid}}" 2>/dev/null
                /usr/bin/pkill -KILL -x aifw-daemon 2>/dev/null
            fi
        fi
    elif [ -f "${{aifw_daemon_pidfile}}" ]; then
        pid=$(cat "${{aifw_daemon_pidfile}}")
        kill -TERM "${{pid}}" 2>/dev/null
        sleep 2
        kill -KILL "${{pid}}" 2>/dev/null
    else
        echo "aifw_daemon is not running."
    fi
    /bin/rm -f ${{aifw_daemon_pidfile}} ${{aifw_daemon_supervisor_pidfile}}
}}

aifw_daemon_poststop()
{{
    /bin/rm -f ${{aifw_daemon_pidfile}} ${{aifw_daemon_supervisor_pidfile}}
}}

run_rc_command "$1"
"#,
        db = config.db_path
    );

    let api_script = format!(
        r#"#!/bin/sh
#
# PROVIDE: aifw_api
# REQUIRE: NETWORKING aifw_daemon aifw_ids
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_api"
rcvar="aifw_api_enable"

load_rc_config $name

: ${{aifw_api_enable:="NO"}}
: ${{aifw_api_pidfile:="/var/run/aifw_api.pid"}}
: ${{aifw_api_supervisor_pidfile:="/var/run/aifw_api-supervisor.pid"}}

pidfile="${{aifw_api_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_api_binary="/usr/local/sbin/aifw-api"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_api_pidfile}} -P ${{aifw_api_supervisor_pidfile}} -R 5 -S -T aifw_api -o /var/log/aifw/api.log -u aifw ${{aifw_api_binary}} --db {db} --listen {listen}:{port} --ui-dir /usr/local/share/aifw/ui --log-level info"

start_precmd="aifw_api_precmd"
stop_cmd="aifw_api_stop"
stop_postcmd="aifw_api_poststop"

aifw_demote_if_clustered()
{{
    if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
        sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
        sleep 1
    fi
}}

aifw_api_precmd()
{{
    /bin/mkdir -p /var/log/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-api" 2>/dev/null
    /usr/bin/pkill -x aifw-api 2>/dev/null
    /bin/rm -f ${{aifw_api_pidfile}} ${{aifw_api_supervisor_pidfile}}
    # Pre-create singleton lockfile owned by aifw. rm+touch+chown+chmod
    # every start so stale ownership/mode from older binaries can't strand
    # the singleton lock — aifw-api now exits hard on FreeBSD when this
    # fails (see #276).
    /bin/rm -f /var/run/aifw-api.lock
    /usr/bin/touch /var/run/aifw-api.lock
    /usr/sbin/chown aifw:aifw /var/run/aifw-api.lock
    /bin/chmod 644 /var/run/aifw-api.lock
}}

aifw_api_stop()
{{
    aifw_demote_if_clustered
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${{aifw_api_supervisor_pidfile}}" ]; then
        sup_pid=$(cat "${{aifw_api_supervisor_pidfile}}")
        echo "Stopping aifw_api (supervisor pid ${{sup_pid}})."
        if kill -TERM "${{sup_pid}}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${{sup_pid}}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${{sup_pid}}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${{sup_pid}}" 2>/dev/null
                /usr/bin/pkill -KILL -x aifw-api 2>/dev/null
            fi
        fi
    elif [ -f "${{aifw_api_pidfile}}" ]; then
        pid=$(cat "${{aifw_api_pidfile}}")
        kill -TERM "${{pid}}" 2>/dev/null
        sleep 2
        kill -KILL "${{pid}}" 2>/dev/null
    else
        echo "aifw_api is not running."
    fi
    /bin/rm -f ${{aifw_api_pidfile}} ${{aifw_api_supervisor_pidfile}}
}}

aifw_api_poststop()
{{
    /bin/rm -f ${{aifw_api_pidfile}} ${{aifw_api_supervisor_pidfile}}
}}

run_rc_command "$1"
"#,
        db = config.db_path,
        listen = config.api_listen,
        port = config.api_port
    );

    let ids_script = format!(
        r#"#!/bin/sh
#
# PROVIDE: aifw_ids
# REQUIRE: NETWORKING aifw_daemon
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_ids"
rcvar="aifw_ids_enable"

load_rc_config $name

: ${{aifw_ids_enable:="NO"}}
: ${{aifw_ids_pidfile:="/var/run/aifw_ids.pid"}}
: ${{aifw_ids_supervisor_pidfile:="/var/run/aifw_ids-supervisor.pid"}}

pidfile="${{aifw_ids_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_ids_binary="/usr/local/sbin/aifw-ids"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_ids_pidfile}} -P ${{aifw_ids_supervisor_pidfile}} -R 5 -S -T aifw_ids -o /var/log/aifw/ids.log -u aifw ${{aifw_ids_binary}} --db {db} --socket /var/run/aifw/ids.sock --log-level info"

start_precmd="aifw_ids_precmd"
stop_cmd="aifw_ids_stop"
stop_postcmd="aifw_ids_poststop"

aifw_demote_if_clustered()
{{
    if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
        sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
        sleep 1
    fi
}}

aifw_ids_precmd()
{{
    /bin/mkdir -p /var/log/aifw /var/run/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw /var/run/aifw
    /bin/chmod 0750 /var/run/aifw
    /usr/bin/pkill -f "daemon:.*aifw-ids" 2>/dev/null
    /usr/bin/pkill -x aifw-ids 2>/dev/null
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}} /var/run/aifw/ids.sock
    /usr/bin/touch /var/run/aifw-ids.lock
    /usr/sbin/chown aifw:aifw /var/run/aifw-ids.lock
}}

aifw_ids_stop()
{{
    aifw_demote_if_clustered
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${{aifw_ids_supervisor_pidfile}}" ]; then
        sup_pid=$(cat "${{aifw_ids_supervisor_pidfile}}")
        echo "Stopping aifw_ids (supervisor pid ${{sup_pid}})."
        if kill -TERM "${{sup_pid}}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${{sup_pid}}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${{sup_pid}}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${{sup_pid}}" 2>/dev/null
                /usr/bin/pkill -KILL -x aifw-ids 2>/dev/null
            fi
        fi
    elif [ -f "${{aifw_ids_pidfile}}" ]; then
        pid=$(cat "${{aifw_ids_pidfile}}")
        kill -TERM "${{pid}}" 2>/dev/null
        sleep 2
        kill -KILL "${{pid}}" 2>/dev/null
    else
        echo "aifw_ids is not running."
    fi
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}}
}}

aifw_ids_poststop()
{{
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}}
}}

run_rc_command "$1"
"#,
        db = config.db_path
    );

    let rdhcpd_script = r#"#!/bin/sh
#
# PROVIDE: rdhcpd
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="rdhcpd"
rcvar="rdhcpd_enable"

load_rc_config $name

: ${rdhcpd_enable:="NO"}
: ${rdhcpd_config:="/usr/local/etc/rdhcpd/config.toml"}
: ${rdhcpd_pidfile:="/var/run/rdhcpd/rdhcpd.pid"}
: ${rdhcpd_supervisor_pidfile:="/var/run/rdhcpd/rdhcpd-supervisor.pid"}

pidfile="${rdhcpd_supervisor_pidfile}"
procname="/usr/sbin/daemon"
rdhcpd_binary="/usr/local/sbin/rdhcpd"
command="/usr/sbin/daemon"
command_args="-f -p ${rdhcpd_pidfile} -P ${rdhcpd_supervisor_pidfile} -R 5 -S -T rdhcpd -o /var/log/rdhcpd/rdhcpd.log ${rdhcpd_binary} ${rdhcpd_config}"

start_precmd="rdhcpd_precmd"
stop_cmd="rdhcpd_stop"
stop_postcmd="rdhcpd_poststop"
reload_cmd="rdhcpd_reload"
extra_commands="reload"

rdhcpd_precmd()
{
    /bin/mkdir -p /var/db/rdhcpd/leases /var/log/rdhcpd /usr/local/etc/rdhcpd /var/run/rdhcpd
    /usr/sbin/chown -R aifw:aifw /var/db/rdhcpd /var/log/rdhcpd /usr/local/etc/rdhcpd /var/run/rdhcpd
    /usr/bin/pkill -f "daemon:.*rdhcpd" 2>/dev/null
    /usr/bin/pkill -x rdhcpd 2>/dev/null
    /bin/rm -f ${rdhcpd_pidfile} ${rdhcpd_supervisor_pidfile}

    if [ ! -f ${rdhcpd_config} ]; then
        echo "ERROR: rdhcpd config not found at ${rdhcpd_config}"
        return 1
    fi
}

rdhcpd_stop()
{
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${rdhcpd_supervisor_pidfile}" ]; then
        sup_pid=$(cat "${rdhcpd_supervisor_pidfile}")
        echo "Stopping rdhcpd (supervisor pid ${sup_pid})."
        if kill -TERM "${sup_pid}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${sup_pid}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${sup_pid}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${sup_pid}" 2>/dev/null
                /usr/bin/pkill -KILL -x rdhcpd 2>/dev/null
            fi
        fi
    elif [ -f "${rdhcpd_pidfile}" ]; then
        pid=$(cat "${rdhcpd_pidfile}")
        kill -TERM "${pid}" 2>/dev/null
        sleep 2
        kill -KILL "${pid}" 2>/dev/null
    else
        echo "rdhcpd is not running."
    fi
    /bin/rm -f ${rdhcpd_pidfile} ${rdhcpd_supervisor_pidfile}
}

rdhcpd_poststop()
{
    /bin/rm -f ${rdhcpd_pidfile} ${rdhcpd_supervisor_pidfile}
}

rdhcpd_reload()
{
    if [ -f "${rdhcpd_pidfile}" ]; then
        pid=$(cat "${rdhcpd_pidfile}")
        echo "Reloading rdhcpd (pid ${pid})."
        /bin/kill -HUP "${pid}" 2>/dev/null
    else
        echo "rdhcpd is not running."
        return 1
    fi
}

run_rc_command "$1"
"#;

    let rcd_dir = if std::path::Path::new("/usr/local/etc/rc.d").exists() {
        "/usr/local/etc/rc.d"
    } else {
        &config.config_dir
    };

    let watchdog_script = r#"#!/bin/sh
#
# PROVIDE: aifw_watchdog
# REQUIRE: aifw_api
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_watchdog"
rcvar="aifw_watchdog_enable"

load_rc_config $name

: ${aifw_watchdog_enable:="NO"}
: ${aifw_watchdog_pidfile:="/var/run/aifw_watchdog.pid"}
: ${aifw_watchdog_supervisor_pidfile:="/var/run/aifw_watchdog-supervisor.pid"}
: ${aifw_watchdog_interval:="60"}

pidfile="${aifw_watchdog_supervisor_pidfile}"
procname="/usr/sbin/daemon"
command="/usr/sbin/daemon"
command_args="-f -p ${aifw_watchdog_pidfile} -P ${aifw_watchdog_supervisor_pidfile} -R 5 -S -T aifw_watchdog -o /var/log/aifw/watchdog.log /usr/local/libexec/aifw-watchdog.sh"

start_precmd="aifw_watchdog_precmd"
stop_cmd="aifw_watchdog_stop"
stop_postcmd="aifw_watchdog_poststop"

aifw_watchdog_precmd()
{
    /bin/mkdir -p /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-watchdog" 2>/dev/null
    /usr/bin/pkill -f "aifw-watchdog.sh" 2>/dev/null
    /bin/rm -f ${aifw_watchdog_pidfile} ${aifw_watchdog_supervisor_pidfile}
    export AIFW_WATCHDOG_INTERVAL="${aifw_watchdog_interval}"
}

aifw_watchdog_stop()
{
    if [ -f "${aifw_watchdog_supervisor_pidfile}" ]; then
        sup_pid=$(cat "${aifw_watchdog_supervisor_pidfile}")
        echo "Stopping aifw_watchdog (supervisor pid ${sup_pid})."
        if kill -TERM "${sup_pid}" 2>/dev/null; then
            i=0
            while [ $i -lt 5 ] && kill -0 "${sup_pid}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${sup_pid}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${sup_pid}" 2>/dev/null
                /usr/bin/pkill -KILL -f "aifw-watchdog.sh" 2>/dev/null
            fi
        fi
    elif [ -f "${aifw_watchdog_pidfile}" ]; then
        pid=$(cat "${aifw_watchdog_pidfile}")
        kill -TERM "${pid}" 2>/dev/null
        sleep 2
        kill -KILL "${pid}" 2>/dev/null
    else
        echo "aifw_watchdog is not running."
    fi
    /bin/rm -f ${aifw_watchdog_pidfile} ${aifw_watchdog_supervisor_pidfile}
}

aifw_watchdog_poststop()
{
    /bin/rm -f ${aifw_watchdog_pidfile} ${aifw_watchdog_supervisor_pidfile}
}

run_rc_command "$1"
"#;

    write_file(&format!("{rcd_dir}/aifw_daemon"), &daemon_script)?;
    write_file(&format!("{rcd_dir}/aifw_api"), &api_script)?;
    write_file(&format!("{rcd_dir}/aifw_ids"), &ids_script)?;
    write_file(&format!("{rcd_dir}/aifw_watchdog"), watchdog_script)?;
    write_file(&format!("{rcd_dir}/rdhcpd"), rdhcpd_script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        warn_on_err(
            "chmod rc.d/aifw_daemon to 0755",
            std::fs::set_permissions(format!("{rcd_dir}/aifw_daemon"), perms.clone()),
        );
        warn_on_err(
            "chmod rc.d/aifw_api to 0755",
            std::fs::set_permissions(format!("{rcd_dir}/aifw_api"), perms.clone()),
        );
        warn_on_err(
            "chmod rc.d/aifw_ids to 0755",
            std::fs::set_permissions(format!("{rcd_dir}/aifw_ids"), perms.clone()),
        );
        warn_on_err(
            "chmod rc.d/aifw_watchdog to 0755",
            std::fs::set_permissions(format!("{rcd_dir}/aifw_watchdog"), perms.clone()),
        );
        warn_on_err(
            "chmod rc.d/rdhcpd to 0755",
            std::fs::set_permissions(format!("{rcd_dir}/rdhcpd"), perms),
        );
    }

    Ok(())
}
