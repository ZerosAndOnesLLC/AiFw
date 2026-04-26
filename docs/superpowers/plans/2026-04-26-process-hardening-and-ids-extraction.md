# Process Hardening + IDS Extraction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate duplicate-process and memory-leak bugs in AiFw by (1) enforcing process singletons at the binary AND rc.d layers, (2) extracting IDS into its own `aifw-ids-bin` process so the rule database and FlowTable exist exactly once, (3) bounding the FlowTable so memory plateaus naturally, (4) pruning the LoginRateLimiter, and (5) applying the same singleton pattern across sibling repos (trafficcop, rDNS, rDHCP, rTime).

**Architecture:** New `aifw-ids` long-running daemon owns BPF capture, the 47k-rule DB, FlowTable, and alert pipeline. aifw-daemon and aifw-api both lose their in-process IDS engines. aifw-api becomes an IPC client over a Unix socket at `/var/run/aifw/ids.sock` with short TTL caching. rc.d daemon-pair pattern from `rdns` is replicated everywhere. New `aifw_common::single_instance` helper provides fcntl-based exclusive locks, applied to every long-running binary including the four sibling-repo services.

**Tech Stack:** Rust (workspace, 2024 edition, tokio, axum, sqlx, dashmap, nix), FreeBSD rc.d / `daemon(8)`, Unix domain sockets, JSON-over-length-prefixed framing.

**Source spec:** `docs/superpowers/specs/2026-04-26-process-hardening-and-ids-extraction-design.md`

**Version policy:** Per project CLAUDE.md, bump version in **both** `Cargo.toml` (workspace.package) and `aifw-ui/package.json` before every commit. Choose major/minor/patch per the change. Most tasks here are minor or patch; PR 4 (new binary) and PR 5 (architecture change) are minor bumps.

---

## File Structure

### New files
- `aifw-common/src/single_instance.rs` — fcntl lockfile helper
- `aifw-ids-ipc/Cargo.toml` — new crate
- `aifw-ids-ipc/src/lib.rs`
- `aifw-ids-ipc/src/proto.rs` — request/response types
- `aifw-ids-ipc/src/framing.rs` — length-prefixed read/write
- `aifw-ids-ipc/src/client.rs` — `IdsClient` with TTL cache
- `aifw-ids-ipc/src/server.rs` — `serve(listener, handler)` helper
- `aifw-ids-bin/Cargo.toml` — new crate
- `aifw-ids-bin/src/main.rs` — binary entry
- `aifw-ids-bin/src/handler.rs` — implements `IpcHandler` trait by calling `IdsEngine`
- `freebsd/overlay/usr/local/etc/rc.d/aifw_ids` — new rc.d script

### Modified files
- `Cargo.toml` (workspace): add `aifw-ids-ipc` and `aifw-ids-bin` to `members`; add nix to workspace-deps
- `aifw-common/Cargo.toml`: add `nix` dep (gated to unix targets)
- `aifw-common/src/lib.rs`: `pub mod single_instance;`
- `aifw-ids/src/flow/mod.rs`: bound stream depth, count cap, byte budget, LRU eviction
- `aifw-ids/src/lib.rs`: time-based expiry tokio task, expose `flow_table_stats()`
- `aifw-api/src/main.rs`: remove in-process IdsEngine; replace with `Arc<IdsClient>`; bump memstats with flow_count + flow_reassembly_kb; LoginRateLimiter pruning
- `aifw-api/src/ids.rs`: switch every handler from `state.ids_engine` to `state.ids_client`
- `aifw-api/Cargo.toml`: add `aifw-ids-ipc`
- `aifw-daemon/src/main.rs`: remove IDS engine init
- `aifw-daemon/Cargo.toml`: drop `aifw-ids` dep (kept transitively only if needed elsewhere)
- `aifw-setup/src/apply.rs:1576-1745` (`write_rcd_scripts`): fix daemon-pair pattern in aifw_daemon, aifw_api, rdhcpd; add aifw_ids; enable aifw_ids in /etc/rc.conf
- `freebsd/overlay/usr/local/etc/rc.d/trafficcop`: rdns-style daemon-pair pattern
- `freebsd/overlay/usr/local/etc/rc.d/rdhcpd`: same
- `freebsd/overlay/usr/local/etc/rc.d/rtime`: same
- `freebsd/manifest.json`: add aifw-ids binary
- `freebsd/deploy.sh`: build + deploy aifw-ids binary

### Sibling repo files (PR 8)
- `~/dev/trafficcop/src/single_instance.rs` (new) + main.rs integration
- `~/dev/rDNS/src/single_instance.rs` (new) + main.rs integration
- `~/dev/rDHCP/src/single_instance.rs` (new) + main.rs integration
- `~/dev/rTime/src/single_instance.rs` (new) + main.rs integration

---

# PR 1 — `aifw-common::single_instance` + apply to aifw-daemon and aifw-api

Self-contained. Defines the fcntl-based lockfile primitive and uses it in two existing binaries.

### Task 1.1: Add nix to aifw-common

**Files:**
- Modify: `aifw-common/Cargo.toml`
- Modify: `Cargo.toml` (root, workspace deps)

- [ ] **Step 1: Add nix to workspace deps**

In `Cargo.toml` (root) under `[workspace.dependencies]`, add:

```toml
nix = { version = "0.29", features = ["fs", "process"] }
```

- [ ] **Step 2: Use it from aifw-common**

In `aifw-common/Cargo.toml` under `[dependencies]`, add:

```toml
[target.'cfg(unix)'.dependencies]
nix = { workspace = true }
```

- [ ] **Step 3: Verify build**

Run: `cargo check -p aifw-common`
Expected: succeeds, zero warnings.

- [ ] **Step 4: Commit**

Bump root `Cargo.toml` version (5.72.3 → 5.72.4) and `aifw-ui/package.json` version. Then:

```bash
git add Cargo.toml aifw-common/Cargo.toml aifw-ui/package.json
git commit -m "deps: add nix to workspace + aifw-common (unix only)"
```

### Task 1.2: Write `single_instance` failing test

**Files:**
- Create: `aifw-common/src/single_instance.rs`
- Modify: `aifw-common/src/lib.rs`

- [ ] **Step 1: Add module declaration**

In `aifw-common/src/lib.rs`, add after the `permission` line (alphabetical):

```rust
#[cfg(unix)]
pub mod single_instance;
```

- [ ] **Step 2: Write failing tests**

Create `aifw-common/src/single_instance.rs` with:

```rust
//! File-locking-based singleton enforcement for long-running daemons.
//!
//! Each binary calls `acquire(name)` immediately after argument parsing and
//! before any heavy initialisation. The returned `InstanceLock` must be kept
//! alive for the lifetime of the process — drop it to release. The kernel
//! releases the lock automatically on process death (including SIGKILL),
//! so the lockfile never leaks across crashes.
//!
//! Mechanism: `open(O_CREAT|O_RDWR)` the lockfile, then `fcntl(F_SETLK,
//! F_WRLCK)` on the whole file. If another process holds the lock,
//! `F_SETLK` returns `EAGAIN`/`EACCES` immediately (no blocking). On
//! success, write the holder PID into the file as a diagnostic for
//! operators inspecting `/var/run`.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum InstanceLockError {
    #[error("another instance is already running (pid {0})")]
    AlreadyRunning(i32),
    #[error("could not open lockfile {path}: {source}")]
    OpenFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("lock syscall failed: {0}")]
    LockFailed(#[source] nix::Error),
}

/// Holds the lock for the lifetime of the process. Dropping releases it.
pub struct InstanceLock {
    _file: std::fs::File,
    path: PathBuf,
}

impl InstanceLock {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Acquire an exclusive lock on `/var/run/<name>.lock`. Returns
/// `AlreadyRunning(pid)` if held. The lock auto-releases on process death.
pub fn acquire(name: &str) -> Result<InstanceLock, InstanceLockError> {
    acquire_at(&PathBuf::from(format!("/var/run/{name}.lock")))
}

/// Like `acquire` but takes an explicit path (used by tests).
pub fn acquire_at(path: &Path) -> Result<InstanceLock, InstanceLockError> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode_if_creating(0o644)
        .open(path)
        .map_err(|source| InstanceLockError::OpenFailed {
            path: path.to_path_buf(),
            source,
        })?;

    let flock = nix::libc::flock {
        l_type: nix::libc::F_WRLCK as i16,
        l_whence: nix::libc::SEEK_SET as i16,
        l_start: 0,
        l_len: 0,
        l_pid: 0,
        #[cfg(target_os = "freebsd")]
        l_sysid: 0,
    };

    let fd = file.as_raw_fd();
    let res = unsafe { nix::libc::fcntl(fd, nix::libc::F_SETLK, &flock) };
    if res == -1 {
        let errno = nix::errno::Errno::last();
        if matches!(errno, nix::errno::Errno::EAGAIN | nix::errno::Errno::EACCES) {
            // Read the recorded PID for the error message.
            let mut buf = String::new();
            let _ = file.seek(SeekFrom::Start(0));
            let _ = file.read_to_string(&mut buf);
            let pid: i32 = buf.trim().parse().unwrap_or(0);
            return Err(InstanceLockError::AlreadyRunning(pid));
        }
        return Err(InstanceLockError::LockFailed(errno.into()));
    }

    // Write our PID for diagnostics. Truncate first so a smaller PID (e.g.
    // after a reboot) doesn't leave stale tail bytes.
    let _ = file.set_len(0);
    let _ = file.seek(SeekFrom::Start(0));
    let _ = writeln!(file, "{}", std::process::id());

    Ok(InstanceLock {
        _file: file,
        path: path.to_path_buf(),
    })
}

// `OpenOptionsExt::mode` only sets perms when creating, but we want a stable
// API regardless of whether the file already exists. This trait extension
// just folds the cfg.
trait OpenOptionsExt {
    fn mode_if_creating(&mut self, mode: u32) -> &mut Self;
}

impl OpenOptionsExt for OpenOptions {
    fn mode_if_creating(&mut self, mode: u32) -> &mut Self {
        use std::os::unix::fs::OpenOptionsExt as _;
        self.mode(mode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_lock(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("aifw-test-{}-{}.lock", name, std::process::id()))
    }

    #[test]
    fn first_acquire_succeeds() {
        let path = tmp_lock("first");
        let _ = std::fs::remove_file(&path);
        let lock = acquire_at(&path).expect("should acquire");
        assert_eq!(lock.path(), path.as_path());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn second_acquire_in_same_process_succeeds_after_drop() {
        // Same-process F_SETLK is reentrant in POSIX: a process can re-lock
        // a file it already holds. So we test drop semantics by acquiring,
        // dropping, and re-acquiring.
        let path = tmp_lock("drop");
        let _ = std::fs::remove_file(&path);
        let lock = acquire_at(&path).expect("first acquire");
        drop(lock);
        let _lock2 = acquire_at(&path).expect("re-acquire after drop");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn concurrent_acquire_from_child_fails() {
        // Spawn a child process that holds the lock, then try to acquire
        // from this process — must fail with AlreadyRunning.
        use std::process::{Command, Stdio};
        use std::time::Duration;

        let path = tmp_lock("conflict");
        let _ = std::fs::remove_file(&path);

        // The child sleeps for 2s while holding the lock.
        let child_program = format!(
            r#"
use aifw_common::single_instance::acquire_at;
use std::path::PathBuf;
use std::time::Duration;

fn main() {{
    let path = PathBuf::from("{}");
    let _lock = acquire_at(&path).expect("child acquire");
    std::thread::sleep(Duration::from_secs(2));
}}
"#,
            path.display()
        );

        // Easier: use a helper binary or a thread? POSIX advisory locks are
        // per-process, so a thread won't conflict. Use a helper binary that
        // we compile as part of the test crate? Simplest: skip the
        // cross-process check in unit tests; just verify the error path
        // by manually calling F_SETLK via a duplicated fd.
        //
        // Workaround: use fork() via nix to create a child that holds the
        // lock without exec'ing.
        use nix::unistd::{fork, ForkResult, sleep};

        match unsafe { fork() }.expect("fork") {
            ForkResult::Child => {
                let _lock = acquire_at(&path).expect("child acquire");
                sleep(2);
                std::process::exit(0);
            }
            ForkResult::Parent { child } => {
                // Give the child a moment to take the lock.
                std::thread::sleep(Duration::from_millis(200));
                let result = acquire_at(&path);
                let _ = nix::sys::wait::waitpid(child, None);
                let _ = std::fs::remove_file(&path);
                match result {
                    Err(InstanceLockError::AlreadyRunning(pid)) => {
                        assert!(pid > 0, "expected child pid in error");
                    }
                    other => panic!("expected AlreadyRunning, got {:?}", other),
                }
            }
        }
        // Suppress unused warning when this branch never runs; the
        // `child_program` string is kept above as documentation.
        let _ = child_program;
    }
}
```

- [ ] **Step 3: Run tests — they should fail to compile or fail**

Run: `cargo test -p aifw-common single_instance`
Expected: tests fail because either nix isn't wired or path issues — confirms the test harness sees them.

If they compile and pass on the first run (because the implementation IS the test file), proceed.

- [ ] **Step 4: Confirm tests pass**

Run: `cargo test -p aifw-common single_instance -- --nocapture`
Expected: 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add aifw-common/src/single_instance.rs aifw-common/src/lib.rs
git commit -m "feat(common): add single_instance fcntl lockfile helper"
```

### Task 1.3: Apply singleton to aifw-daemon

**Files:**
- Modify: `aifw-daemon/src/main.rs`
- Modify: `aifw-daemon/Cargo.toml` (already depends on aifw-common — no change needed; verify)

- [ ] **Step 1: Verify aifw-common is a dep**

Run: `grep aifw-common /home/mack/dev/AiFw/aifw-daemon/Cargo.toml`
Expected: line found. If not, add `aifw-common = { workspace = true }`.

- [ ] **Step 2: Add the lock acquisition**

Locate the `main` function in `aifw-daemon/src/main.rs`. Right after argument parsing (after `let args = Args::parse();` or equivalent — search for `Parser` use), add:

```rust
#[cfg(unix)]
let _instance_lock = match aifw_common::single_instance::acquire("aifw-daemon") {
    Ok(lock) => lock,
    Err(e) => {
        eprintln!("aifw-daemon: {e}");
        std::process::exit(1);
    }
};
```

Place this BEFORE pool creation, BEFORE tracing init — earliest possible point. The variable name `_instance_lock` keeps it alive for the rest of `main` without a clippy unused warning.

- [ ] **Step 3: cargo check**

Run: `cargo check -p aifw-daemon`
Expected: zero warnings.

- [ ] **Step 4: Commit**

Bump version (patch). Commit:

```bash
git add aifw-daemon/src/main.rs Cargo.toml aifw-ui/package.json
git commit -m "feat(daemon): refuse to start when another instance is running"
```

### Task 1.4: Apply singleton to aifw-api

**Files:**
- Modify: `aifw-api/src/main.rs`

- [ ] **Step 1: Add lock acquisition**

In `aifw-api/src/main.rs`, locate the `#[tokio::main] async fn main()` (or equivalent entry point — search for `Args::parse`). Right after argument parsing, add:

```rust
#[cfg(unix)]
let _instance_lock = match aifw_common::single_instance::acquire("aifw-api") {
    Ok(lock) => lock,
    Err(e) => {
        eprintln!("aifw-api: {e}");
        std::process::exit(1);
    }
};
```

- [ ] **Step 2: cargo check**

Run: `cargo check -p aifw-api`
Expected: zero warnings.

- [ ] **Step 3: Manual two-instance verification**

Run a brief local check to verify the lock works. Build:

`cargo build -p aifw-api --release`

In one terminal: `./target/release/aifw-api --db /tmp/test.db --listen 127.0.0.1:18080 --no-tls --insecure-tls`

In another: `./target/release/aifw-api --db /tmp/test.db --listen 127.0.0.1:18081 --no-tls --insecure-tls`

Expected: second invocation prints `aifw-api: another instance is already running (pid X)` and exits 1.

- [ ] **Step 4: Commit**

Bump version (patch). Commit:

```bash
git add aifw-api/src/main.rs Cargo.toml aifw-ui/package.json
git commit -m "feat(api): refuse to start when another instance is running"
```

---

# PR 2 — rc.d daemon-pair fix (5 scripts overlay + 4 in apply.rs)

Self-contained. No code-binary changes; only shell scripts and the Rust string literals that emit them.

### Task 2.1: Define the canonical pattern

The pattern (validated against `freebsd/overlay/usr/local/etc/rc.d/rdns`):

```sh
#!/bin/sh
#
# PROVIDE: <name>
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="<name>"
rcvar="<name>_enable"

load_rc_config $name

: ${<name>_enable:="NO"}
: ${<name>_pidfile:="/var/run/<name>.pid"}
: ${<name>_supervisor_pidfile:="/var/run/<name>-supervisor.pid"}

# Track the daemon(8) supervisor so `service <name> stop` kills both it and
# the child. Using -p alone (child pidfile) leaves the supervisor running,
# and -R 5 respawns the child — accumulating orphans on every restart.
pidfile="${<name>_supervisor_pidfile}"
procname="/usr/sbin/daemon"
<name>_binary="<binary path>"
command="/usr/sbin/daemon"
command_args="-f -p ${<name>_pidfile} -P ${<name>_supervisor_pidfile} -R 5 -S -T <name> -o /var/log/<name>/<name>.log <user-flag-if-needed> ${<name>_binary} <binary args>"

start_precmd="<name>_precmd"
stop_postcmd="<name>_poststop"

<name>_precmd()
{
    /bin/mkdir -p /var/run/<name> /var/log/<name>
    # Reap orphan supervisor + child pairs left by previous buggy restarts.
    /usr/bin/pkill -f "daemon:.*<basename of binary>" 2>/dev/null
    /usr/bin/pkill -x "<basename of binary>" 2>/dev/null
    /bin/rm -f ${<name>_pidfile} ${<name>_supervisor_pidfile}
    # Service-specific setup goes here (perms, log file pre-creation, etc.)
}

<name>_poststop()
{
    /bin/rm -f ${<name>_pidfile} ${<name>_supervisor_pidfile}
}

run_rc_command "$1"
```

Service-specific notes:
- `aifw_daemon`, `aifw_api`, `aifw_ids`, `trafficcop` need `-u aifw` (drop privileges).
- `rdhcpd` runs as root.
- `rtime` runs as root.

### Task 2.2: Replace `freebsd/overlay/usr/local/etc/rc.d/trafficcop`

**Files:**
- Modify: `freebsd/overlay/usr/local/etc/rc.d/trafficcop`

- [ ] **Step 1: Replace the file with the canonical pattern**

Full contents:

```sh
#!/bin/sh
#
# PROVIDE: trafficcop
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="trafficcop"
rcvar="trafficcop_enable"

load_rc_config $name

: ${trafficcop_enable:="NO"}
: ${trafficcop_config:="/usr/local/etc/trafficcop/config.yaml"}
: ${trafficcop_pidfile:="/var/run/trafficcop/trafficcop.pid"}
: ${trafficcop_supervisor_pidfile:="/var/run/trafficcop/trafficcop-supervisor.pid"}

pidfile="${trafficcop_supervisor_pidfile}"
procname="/usr/sbin/daemon"
trafficcop_binary="/usr/local/sbin/trafficcop"
command="/usr/sbin/daemon"
command_args="-f -p ${trafficcop_pidfile} -P ${trafficcop_supervisor_pidfile} -R 5 -S -T trafficcop -o /var/log/trafficcop/trafficcop.log -u aifw ${trafficcop_binary} -c ${trafficcop_config}"

start_precmd="trafficcop_precmd"
stop_postcmd="trafficcop_poststop"

trafficcop_precmd()
{
    /bin/mkdir -p /var/run/trafficcop /var/log/trafficcop
    /usr/sbin/chown aifw:aifw /var/log/trafficcop /var/run/trafficcop
    /usr/bin/pkill -f "daemon:.*trafficcop" 2>/dev/null
    /usr/bin/pkill -x trafficcop 2>/dev/null
    /bin/rm -f ${trafficcop_pidfile} ${trafficcop_supervisor_pidfile}

    if [ -f ${trafficcop_config} ]; then
        if ! ${trafficcop_binary} -c ${trafficcop_config} --validate >/dev/null 2>&1; then
            echo "ERROR: trafficcop config validation failed"
            return 1
        fi
    fi
}

trafficcop_poststop()
{
    /bin/rm -f ${trafficcop_pidfile} ${trafficcop_supervisor_pidfile}
}

run_rc_command "$1"
```

- [ ] **Step 2: Mark executable**

Run: `chmod +x /home/mack/dev/AiFw/freebsd/overlay/usr/local/etc/rc.d/trafficcop`

- [ ] **Step 3: Commit (we'll commit all overlay changes together at end of PR 2)**

Skip until task 2.5.

### Task 2.3: Replace `freebsd/overlay/usr/local/etc/rc.d/rdhcpd`

**Files:**
- Modify: `freebsd/overlay/usr/local/etc/rc.d/rdhcpd`

- [ ] **Step 1: Replace with canonical pattern**

```sh
#!/bin/sh
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
```

- [ ] **Step 2: chmod +x**

Run: `chmod +x /home/mack/dev/AiFw/freebsd/overlay/usr/local/etc/rc.d/rdhcpd`

### Task 2.4: Replace `freebsd/overlay/usr/local/etc/rc.d/rtime`

**Files:**
- Modify: `freebsd/overlay/usr/local/etc/rc.d/rtime`

- [ ] **Step 1: Replace contents**

```sh
#!/bin/sh
#
# PROVIDE: rtime
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="rtime"
rcvar="rtime_enable"

load_rc_config $name

: ${rtime_enable:="NO"}
: ${rtime_config:="/usr/local/etc/rtime/rtime.toml"}
: ${rtime_pidfile:="/var/run/rtime/rtime.pid"}
: ${rtime_supervisor_pidfile:="/var/run/rtime/rtime-supervisor.pid"}

pidfile="${rtime_supervisor_pidfile}"
procname="/usr/sbin/daemon"
rtime_binary="/usr/local/sbin/rtime"
command="/usr/sbin/daemon"
command_args="-f -p ${rtime_pidfile} -P ${rtime_supervisor_pidfile} -R 5 -S -T rtime -o /var/log/rtime/rtime.log ${rtime_binary} --config ${rtime_config}"

start_precmd="rtime_precmd"
stop_postcmd="rtime_poststop"

rtime_precmd()
{
    /bin/mkdir -p /var/run/rtime /var/log/rtime /usr/local/etc/rtime
    /usr/bin/pkill -f "daemon:.*rtime" 2>/dev/null
    /usr/bin/pkill -x rtime 2>/dev/null
    /bin/rm -f ${rtime_pidfile} ${rtime_supervisor_pidfile}
}

rtime_poststop()
{
    /bin/rm -f ${rtime_pidfile} ${rtime_supervisor_pidfile}
}

run_rc_command "$1"
```

- [ ] **Step 2: chmod +x**

Run: `chmod +x /home/mack/dev/AiFw/freebsd/overlay/usr/local/etc/rc.d/rtime`

### Task 2.5: Update `aifw-setup/src/apply.rs::write_rcd_scripts`

**Files:**
- Modify: `aifw-setup/src/apply.rs:1576-1745`

- [ ] **Step 1: Replace the three script string literals**

Replace the entire `write_rcd_scripts` function (currently lines 1576–1745) with this new version. Note:
1. Three script bodies (`daemon_script`, `api_script`, `rdhcpd_script`) updated to canonical pattern.
2. New `ids_script` added.
3. New `write_file` calls and `set_permissions` for `aifw_ids`.
4. Each fresh-install `/etc/rc.conf` line is **the responsibility of `enable_rc_services` elsewhere in this file**, not `write_rcd_scripts`. Find that function and add `aifw_ids` to its enable list.

Replacement function body (full):

```rust
/// Write FreeBSD rc.d service scripts. Pattern follows `rdns` — supervisor
/// pidfile + child pidfile + start_precmd reaping orphans.
fn write_rcd_scripts(config: &SetupConfig) -> Result<(), String> {
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

pidfile="${{aifw_daemon_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_daemon_binary="/usr/local/sbin/aifw-daemon"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_daemon_pidfile}} -P ${{aifw_daemon_supervisor_pidfile}} -R 5 -S -T aifw_daemon -o /var/log/aifw/daemon.log -u aifw ${{aifw_daemon_binary}} --db {db} --log-level info"

start_precmd="aifw_daemon_precmd"
stop_postcmd="aifw_daemon_poststop"

aifw_daemon_precmd()
{{
    /bin/mkdir -p /var/log/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-daemon" 2>/dev/null
    /usr/bin/pkill -x aifw-daemon 2>/dev/null
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
stop_postcmd="aifw_api_poststop"

aifw_api_precmd()
{{
    /bin/mkdir -p /var/log/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-api" 2>/dev/null
    /usr/bin/pkill -x aifw-api 2>/dev/null
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
stop_postcmd="aifw_ids_poststop"

aifw_ids_precmd()
{{
    /bin/mkdir -p /var/log/aifw /var/run/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw /var/run/aifw
    /bin/chmod 0750 /var/run/aifw
    /usr/bin/pkill -f "daemon:.*aifw-ids" 2>/dev/null
    /usr/bin/pkill -x aifw-ids 2>/dev/null
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}} /var/run/aifw/ids.sock
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

    write_file(&format!("{rcd_dir}/aifw_daemon"), &daemon_script)?;
    write_file(&format!("{rcd_dir}/aifw_api"), &api_script)?;
    write_file(&format!("{rcd_dir}/aifw_ids"), &ids_script)?;
    write_file(&format!("{rcd_dir}/rdhcpd"), rdhcpd_script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_daemon"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_api"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_ids"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/rdhcpd"), perms);
    }

    Ok(())
}
```

- [ ] **Step 2: Add `aifw_ids_enable="YES"` to rc.conf writer**

Search apply.rs for where `aifw_daemon_enable` and `aifw_api_enable` are added to `/etc/rc.conf`. The function is likely called `enable_rc_services` or `write_rc_conf`. Add a sibling line for `aifw_ids_enable`.

Run: `grep -n "aifw_daemon_enable\|aifw_api_enable" /home/mack/dev/AiFw/aifw-setup/src/apply.rs` to find it. Add `aifw_ids_enable="YES"` right after `aifw_api_enable="YES"`.

- [ ] **Step 3: cargo check**

Run: `cargo check -p aifw-setup`
Expected: zero warnings.

- [ ] **Step 4: Run aifw-setup tests if any**

Run: `cargo test -p aifw-setup`
Expected: all green.

### Task 2.6: Commit PR 2

- [ ] **Step 1: Bump version**

`Cargo.toml` minor (5.72.x → 5.73.0) since this fixes a customer-visible bug class. Bump `aifw-ui/package.json` to match.

- [ ] **Step 2: Commit**

```bash
git add freebsd/overlay/usr/local/etc/rc.d/trafficcop \
        freebsd/overlay/usr/local/etc/rc.d/rdhcpd \
        freebsd/overlay/usr/local/etc/rc.d/rtime \
        aifw-setup/src/apply.rs \
        Cargo.toml aifw-ui/package.json
git commit -m "fix(rc.d): track daemon(8) supervisor pidfile to stop orphans on restart"
```

---

# PR 3 — `aifw-ids-ipc` crate (types + framing + client + server skeleton)

Self-contained. Adds wire types and the framing primitives. Has no consumers yet, but is fully unit-testable.

### Task 3.1: Create the crate

**Files:**
- Create: `aifw-ids-ipc/Cargo.toml`
- Create: `aifw-ids-ipc/src/lib.rs`
- Modify: `Cargo.toml` (root, workspace members)

- [ ] **Step 1: Add crate to workspace**

In root `Cargo.toml`, in `[workspace] members =`, add `"aifw-ids-ipc",` (alphabetically before `aifw-ids-bin` once that exists; for now, between `aifw-ids` and `aifw-metrics`):

```toml
members = [
    "aifw-common",
    "aifw-pf",
    "aifw-core",
    "aifw-conntrack",
    "aifw-plugins",
    "aifw-ai",
    "aifw-ids",
    "aifw-ids-ipc",
    "aifw-metrics",
    "aifw-api",
    "aifw-tui",
    "aifw-daemon",
    "aifw-cli",
    "aifw-setup",
]
```

Add to `[workspace.dependencies]`:

```toml
aifw-ids-ipc = { path = "aifw-ids-ipc" }
```

- [ ] **Step 2: Create `aifw-ids-ipc/Cargo.toml`**

```toml
[package]
name = "aifw-ids-ipc"
version.workspace = true
edition.workspace = true
license.workspace = true

[dependencies]
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true }
thiserror = { workspace = true }
chrono = { workspace = true }
aifw-common = { workspace = true }
tracing = { workspace = true }
async-trait = { workspace = true }

[dev-dependencies]
tokio = { workspace = true, features = ["test-util", "macros"] }
```

- [ ] **Step 3: Create `aifw-ids-ipc/src/lib.rs`**

```rust
//! IPC protocol between aifw-api and aifw-ids.
//!
//! Wire format: 4-byte big-endian length prefix + UTF-8 JSON body.
//! Connection-per-call (no streaming yet — keeps the server stateless).
//!
//! `proto` defines the on-wire request/response shapes. `framing` reads
//! and writes the length-prefixed envelopes. `client` provides a thin
//! Unix-socket client with TTL caching of read responses. `server` is the
//! glue that turns an `IpcHandler` impl into a request loop.

pub mod client;
pub mod framing;
pub mod proto;
pub mod server;

pub use client::{IdsClient, IdsClientError};
pub use proto::{IpcRequest, IpcResponse};
pub use server::IpcHandler;
```

- [ ] **Step 4: cargo check**

Run: `cargo check -p aifw-ids-ipc`
Expected: succeeds (will fail because the modules don't exist yet — proceed to next task).

### Task 3.2: Wire types in `proto.rs`

**Files:**
- Create: `aifw-ids-ipc/src/proto.rs`

- [ ] **Step 1: Write the type definitions**

```rust
//! Wire types for the aifw-ids IPC protocol.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    GetConfig,
    SetConfig { config: aifw_common::ids::IdsConfig },
    Reload,
    GetStats,
    ListRulesets,
    GetRule { id: String },
    SetRule { id: String, enabled: bool },
    TailAlerts { count: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok,
    Config(aifw_common::ids::IdsConfig),
    Stats(IdsStats),
    Rulesets(Vec<RulesetSummary>),
    Rule(Option<RuleSummary>),
    Alerts(Vec<AlertSummary>),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdsStats {
    pub mode: String,
    pub running: bool,
    pub rules_loaded: u32,
    pub flow_count: u64,
    pub flow_reassembly_bytes: u64,
    pub packets_inspected: u64,
    pub alerts_total: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulesetSummary {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub rule_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSummary {
    pub id: String,
    pub sid: u32,
    pub msg: String,
    pub action: String,
    pub enabled: bool,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertSummary {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sid: u32,
    pub msg: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = IpcRequest::GetStats;
        let s = serde_json::to_string(&r).unwrap();
        let back: IpcRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, IpcRequest::GetStats));
    }

    #[test]
    fn stats_round_trips() {
        let stats = IdsStats {
            mode: "alert".to_string(),
            running: true,
            rules_loaded: 47755,
            flow_count: 123,
            flow_reassembly_bytes: 4096,
            packets_inspected: 100,
            alerts_total: 5,
            uptime_secs: 600,
        };
        let s = serde_json::to_string(&stats).unwrap();
        let back: IdsStats = serde_json::from_str(&s).unwrap();
        assert_eq!(stats, back);
    }
}
```

- [ ] **Step 2: cargo test**

Run: `cargo test -p aifw-ids-ipc proto`
Expected: 2 tests pass.

### Task 3.3: Length-prefixed framing

**Files:**
- Create: `aifw-ids-ipc/src/framing.rs`

- [ ] **Step 1: Implement framing**

```rust
//! Length-prefixed JSON framing over an async stream.
//!
//! Format: 4-byte big-endian u32 length, then exactly that many UTF-8
//! bytes of JSON. The 4 GiB max body is enforced; we additionally cap to
//! 16 MiB to defend against accidental huge requests.

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes (max {})", MAX_FRAME_BYTES)]
    TooLarge(u32),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn read_frame<T, R>(reader: &mut R) -> Result<T, FrameError>
where
    T: DeserializeOwned,
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if (len as usize) > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    let msg = serde_json::from_slice(&buf)?;
    Ok(msg)
}

pub async fn write_frame<T, W>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    T: Serialize,
    W: AsyncWriteExt + Unpin,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(body.len() as u32));
    }
    let len = (body.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IpcRequest;
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trip_request() {
        let (mut a, mut b) = duplex(64 * 1024);
        let sent = IpcRequest::GetStats;
        write_frame(&mut a, &sent).await.unwrap();
        let received: IpcRequest = read_frame(&mut b).await.unwrap();
        assert!(matches!(received, IpcRequest::GetStats));
    }

    #[tokio::test]
    async fn rejects_oversized() {
        let (mut a, mut b) = duplex(64 * 1024);
        // Hand-craft a 4-byte length prefix that claims 100 MiB.
        let len: u32 = 100 * 1024 * 1024;
        a.write_all(&len.to_be_bytes()).await.unwrap();
        let result: Result<IpcRequest, _> = read_frame(&mut b).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }
}
```

- [ ] **Step 2: cargo test**

Run: `cargo test -p aifw-ids-ipc framing`
Expected: 2 tests pass.

### Task 3.4: Server trait and request loop

**Files:**
- Create: `aifw-ids-ipc/src/server.rs`

- [ ] **Step 1: Implement server**

```rust
//! Server-side loop: accept connections, read one request, call handler,
//! write one response, close. No persistent connection state.

use crate::framing::{FrameError, read_frame, write_frame};
use crate::proto::{IpcRequest, IpcResponse};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::UnixListener;

#[async_trait]
pub trait IpcHandler: Send + Sync + 'static {
    async fn handle(&self, req: IpcRequest) -> IpcResponse;
}

/// Run the accept loop. Blocks until `listener` errors. Each accepted
/// connection is served on its own tokio task.
pub async fn serve<H: IpcHandler>(listener: UnixListener, handler: Arc<H>) {
    loop {
        let (mut stream, _addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let req: IpcRequest = match read_frame(&mut stream).await {
                Ok(r) => r,
                Err(FrameError::Io(_)) => return, // client closed
                Err(e) => {
                    let _ = write_frame(&mut stream, &IpcResponse::Error(e.to_string())).await;
                    return;
                }
            };
            let resp = handler.handle(req).await;
            let _ = write_frame(&mut stream, &resp).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IdsStats;
    use std::path::PathBuf;
    use tokio::net::UnixStream;

    struct StubHandler;

    #[async_trait]
    impl IpcHandler for StubHandler {
        async fn handle(&self, req: IpcRequest) -> IpcResponse {
            match req {
                IpcRequest::GetStats => IpcResponse::Stats(IdsStats {
                    mode: "alert".into(),
                    running: true,
                    rules_loaded: 1,
                    flow_count: 0,
                    flow_reassembly_bytes: 0,
                    packets_inspected: 0,
                    alerts_total: 0,
                    uptime_secs: 1,
                }),
                _ => IpcResponse::Error("unsupported".into()),
            }
        }
    }

    #[tokio::test]
    async fn serves_one_request() {
        let path = std::env::temp_dir().join(format!("aifw-ipc-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(serve(listener, Arc::new(StubHandler)));

        let mut client = UnixStream::connect(&path).await.unwrap();
        write_frame(&mut client, &IpcRequest::GetStats).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert!(matches!(resp, IpcResponse::Stats(_)));

        server.abort();
        let _ = std::fs::remove_file(PathBuf::from(&path));
    }
}
```

- [ ] **Step 2: cargo test**

Run: `cargo test -p aifw-ids-ipc server`
Expected: 1 test passes.

### Task 3.5: Client with TTL cache

**Files:**
- Create: `aifw-ids-ipc/src/client.rs`

- [ ] **Step 1: Implement client**

```rust
//! Async client for the aifw-ids IPC.
//!
//! For read methods the client maintains a small TTL cache so that hot
//! API endpoints (dashboard refresh) don't hammer the socket. Write
//! methods (`SetConfig`, `Reload`, `SetRule`) invalidate cached entries.

use crate::framing::{read_frame, write_frame};
use crate::proto::{AlertSummary, IdsStats, IpcRequest, IpcResponse, RuleSummary, RulesetSummary};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum IdsClientError {
    #[error("ids service unavailable: {0}")]
    Unavailable(String),
    #[error("ids service timeout")]
    Timeout,
    #[error("ids server error: {0}")]
    Server(String),
    #[error("framing error: {0}")]
    Framing(#[from] crate::framing::FrameError),
    #[error("unexpected response shape")]
    UnexpectedResponse,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct CacheEntry<T: Clone> {
    value: T,
    expires_at: Instant,
}

#[derive(Default)]
struct Cache {
    config: Option<CacheEntry<aifw_common::ids::IdsConfig>>,
    stats: Option<CacheEntry<IdsStats>>,
    rulesets: Option<CacheEntry<Vec<RulesetSummary>>>,
    rules: std::collections::HashMap<String, CacheEntry<Option<RuleSummary>>>,
    alerts_tail: Option<CacheEntry<Vec<AlertSummary>>>,
}

pub struct IdsClient {
    socket_path: PathBuf,
    cache: Arc<Mutex<Cache>>,
}

impl IdsClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            cache: Arc::new(Mutex::new(Cache::default())),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    async fn raw_call(&self, req: IpcRequest) -> Result<IpcResponse, IdsClientError> {
        let connect = UnixStream::connect(&self.socket_path);
        let mut stream = match tokio::time::timeout(REQUEST_TIMEOUT, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(IdsClientError::Unavailable(e.to_string())),
            Err(_) => return Err(IdsClientError::Timeout),
        };
        let io = async {
            write_frame(&mut stream, &req).await?;
            let resp: IpcResponse = read_frame(&mut stream).await?;
            Ok::<_, IdsClientError>(resp)
        };
        match tokio::time::timeout(REQUEST_TIMEOUT, io).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(IdsClientError::Timeout),
        }
    }

    pub async fn get_config(&self) -> Result<aifw_common::ids::IdsConfig, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.config
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::GetConfig).await?;
        match resp {
            IpcResponse::Config(c) => {
                let mut cache = self.cache.lock().await;
                cache.config = Some(CacheEntry {
                    value: c.clone(),
                    expires_at: Instant::now() + Duration::from_secs(5),
                });
                Ok(c)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn set_config(&self, config: aifw_common::ids::IdsConfig) -> Result<(), IdsClientError> {
        let resp = self.raw_call(IpcRequest::SetConfig { config }).await?;
        match resp {
            IpcResponse::Ok => {
                self.invalidate_all().await;
                Ok(())
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn reload(&self) -> Result<(), IdsClientError> {
        let resp = self.raw_call(IpcRequest::Reload).await?;
        self.invalidate_all().await;
        match resp {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn get_stats(&self) -> Result<IdsStats, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.stats
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::GetStats).await?;
        match resp {
            IpcResponse::Stats(s) => {
                let mut cache = self.cache.lock().await;
                cache.stats = Some(CacheEntry {
                    value: s.clone(),
                    expires_at: Instant::now() + Duration::from_secs(2),
                });
                Ok(s)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn list_rulesets(&self) -> Result<Vec<RulesetSummary>, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.rulesets
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::ListRulesets).await?;
        match resp {
            IpcResponse::Rulesets(rs) => {
                let mut cache = self.cache.lock().await;
                cache.rulesets = Some(CacheEntry {
                    value: rs.clone(),
                    expires_at: Instant::now() + Duration::from_secs(30),
                });
                Ok(rs)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn get_rule(&self, id: &str) -> Result<Option<RuleSummary>, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.rules.get(id)
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::GetRule { id: id.to_string() }).await?;
        match resp {
            IpcResponse::Rule(r) => {
                let mut cache = self.cache.lock().await;
                cache.rules.insert(
                    id.to_string(),
                    CacheEntry {
                        value: r.clone(),
                        expires_at: Instant::now() + Duration::from_secs(60),
                    },
                );
                Ok(r)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn set_rule(&self, id: &str, enabled: bool) -> Result<(), IdsClientError> {
        let resp = self
            .raw_call(IpcRequest::SetRule {
                id: id.to_string(),
                enabled,
            })
            .await?;
        match resp {
            IpcResponse::Ok => {
                let mut cache = self.cache.lock().await;
                cache.rules.remove(id);
                cache.rulesets = None;
                Ok(())
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn tail_alerts(&self, count: u32) -> Result<Vec<AlertSummary>, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.alerts_tail
                && entry.expires_at > Instant::now()
                && entry.value.len() >= count as usize
            {
                return Ok(entry.value.iter().take(count as usize).cloned().collect());
            }
        }
        let resp = self.raw_call(IpcRequest::TailAlerts { count }).await?;
        match resp {
            IpcResponse::Alerts(a) => {
                let mut cache = self.cache.lock().await;
                cache.alerts_tail = Some(CacheEntry {
                    value: a.clone(),
                    expires_at: Instant::now() + Duration::from_secs(1),
                });
                Ok(a)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    async fn invalidate_all(&self) {
        let mut cache = self.cache.lock().await;
        cache.config = None;
        cache.stats = None;
        cache.rulesets = None;
        cache.rules.clear();
        cache.alerts_tail = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IpcResponse;
    use crate::server::{IpcHandler, serve};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::UnixListener;

    struct CountingHandler {
        count: Arc<AtomicU32>,
    }

    #[async_trait]
    impl IpcHandler for CountingHandler {
        async fn handle(&self, req: IpcRequest) -> IpcResponse {
            self.count.fetch_add(1, Ordering::SeqCst);
            match req {
                IpcRequest::GetStats => IpcResponse::Stats(IdsStats {
                    mode: "alert".into(),
                    running: true,
                    rules_loaded: 1,
                    flow_count: 0,
                    flow_reassembly_bytes: 0,
                    packets_inspected: 0,
                    alerts_total: 0,
                    uptime_secs: 1,
                }),
                _ => IpcResponse::Error("unsupported".into()),
            }
        }
    }

    #[tokio::test]
    async fn cache_avoids_redundant_calls() {
        let path = std::env::temp_dir().join(format!("aifw-cli-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(CountingHandler {
            count: count.clone(),
        });
        let server = tokio::spawn(serve(listener, handler));

        let client = IdsClient::new(&path);
        let _ = client.get_stats().await.unwrap();
        let _ = client.get_stats().await.unwrap();
        let _ = client.get_stats().await.unwrap();

        // The 2-second TTL should have absorbed the second and third call.
        assert_eq!(count.load(Ordering::SeqCst), 1);

        server.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn unavailable_when_socket_missing() {
        let path = std::env::temp_dir().join(format!("aifw-noexist-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let client = IdsClient::new(&path);
        let result = client.get_stats().await;
        assert!(matches!(result, Err(IdsClientError::Unavailable(_))));
    }
}
```

- [ ] **Step 2: cargo test**

Run: `cargo test -p aifw-ids-ipc client`
Expected: 2 tests pass.

### Task 3.6: Commit PR 3

- [ ] **Step 1: Bump version (patch)**

- [ ] **Step 2: Commit**

```bash
git add Cargo.toml aifw-ids-ipc aifw-ui/package.json
git commit -m "feat(ids-ipc): wire types, framing, client+TTL cache, server skeleton"
```

---

# PR 4 — `aifw-ids-bin` daemon (binary, IPC server, lockfile, rc.d)

Creates the new binary that owns IDS state. Has no consumers yet (PR 5 wires aifw-api to it).

### Task 4.1: Create the crate

**Files:**
- Create: `aifw-ids-bin/Cargo.toml`
- Create: `aifw-ids-bin/src/main.rs`
- Create: `aifw-ids-bin/src/handler.rs`
- Modify: `Cargo.toml` (root, members)

- [ ] **Step 1: Add to workspace members**

In root `Cargo.toml`:

```toml
members = [
    ...
    "aifw-ids",
    "aifw-ids-bin",
    "aifw-ids-ipc",
    ...
]
```

- [ ] **Step 2: Create `aifw-ids-bin/Cargo.toml`**

```toml
[package]
name = "aifw-ids-bin"
version.workspace = true
edition.workspace = true
license.workspace = true

[[bin]]
name = "aifw-ids"
path = "src/main.rs"

[dependencies]
aifw-common = { workspace = true }
aifw-ids = { workspace = true }
aifw-ids-ipc = { workspace = true }
aifw-pf = { workspace = true }
tokio = { workspace = true }
sqlx = { workspace = true }
clap = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
async-trait = { workspace = true }
chrono = { workspace = true }
anyhow = "1"
```

- [ ] **Step 3: Create `aifw-ids-bin/src/handler.rs`**

```rust
//! Implements `IpcHandler` by delegating to an `IdsEngine`.

use aifw_ids::IdsEngine;
use aifw_ids_ipc::proto::{
    AlertSummary, IdsStats, IpcRequest, IpcResponse, RuleSummary, RulesetSummary,
};
use aifw_ids_ipc::server::IpcHandler;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Instant;

pub struct EngineHandler {
    engine: Arc<IdsEngine>,
    started_at: Instant,
}

impl EngineHandler {
    pub fn new(engine: Arc<IdsEngine>) -> Self {
        Self {
            engine,
            started_at: Instant::now(),
        }
    }
}

#[async_trait]
impl IpcHandler for EngineHandler {
    async fn handle(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::GetConfig => match self.engine.load_config().await {
                Ok(c) => IpcResponse::Config(c),
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::SetConfig { config } => match self.engine.save_config(&config).await {
                Ok(()) => IpcResponse::Ok,
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::Reload => {
                let mgr = aifw_ids::rules::manager::RulesetManager::new(self.engine.pool().clone());
                match mgr.compile_rules(self.engine.rule_db()).await {
                    Ok(_) => IpcResponse::Ok,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetStats => {
                let cfg = self.engine.load_config().await.ok();
                let mode = cfg
                    .as_ref()
                    .map(|c| format!("{:?}", c.mode).to_lowercase())
                    .unwrap_or_else(|| "unknown".into());
                let rules_loaded = self.engine.rule_db().rule_count() as u32;
                let flow_count = self
                    .engine
                    .flow_table()
                    .map(|t| t.len() as u64)
                    .unwrap_or(0);
                let flow_reassembly_bytes = self
                    .engine
                    .flow_table()
                    .map(|t| t.reassembly_bytes() as u64)
                    .unwrap_or(0);
                IpcResponse::Stats(IdsStats {
                    mode,
                    running: self.engine.is_running(),
                    rules_loaded,
                    flow_count,
                    flow_reassembly_bytes,
                    packets_inspected: self.engine.packets_inspected(),
                    alerts_total: self.engine.alerts_total().await,
                    uptime_secs: self.started_at.elapsed().as_secs(),
                })
            }
            IpcRequest::ListRulesets => {
                match aifw_ids::rules::manager::RulesetManager::new(self.engine.pool().clone())
                    .list_rulesets()
                    .await
                {
                    Ok(rs) => IpcResponse::Rulesets(
                        rs.into_iter()
                            .map(|r| RulesetSummary {
                                id: r.id,
                                name: r.name,
                                enabled: r.enabled,
                                rule_count: r.rule_count as u32,
                            })
                            .collect(),
                    ),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetRule { id } => match self.engine.get_rule(&id).await {
                Ok(Some(r)) => IpcResponse::Rule(Some(RuleSummary {
                    id: r.id,
                    sid: r.sid,
                    msg: r.msg,
                    action: r.action,
                    enabled: r.enabled,
                    raw: r.raw,
                })),
                Ok(None) => IpcResponse::Rule(None),
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::SetRule { id, enabled } => {
                match self.engine.set_rule_enabled(&id, enabled).await {
                    Ok(()) => IpcResponse::Ok,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::TailAlerts { count } => {
                let alerts = self.engine.alert_buffer().tail(count as usize).await;
                IpcResponse::Alerts(
                    alerts
                        .into_iter()
                        .map(|a| AlertSummary {
                            id: a.id,
                            timestamp: a.timestamp,
                            sid: a.sid,
                            msg: a.msg,
                            src_ip: a.src_ip,
                            dst_ip: a.dst_ip,
                            src_port: a.src_port,
                            dst_port: a.dst_port,
                            protocol: a.protocol,
                        })
                        .collect(),
                )
            }
        }
    }
}
```

NOTE: this handler relies on methods that need to be added to `IdsEngine` (`flow_table()`, `is_running()`, `packets_inspected()`, `alerts_total()`, `get_rule()`, `set_rule_enabled()`, `alert_buffer()`). Either:
- Verify they already exist (run `grep -rn "impl IdsEngine" aifw-ids/src/`).
- Or add small accessor methods exposing existing internal counters.

The agent executing this step should `cargo check -p aifw-ids-bin`, identify missing methods, and add the minimal accessors to `aifw-ids/src/lib.rs` to make them public.

- [ ] **Step 4: Create `aifw-ids-bin/src/main.rs`**

```rust
//! aifw-ids — owns the IDS engine, BPF capture, FlowTable, and the IPC
//! server that aifw-api queries.

mod handler;

use aifw_common::single_instance::acquire;
use aifw_ids::IdsEngine;
use aifw_ids_ipc::server::serve;
use anyhow::Context;
use clap::Parser;
use handler::EngineHandler;
use sqlx::sqlite::SqlitePoolOptions;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::UnixListener;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
#[command(name = "aifw-ids", about = "AiFw IDS daemon")]
struct Args {
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    #[arg(long, default_value = "/var/run/aifw/ids.sock")]
    socket: PathBuf,

    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    #[cfg(unix)]
    let _instance_lock = match acquire("aifw-ids") {
        Ok(lock) => lock,
        Err(e) => {
            eprintln!("aifw-ids: {e}");
            std::process::exit(1);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&format!("sqlite://{}", args.db.display()))
        .await
        .context("connect sqlite")?;

    IdsEngine::migrate(&pool)
        .await
        .map_err(|e| anyhow::anyhow!("migrate: {e}"))?;

    let pf = aifw_pf::create_backend();
    let engine = Arc::new(
        IdsEngine::new(pool, pf)
            .await
            .map_err(|e| anyhow::anyhow!("init engine: {e}"))?,
    );

    // Compile and start if mode != Disabled.
    if let Ok(cfg) = engine.load_config().await
        && cfg.mode != aifw_common::ids::IdsMode::Disabled
    {
        let mgr = aifw_ids::rules::manager::RulesetManager::new(engine.pool().clone());
        if let Err(e) = mgr.compile_rules(engine.rule_db()).await {
            tracing::warn!(error = %e, "rule compile failed");
        }
        if let Err(e) = engine.start().await {
            tracing::warn!(error = %e, "engine start failed");
        }
    }

    // Bind the IPC socket. Remove stale socket file if present.
    let _ = std::fs::remove_file(&args.socket);
    if let Some(parent) = args.socket.parent() {
        std::fs::create_dir_all(parent).context("create socket dir")?;
    }
    let listener = UnixListener::bind(&args.socket).context("bind unix socket")?;

    // Permissions: root:aifw 0660. The rc.d script chowns the parent dir;
    // we just chmod the socket inode.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o660);
        let _ = std::fs::set_permissions(&args.socket, perms);
    }

    tracing::info!(socket = %args.socket.display(), "aifw-ids serving");

    let handler = Arc::new(EngineHandler::new(engine.clone()));
    let server_task = tokio::spawn(serve(listener, handler));

    // Wait for SIGTERM/SIGINT for clean shutdown.
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM"),
        _ = sigint.recv() => tracing::info!("SIGINT"),
    }

    server_task.abort();
    let _ = std::fs::remove_file(&args.socket);
    Ok(())
}
```

- [ ] **Step 5: cargo check**

Run: `cargo check -p aifw-ids-bin`

If methods are missing on `IdsEngine`, add them. Specifically check that the following accessors exist on `aifw_ids::IdsEngine`:
- `flow_table() -> Option<&FlowTable>` or similar
- `is_running() -> bool`
- `packets_inspected() -> u64`
- `alerts_total() -> u64` (async — may need to query DB or alert buffer)
- `alert_buffer() -> &AlertBuffer`
- `get_rule(id: &str) -> Result<Option<RuleRow>>`
- `set_rule_enabled(id: &str, enabled: bool) -> Result<()>`
- `pool() -> &SqlitePool` (likely already exists)
- `rule_db() -> &Arc<RuleDatabase>` (likely already exists)
- `save_config(&IdsConfig) -> Result<()>`

Add minimal accessors as needed in `aifw-ids/src/lib.rs`. Each accessor is one-liner; do not change any existing method signatures.

`FlowTable::reassembly_bytes()` does not yet exist — add it (PR 6 will use it too):

```rust
impl FlowTable {
    /// Sum of toserver_buf.len() + toclient_buf.len() across all flows.
    pub fn reassembly_bytes(&self) -> usize {
        self.table
            .iter()
            .map(|e| e.value().toserver_buf.len() + e.value().toclient_buf.len())
            .sum()
    }
}
```

- [ ] **Step 6: Smoke test — start the binary and query stats**

Build it:

`cargo build -p aifw-ids-bin --release`

Create a test socket and start it:

```bash
mkdir -p /tmp/aifw-test-run
TEST_DB=/tmp/aifw-test-run/test.db
TEST_SOCK=/tmp/aifw-test-run/ids.sock
sqlite3 "$TEST_DB" 'SELECT 1'  # creates the file
./target/release/aifw-ids --db "$TEST_DB" --socket "$TEST_SOCK" --log-level debug &
IDS_PID=$!
sleep 1
ls -la "$TEST_SOCK"
# Send a GetStats: write 4-byte length + JSON to socket, read response.
python3 -c '
import socket, struct, json
s = socket.socket(socket.AF_UNIX)
s.connect("'"$TEST_SOCK"'")
body = json.dumps({"method":"get_stats"}).encode()
s.send(struct.pack(">I", len(body)) + body)
n = struct.unpack(">I", s.recv(4))[0]
print(s.recv(n).decode())
'
kill $IDS_PID
rm -rf /tmp/aifw-test-run
```

Expected: prints a JSON `{"type":"stats","data":{...}}` response.

- [ ] **Step 7: Add aifw_ids overlay rc.d**

Create `freebsd/overlay/usr/local/etc/rc.d/aifw_ids` (the canonical pattern from Task 2.1):

```sh
#!/bin/sh
#
# PROVIDE: aifw_ids
# REQUIRE: NETWORKING aifw_daemon
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_ids"
rcvar="aifw_ids_enable"

load_rc_config $name

: ${aifw_ids_enable:="NO"}
: ${aifw_ids_pidfile:="/var/run/aifw_ids.pid"}
: ${aifw_ids_supervisor_pidfile:="/var/run/aifw_ids-supervisor.pid"}
: ${aifw_ids_db:="/var/db/aifw/aifw.db"}
: ${aifw_ids_socket:="/var/run/aifw/ids.sock"}

pidfile="${aifw_ids_supervisor_pidfile}"
procname="/usr/sbin/daemon"
aifw_ids_binary="/usr/local/sbin/aifw-ids"
command="/usr/sbin/daemon"
command_args="-f -p ${aifw_ids_pidfile} -P ${aifw_ids_supervisor_pidfile} -R 5 -S -T aifw_ids -o /var/log/aifw/ids.log -u aifw ${aifw_ids_binary} --db ${aifw_ids_db} --socket ${aifw_ids_socket} --log-level info"

start_precmd="aifw_ids_precmd"
stop_postcmd="aifw_ids_poststop"

aifw_ids_precmd()
{
    /bin/mkdir -p /var/log/aifw /var/run/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw /var/run/aifw
    /bin/chmod 0750 /var/run/aifw
    /usr/bin/pkill -f "daemon:.*aifw-ids" 2>/dev/null
    /usr/bin/pkill -x aifw-ids 2>/dev/null
    /bin/rm -f ${aifw_ids_pidfile} ${aifw_ids_supervisor_pidfile} ${aifw_ids_socket}
}

aifw_ids_poststop()
{
    /bin/rm -f ${aifw_ids_pidfile} ${aifw_ids_supervisor_pidfile}
}

run_rc_command "$1"
```

`chmod +x freebsd/overlay/usr/local/etc/rc.d/aifw_ids`

### Task 4.2: Update manifest + deploy script

**Files:**
- Modify: `freebsd/manifest.json`
- Modify: `freebsd/deploy.sh`

- [ ] **Step 1: Read manifest.json and add aifw-ids**

Find the AiFw binary list in `freebsd/manifest.json`. Add an entry mirroring `aifw-daemon`:

```json
{ "name": "aifw-ids", "path": "/usr/local/sbin/aifw-ids", "service": "aifw_ids" }
```

(Match the exact existing entry shape — adapt fields as needed.)

- [ ] **Step 2: Update deploy.sh**

Find where `aifw-daemon` and `aifw-api` binaries get scp'd to the target. Add `aifw-ids` to the same loop. Find where `service aifw_daemon restart` happens; add `service aifw_ids restart` between aifw_daemon and aifw_api (since aifw_api REQUIREs aifw_ids).

### Task 4.3: Commit PR 4

- [ ] **Step 1: Bump version (minor — new binary)**

`Cargo.toml` 5.73.x → 5.74.0. `aifw-ui/package.json` matches.

- [ ] **Step 2: Commit**

```bash
git add Cargo.toml aifw-ui/package.json aifw-ids-bin \
        aifw-ids/src/lib.rs aifw-ids/src/flow/mod.rs \
        freebsd/overlay/usr/local/etc/rc.d/aifw_ids \
        freebsd/manifest.json freebsd/deploy.sh
git commit -m "feat(ids): new aifw-ids daemon with IPC server + lockfile"
```

---

# PR 5 — Cutover: remove IDS from aifw-daemon and aifw-api; aifw-api → IPC client

This is the merge that observably changes runtime behaviour. Everything from PR 1–4 is dormant until this lands.

### Task 5.1: Replace `AppState.ids_engine` with `IdsClient`

**Files:**
- Modify: `aifw-api/Cargo.toml` (add aifw-ids-ipc dep)
- Modify: `aifw-api/src/main.rs:146-175` (AppState struct), `:1532-1561` (instantiation), and `:1641+` (state construction)

- [ ] **Step 1: Add IPC dep to aifw-api**

In `aifw-api/Cargo.toml` `[dependencies]`:

```toml
aifw-ids-ipc = { workspace = true }
```

- [ ] **Step 2: Add `--ids-socket` CLI flag**

Find the `Args` struct in `aifw-api/src/main.rs` (around line 193). Add:

```rust
/// Path to aifw-ids Unix socket
#[arg(long, default_value = "/var/run/aifw/ids.sock")]
ids_socket: PathBuf,
```

- [ ] **Step 3: Replace `AppState.ids_engine` field**

Change line 162 from:

```rust
pub ids_engine: Option<Arc<aifw_ids::IdsEngine>>,
```

to:

```rust
pub ids_client: Arc<aifw_ids_ipc::IdsClient>,
```

Also remove `pub alert_buffer: Arc<aifw_ids::output::memory::AlertBuffer>,` — alerts now live entirely in aifw-ids. The aifw-api side relies on `tail_alerts` IPC + DB queries.

- [ ] **Step 4: Replace the in-process IDS instantiation**

Delete lines 1525–1561 (alert_buffer creation, IdsEngine::migrate, IdsEngine::with_alert_buffer, start). The aifw-ids daemon owns these now.

Insert this in their place:

```rust
let ids_client = Arc::new(aifw_ids_ipc::IdsClient::new(args.ids_socket.clone()));
```

- [ ] **Step 5: Update AppState construction (around line 1641)**

In the `Ok(AppState { ... })` block:
- Remove `alert_buffer,`
- Replace `ids_engine,` with `ids_client,`

- [ ] **Step 6: Remove `aifw-ids` direct dep from aifw-api if unused**

Run: `grep -n "aifw_ids::" /home/mack/dev/AiFw/aifw-api/src/`

If the only remaining usages are types that are now exposed via `aifw-ids-ipc`, remove `aifw-ids = ...` from `aifw-api/Cargo.toml`. If there are concrete types still imported (e.g. `IdsConfig` from `aifw_common::ids`), they're already in `aifw-common` — keep using those, drop the direct `aifw-ids` dep.

- [ ] **Step 7: cargo check (will fail — handlers still use ids_engine)**

Run: `cargo check -p aifw-api`
Expected: many errors about `state.ids_engine` not existing. Proceed to next task.

### Task 5.2: Update each handler in `aifw-api/src/ids.rs`

**Files:**
- Modify: `aifw-api/src/ids.rs`

- [ ] **Step 1: Read the existing handlers**

Run: `grep -n "fn \|state.ids_engine" /home/mack/dev/AiFw/aifw-api/src/ids.rs`

Expected handlers (per spec): get/set config, reload, alerts list (paginated), alert by id (acknowledge), rulesets list/CRUD, rules list/get/set, suppressions list/CRUD, stats.

- [ ] **Step 2: Switch read handlers to `state.ids_client`**

For each handler that previously called `state.ids_engine.as_ref().unwrap().<method>()`:

- **`GET /api/v1/ids/config`** → `state.ids_client.get_config().await`
- **`PUT /api/v1/ids/config`** → `state.ids_client.set_config(req).await`
- **`POST /api/v1/ids/reload`** → `state.ids_client.reload().await`
- **`GET /api/v1/ids/stats`** → `state.ids_client.get_stats().await`
- **`GET /api/v1/ids/rulesets`** → `state.ids_client.list_rulesets().await`
- **`GET /api/v1/ids/rules/:id`** → `state.ids_client.get_rule(&id).await`
- **`PUT /api/v1/ids/rules/:id`** → `state.ids_client.set_rule(&id, enabled).await`

Each call returns `Result<T, IdsClientError>`. Map errors to HTTP responses:

```rust
fn ipc_to_response<T: serde::Serialize>(
    r: Result<T, aifw_ids_ipc::IdsClientError>,
) -> Result<axum::Json<T>, (axum::http::StatusCode, String)> {
    match r {
        Ok(v) => Ok(axum::Json(v)),
        Err(aifw_ids_ipc::IdsClientError::Unavailable(_))
        | Err(aifw_ids_ipc::IdsClientError::Timeout) => Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "ids service unavailable".to_string(),
        )),
        Err(aifw_ids_ipc::IdsClientError::Server(e)) => {
            Err((axum::http::StatusCode::BAD_REQUEST, e))
        }
        Err(e) => Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
```

Place this helper at the top of `ids.rs`. Use it as `ipc_to_response(state.ids_client.get_stats().await)` etc.

- [ ] **Step 3: DB-backed handlers stay direct-DB**

Endpoints that just read/write the SQLite tables (`ids_alerts` pagination,
`ids_suppressions` list/create/delete, alert acknowledge by id) keep using
`sqlx::query` against `state.pool` — the IPC layer doesn't add anything for
these. Verify no remaining `state.ids_engine` references in these
handlers; replace if any.

- [ ] **Step 4: cargo check**

Run: `cargo check -p aifw-api`
Expected: zero warnings, zero errors.

- [ ] **Step 5: Run the existing aifw-api test suite**

Run: `cargo test -p aifw-api`
Expected: tests adjusted for the new state shape pass. Some tests may need
the `state.ids_client` field set to a stub. If a test's `create_app_state_in_memory()`
helper needs an IDS-mock, point it at a path that doesn't exist — the
client will return `Unavailable`, and tests can either accept 503 or stub
a fake server. If a test specifically asserted IDS-engine internals, it
needs to be moved to `aifw-ids-bin` or skipped here.

### Task 5.3: Remove IDS from aifw-daemon

**Files:**
- Modify: `aifw-daemon/src/main.rs:190-218`
- Modify: `aifw-daemon/Cargo.toml`

- [ ] **Step 1: Delete the IDS init block**

Replace lines 190–218 (the `aifw_ids::IdsEngine::migrate` + `RuntimeConfig::load` + `IdsEngine::new` + `engine.start()` block) with a single comment:

```rust
// IDS engine moved to aifw-ids binary (see PR 5 / spec
// 2026-04-26-process-hardening-and-ids-extraction-design.md). aifw-daemon
// no longer holds an in-process IdsEngine. Configuration changes flow
// through the IPC layer at /var/run/aifw/ids.sock, which aifw-api owns.
```

- [ ] **Step 2: Remove unused `aifw-ids` dep**

Run: `grep -n "aifw_ids::" /home/mack/dev/AiFw/aifw-daemon/src/`
If no remaining usages, delete the line in `aifw-daemon/Cargo.toml`.

- [ ] **Step 3: cargo check**

Run: `cargo check -p aifw-daemon`
Expected: zero warnings, zero errors.

### Task 5.4: Update memstats heartbeat to query aifw-ids

**Files:**
- Modify: `aifw-api/src/main.rs:2080-2146`

- [ ] **Step 1: Replace IDS-related counters with IPC call**

Around line 2106–2114, replace:

```rust
let ids_rules = mem_state
    .ids_engine
    .as_ref()
    .map(|e| e.rule_db().rule_count())
    .unwrap_or(0);
let (ids_alerts_db,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ids_alerts")
    .fetch_one(&mem_state.pool)
    .await
    .unwrap_or((0,));
```

with:

```rust
let ids_stats = mem_state.ids_client.get_stats().await.ok();
let ids_rules = ids_stats.as_ref().map(|s| s.rules_loaded).unwrap_or(0);
let flow_count = ids_stats.as_ref().map(|s| s.flow_count).unwrap_or(0);
let flow_reassembly_kb = ids_stats
    .as_ref()
    .map(|s| s.flow_reassembly_bytes / 1024)
    .unwrap_or(0);
let (ids_alerts_db,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ids_alerts")
    .fetch_one(&mem_state.pool)
    .await
    .unwrap_or((0,));
```

Around line 2086, remove `let alert = mem_state.alert_buffer.stats().await;` — alert_buffer is gone from AppState. Replace any references to `alert.count` and `alert.estimated_mb` etc. with values from `ids_stats` or drop those fields from the heartbeat output.

In the `tracing::info!` call (line 2128), replace alert-buffer fields with:

```rust
ids_alerts_total = ids_stats.as_ref().map(|s| s.alerts_total).unwrap_or(0),
flow_count = flow_count,
flow_reassembly_kb = flow_reassembly_kb,
```

- [ ] **Step 2: cargo check**

Run: `cargo check -p aifw-api`
Expected: zero warnings.

### Task 5.5: Cargo test full workspace

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: all green. Fix any test that depended on in-process `ids_engine`.

### Task 5.6: Commit PR 5

- [ ] **Step 1: Bump version (minor — architecture change)**

5.74.x → 5.75.0.

- [ ] **Step 2: Commit**

```bash
git add aifw-api aifw-daemon Cargo.toml aifw-ui/package.json
git commit -m "feat(ids): cutover — aifw-api uses IPC client, aifw-daemon drops IDS"
```

---

# PR 6 — FlowTable bounding (count cap, byte budget, time-based expiry)

Lands inside `aifw-ids` library. Picked up by `aifw-ids-bin` automatically.

### Task 6.1: Reduce default stream depth

**Files:**
- Modify: `aifw-ids/src/flow/mod.rs:241`

- [ ] **Step 1: Test the new default**

Add to `aifw-ids/src/flow/mod.rs` test module:

```rust
#[test]
fn default_stream_depth_is_64kb() {
    let table = FlowTable::new(1024);
    assert_eq!(table.max_stream_depth, 65536);
}
```

- [ ] **Step 2: Run — should fail**

Run: `cargo test -p aifw-ids default_stream_depth_is_64kb`
Expected: FAIL (currently 1 MB).

- [ ] **Step 3: Change the default**

In `flow/mod.rs:241`, change:

```rust
max_stream_depth: 1024 * 1024, // 1MB default stream depth
```

to:

```rust
max_stream_depth: 65536, // 64 KB per direction — covers HTTP headers, TLS handshake, DNS, banners.
```

- [ ] **Step 4: Run — should pass**

`cargo test -p aifw-ids default_stream_depth_is_64kb`

### Task 6.2: Hard count cap with LRU eviction

**Files:**
- Modify: `aifw-ids/src/flow/mod.rs`

- [ ] **Step 1: Add capacity field + getter**

Replace the `FlowTable` struct definition (line ~232):

```rust
pub struct FlowTable {
    table: DashMap<FlowKey, Flow>,
    max_stream_depth: usize,
    max_flows: usize,
}

impl FlowTable {
    pub fn new(max_flows: usize) -> Self {
        Self {
            table: DashMap::with_capacity(max_flows),
            max_stream_depth: 65536,
            max_flows,
        }
    }

    pub fn with_stream_depth(mut self, depth: usize) -> Self {
        self.max_stream_depth = depth;
        self
    }

    pub fn max_flows(&self) -> usize {
        self.max_flows
    }
    // ... rest unchanged
}
```

- [ ] **Step 2: Test eviction**

Add to test module:

```rust
#[test]
fn evicts_oldest_when_at_cap() {
    let table = FlowTable::new(3);
    let make_pkt = |src_octet: u8, ts: i64| DecodedPacket {
        timestamp_us: ts,
        src_ip: Some(format!("10.0.0.{src_octet}").parse().unwrap()),
        dst_ip: Some("10.0.1.1".parse().unwrap()),
        src_port: Some(1000),
        dst_port: Some(80),
        protocol: PacketProtocol::Tcp,
        tcp_flags: None,
        payload: vec![],
        packet_len: 64,
    };
    table.track_packet(&make_pkt(1, 1_000));
    table.track_packet(&make_pkt(2, 2_000));
    table.track_packet(&make_pkt(3, 3_000));
    assert_eq!(table.len(), 3);
    table.track_packet(&make_pkt(4, 4_000));
    assert_eq!(table.len(), 3, "should not exceed cap");
    // Oldest (src 1, ts 1000) should have been evicted.
    let oldest_key = FlowKey::from_packet(
        "10.0.0.1".parse().unwrap(),
        "10.0.1.1".parse().unwrap(),
        1000,
        80,
        6,
    );
    assert!(table.get(&oldest_key).is_none());
}
```

- [ ] **Step 3: Run — should fail**

Run: `cargo test -p aifw-ids evicts_oldest_when_at_cap`
Expected: FAIL — table grows past cap.

- [ ] **Step 4: Implement eviction in `track_packet`**

Replace the `track_packet` method:

```rust
pub fn track_packet(&self, packet: &DecodedPacket) -> Option<(FlowKey, FlowDirection)> {
    let src_ip = packet.src_ip?;
    let dst_ip = packet.dst_ip?;
    let src_port = packet.src_port.unwrap_or(0);
    let dst_port = packet.dst_port.unwrap_or(0);

    let proto = match packet.protocol {
        PacketProtocol::Tcp => 6,
        PacketProtocol::Udp => 17,
        PacketProtocol::Icmpv4 => 1,
        PacketProtocol::Icmpv6 => 58,
        PacketProtocol::Other(n) => n,
    };

    let key = FlowKey::from_packet(src_ip, dst_ip, src_port, dst_port, proto);
    let direction = key.direction(src_ip, src_port);

    // Evict if at cap and this is a new flow.
    if !self.table.contains_key(&key) && self.table.len() >= self.max_flows {
        self.evict_oldest();
    }

    self.table
        .entry(key.clone())
        .and_modify(|flow| flow.update(packet, direction))
        .or_insert_with(|| Flow::new(key.clone(), packet, self.max_stream_depth));

    Some((key, direction))
}

/// Evict the entry with the smallest `last_ts`. O(N).
fn evict_oldest(&self) {
    let oldest = self
        .table
        .iter()
        .min_by_key(|e| e.value().last_ts)
        .map(|e| e.key().clone());
    if let Some(k) = oldest {
        self.table.remove(&k);
    }
}
```

- [ ] **Step 5: Run — should pass**

Run: `cargo test -p aifw-ids evicts_oldest_when_at_cap`
Expected: PASS.

### Task 6.3: Reassembly byte budget

**Files:**
- Modify: `aifw-ids/src/flow/mod.rs`

- [ ] **Step 1: Test budget eviction**

Add to test module:

```rust
#[test]
fn evicts_when_reassembly_budget_exceeded() {
    let table = FlowTable::new(1024).with_reassembly_budget(2048);
    let mut ts = 1_000;
    for i in 1..=10u8 {
        let pkt = DecodedPacket {
            timestamp_us: ts,
            src_ip: Some(format!("10.0.0.{i}").parse().unwrap()),
            dst_ip: Some("10.0.1.1".parse().unwrap()),
            src_port: Some(1000),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![0u8; 512], // 512 bytes per direction
            packet_len: 600,
        };
        table.track_packet(&pkt);
        ts += 1_000;
    }
    assert!(
        table.reassembly_bytes() <= 2048,
        "budget exceeded: {}",
        table.reassembly_bytes()
    );
}
```

- [ ] **Step 2: Run — should fail**

Run: `cargo test -p aifw-ids evicts_when_reassembly_budget_exceeded`
Expected: FAIL.

- [ ] **Step 3: Add budget field + `with_reassembly_budget` builder**

Augment `FlowTable`:

```rust
pub struct FlowTable {
    table: DashMap<FlowKey, Flow>,
    max_stream_depth: usize,
    max_flows: usize,
    reassembly_budget_bytes: usize,
}

impl FlowTable {
    pub fn new(max_flows: usize) -> Self {
        Self {
            table: DashMap::with_capacity(max_flows),
            max_stream_depth: 65536,
            max_flows,
            reassembly_budget_bytes: 256 * 1024 * 1024, // 256 MB
        }
    }

    pub fn with_reassembly_budget(mut self, bytes: usize) -> Self {
        self.reassembly_budget_bytes = bytes;
        self
    }
    // existing impls
}
```

- [ ] **Step 4: Enforce budget after each `track_packet`**

In `track_packet`, after the `entry().or_insert_with()`, add:

```rust
while self.reassembly_bytes() > self.reassembly_budget_bytes && !self.table.is_empty() {
    self.evict_oldest();
}
```

- [ ] **Step 5: Run — should pass**

`cargo test -p aifw-ids evicts_when_reassembly_budget_exceeded`

### Task 6.4: Time-based expiry task in aifw-ids-bin

**Files:**
- Modify: `aifw-ids-bin/src/main.rs`

- [ ] **Step 1: Add expiry tokio task after engine.start()**

Right after the `engine.start()` block in `main.rs`, add:

```rust
{
    let engine = engine.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        const FLOW_IDLE_TIMEOUT_US: i64 = 300_000_000; // 5 min
        loop {
            interval.tick().await;
            if let Some(table) = engine.flow_table() {
                let now_us = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_micros() as i64;
                let expired = table.expire(now_us, FLOW_IDLE_TIMEOUT_US);
                if expired > 0 {
                    tracing::debug!(expired, active = table.len(), "flow table time-expiry");
                }
            }
        }
    });
}
```

- [ ] **Step 2: cargo check + smoke test**

Run: `cargo build -p aifw-ids-bin --release`. Repeat the smoke test from Task 4.1 step 6 — should still respond to GetStats.

### Task 6.5: Wire `flow_table_size` and `flow_stream_depth_kb` config

**Files:**
- Modify: `aifw-common/src/ids.rs:259` (IdsConfig adds `flow_stream_depth_kb`)
- Modify: `aifw-ids/src/lib.rs:94-102` (use config values)

- [ ] **Step 1: Add config field**

In `aifw-common/src/ids.rs`, add to `IdsConfig`:

```rust
pub flow_stream_depth_kb: Option<u32>,
```

Default `None` (use built-in 64). Update Default impl.

- [ ] **Step 2: Use it when constructing FlowTable**

In `aifw-ids/src/lib.rs:94-102`, change:

```rust
let flow_table_size = if disabled {
    1024
} else {
    config.config().flow_table_size.unwrap_or(65536) as usize
};
let flow_table = Arc::new(FlowTable::new(flow_table_size));
```

to:

```rust
let cfg_view = config.config();
let flow_table_size = if disabled {
    1024
} else {
    cfg_view.flow_table_size.unwrap_or(65536) as usize
};
let stream_depth_bytes = cfg_view
    .flow_stream_depth_kb
    .unwrap_or(64) as usize
    * 1024;
let flow_table = Arc::new(
    FlowTable::new(flow_table_size).with_stream_depth(stream_depth_bytes),
);
```

- [ ] **Step 3: Run all aifw-ids and aifw-common tests**

Run: `cargo test -p aifw-ids -p aifw-common`
Expected: green.

### Task 6.6: Commit PR 6

- [ ] **Step 1: Bump version (patch)**

- [ ] **Step 2: Commit**

```bash
git add aifw-ids aifw-ids-bin aifw-common Cargo.toml aifw-ui/package.json
git commit -m "fix(ids): bound FlowTable — 64 KB stream depth, count cap, 256 MB budget, 30s time-expiry"
```

---

# PR 7 — LoginRateLimiter pruning

Trivial. Stops slow growth of the per-IP/per-user attempt maps.

### Task 7.1: Test for opportunistic pruning

**Files:**
- Modify: `aifw-api/src/main.rs:64-143`

- [ ] **Step 1: Add test**

In `aifw-api/src/main.rs` test module (or wherever the limiter tests live — search for `LoginRateLimiter` test), add:

```rust
#[tokio::test]
async fn login_limiter_prunes_expired_entries() {
    let limiter = LoginRateLimiter::with_limits(5, 1); // 1-second window
    limiter.record_failure("1.1.1.1", "alice").await;
    limiter.record_failure("2.2.2.2", "bob").await;
    assert_eq!(limiter.by_ip.read().await.len(), 2);

    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // Any subsequent call should opportunistically prune both expired
    // entries before doing its own work.
    limiter.record_failure("3.3.3.3", "carol").await;
    assert_eq!(
        limiter.by_ip.read().await.len(),
        1,
        "expired entries should have been pruned"
    );
}
```

- [ ] **Step 2: Run — fails**

Run: `cargo test -p aifw-api login_limiter_prunes_expired_entries`
Expected: FAIL — assertion mismatch (map will have 3 entries).

- [ ] **Step 3: Implement prune in `bump`**

Replace the `bump` function:

```rust
async fn bump(
    map: &Arc<RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>>,
    key: &str,
    max_attempts: u32,
    window_secs: i64,
) -> bool {
    let now = chrono::Utc::now();
    let mut m = map.write().await;
    m.retain(|_, (_, since)| (now - *since).num_seconds() <= window_secs);
    let entry = m.entry(key.to_string()).or_insert((0, now));
    if (now - entry.1).num_seconds() > window_secs {
        *entry = (1, now);
        return false;
    }
    entry.0 += 1;
    entry.0 >= max_attempts
}
```

Also update `over_cap`:

```rust
async fn over_cap(
    map: &Arc<RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>>,
    key: &str,
    max_attempts: u32,
    window_secs: i64,
) -> bool {
    let now = chrono::Utc::now();
    let mut m = map.write().await; // upgraded to write — needed for prune
    m.retain(|_, (_, since)| (now - *since).num_seconds() <= window_secs);
    matches!(
        m.get(key),
        Some((count, since))
            if (now - *since).num_seconds() <= window_secs
                && *count >= max_attempts
    )
}
```

- [ ] **Step 4: Run — should pass**

`cargo test -p aifw-api login_limiter_prunes_expired_entries`

- [ ] **Step 5: Commit**

Bump version (patch).

```bash
git add aifw-api/src/main.rs Cargo.toml aifw-ui/package.json
git commit -m "fix(api): prune expired LoginRateLimiter entries on every call"
```

---

# PR 8 — Singleton lock + rc.d fix in sibling repos (trafficcop, rDNS, rDHCP, rTime)

Each is a separate repo with its own commit. Apply the same `single_instance` helper (copied locally — no shared crate to keep blast radius small) and rc.d fix where applicable.

### Task 8.1: trafficcop singleton

**Repo:** `~/dev/trafficcop`

- [ ] **Step 1: Survey the binary**

Run: `ls ~/dev/trafficcop/src/ && grep -n "fn main" ~/dev/trafficcop/src/main.rs ~/dev/trafficcop/src/bin/*.rs 2>/dev/null`

Identify the binary entry point.

- [ ] **Step 2: Add nix dep**

In `~/dev/trafficcop/Cargo.toml`:

```toml
[target.'cfg(unix)'.dependencies]
nix = { version = "0.29", features = ["fs", "process"] }
thiserror = "2"
```

(Adjust if already present.)

- [ ] **Step 3: Copy `single_instance.rs`**

Create `~/dev/trafficcop/src/single_instance.rs` with the same body as `aifw-common/src/single_instance.rs` from Task 1.2. Keep the module local; don't depend on aifw-common.

- [ ] **Step 4: Wire into main**

In `~/dev/trafficcop/src/main.rs` (or wherever `fn main()` is), at the top of `main` after argument parsing:

```rust
#[cfg(unix)]
mod single_instance;

// inside main():
#[cfg(unix)]
let _instance_lock = match single_instance::acquire("trafficcop") {
    Ok(lock) => lock,
    Err(e) => {
        eprintln!("trafficcop: {e}");
        std::process::exit(1);
    }
};
```

- [ ] **Step 5: cargo check + commit**

In `~/dev/trafficcop`:

```bash
cargo check
git add Cargo.toml src/single_instance.rs src/main.rs
git commit -m "feat: refuse to start when another trafficcop instance is running"
```

### Task 8.2: rDNS singleton

**Repo:** `~/dev/rDNS`

Repeat Task 8.1 steps, substituting `rdns` for the lock name. The rc.d
script is already correct (the AiFw overlay copy was modeled on it). No
rc.d change needed in this repo.

### Task 8.3: rDHCP singleton

**Repo:** `~/dev/rDHCP`

Repeat Task 8.1 steps, substituting `rdhcpd` for the lock name. The
relevant rc.d script lives in AiFw's overlay — already fixed in PR 2.

### Task 8.4: rTime singleton

**Repo:** `~/dev/rTime`

Repeat Task 8.1 steps, substituting `rtime`. rc.d in AiFw overlay already
fixed.

---

# Final verification

### Task F.1: Full workspace build + test

- [ ] **Step 1: cargo check + test**

Run: `cargo check` (root); expect zero warnings.
Run: `cargo test`; expect green.

### Task F.2: UI build still works

- [ ] **Step 1**

Run: `cd aifw-ui && npm run build && cd ..`
Expected: succeeds.

### Task F.3: Deploy to test VM (172.29.69.159) and verify

Per CLAUDE.md memory: deploy via `ssh root@172.29.69.159 "cd /root/AiFw && sh freebsd/deploy.sh"`. 2 min timeout. Run in foreground.

- [ ] **Step 1: Deploy**

```bash
timeout 120 ssh root@172.29.69.159 "cd /root/AiFw && sh freebsd/deploy.sh"
```

- [ ] **Step 2: Verify singleton**

```bash
ssh root@172.29.69.159 'service aifw_api stop; \
  /usr/local/sbin/aifw-api --db /var/db/aifw/aifw.db --listen 127.0.0.1:18080 --no-tls --insecure-tls &
  sleep 1
  /usr/local/sbin/aifw-api --db /var/db/aifw/aifw.db --listen 127.0.0.1:18081 --no-tls --insecure-tls
  echo "exit code: $?"
  pkill -f "aifw-api --listen 127.0.0.1:18080"
  service aifw_api start'
```

Expected: second invocation prints `aifw-api: another instance is already running (pid X)`, exits 1. First continues running.

- [ ] **Step 3: Verify rc.d hygiene — 5 restarts, exactly one supervisor + one child each**

```bash
ssh root@172.29.69.159 '
  for s in aifw_daemon aifw_api aifw_ids trafficcop rdhcpd rtime rdns; do
    for i in 1 2 3 4 5; do service $s restart >/dev/null 2>&1 || true; done
    echo "$s: $(pgrep -af "${s%_*}|${s/_/-}" | wc -l) processes"
  done'
```

Expected: each service shows `2 processes` (supervisor + child).

- [ ] **Step 4: Verify aifw-api memory baseline + 1h growth**

```bash
ssh root@172.29.69.159 'ps -o rss= -p $(pgrep -x aifw-api)'
sleep 3600
ssh root@172.29.69.159 'ps -o rss= -p $(pgrep -x aifw-api)'
```

Expected: difference < 50 MB.

- [ ] **Step 5: Verify only one IDS in memory**

```bash
ssh root@172.29.69.159 'ps -o pid,rss,command -p $(pgrep -x aifw-api),$(pgrep -x aifw-daemon),$(pgrep -x aifw-ids)'
```

Expected: aifw-api RSS dropped by ~1.9 GB vs the 2.3 GB pre-fix; aifw-daemon RSS lower (no IDS); aifw-ids exists with reasonable RSS (~1.5–2 GB for the rule DB).

### Task F.4: Create GitHub issues (1 per PR)

- [ ] **Step 1: Create issues**

Use `gh issue create` for each. Body should reference the spec doc and the
plan. One example:

```bash
gh issue create --repo ZerosAndOnesLLC/AiFw \
  --title "PR 1: aifw-common::single_instance fcntl lockfile + apply to aifw-daemon, aifw-api" \
  --body "Adds a kernel-managed exclusive-lockfile primitive at \`aifw_common::single_instance::acquire\` and wires it into both long-running binaries so a second invocation refuses to start.

Tracks: docs/superpowers/specs/2026-04-26-process-hardening-and-ids-extraction-design.md
Plan section: PR 1
Priority: high (root-cause fix for duplicate-process bug class)"
```

Repeat for PR 2 through PR 8 with appropriate titles and bodies. PR 8 is created in 4 separate repos (trafficcop, rDNS, rDHCP, rTime) — file each in the corresponding repo.

---

## Self-Review Notes

**Spec coverage:**
- Goals 1 (singleton at rc.d + binary): PR 1 + PR 2 + PR 8 ✓
- Goal 2 (one IDS process, one rule DB in RAM): PR 3 + PR 4 + PR 5 ✓
- Goal 3 (memory plateaus naturally): PR 6 ✓
- Goal 4 (operator visibility): PR 5 task 5.4 (memstats) ✓
- Goal 5 (ships via update tarball): manifest + deploy.sh updates in PR 4 ✓

**Open risk:**
- Existing aifw-api tests using in-process `ids_engine` may need rework. Task 5.2 step 5 calls this out.
- `IdsEngine` accessor methods (`flow_table()`, `is_running()`, `packets_inspected()`, `alerts_total()`, `get_rule()`, `set_rule_enabled()`, `alert_buffer().tail()`, `save_config()`) may not all exist in the current shape. Task 4.1 step 5 explicitly tells the executor to add them. If the executor finds the existing API materially different, they should adjust the handler to use what's available rather than invent new methods.
