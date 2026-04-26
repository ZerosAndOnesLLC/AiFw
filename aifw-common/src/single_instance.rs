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
#[derive(Debug)]
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
        // from this process — must fail with AlreadyRunning. POSIX advisory
        // locks are per-process, so a thread won't conflict; we need fork.
        use nix::unistd::{ForkResult, fork, sleep};
        use std::time::Duration;

        let path = tmp_lock("conflict");
        let _ = std::fs::remove_file(&path);

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
    }
}
