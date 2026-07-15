//! Native-syscall replacements for the subprocess sprawl in
//! `ws::collect_system_metrics` and friends (PERF-C5).
//!
//! Per dashboard tick the previous code spawned ~30 fork/exec calls
//! (`ifconfig`, `netstat`, `sysctl`, `df`, `hostname`, `freebsd-version`,
//! `ps aux`, ...). On a 6-NIC box that was 25-30 subprocesses per second
//! — easily 50-200 ms of CPU just on shell wrappers.
//!
//! All FreeBSD paths use `libc::sysctlbyname` / `statvfs(3)` / `getifaddrs(3)`
//! / `gethostname(3)`. Linux (dev / CI) returns sensible defaults so the
//! caller's `unwrap_or(0)` fallbacks still produce a coherent dashboard
//! payload.

#[cfg(target_os = "freebsd")]
pub mod sysctl {
    use std::ffi::CString;

    /// Read a sysctl name into a single `u64` (or smaller — `unsigned long`
    /// covers 32 / 64-bit MIBs on FreeBSD). Returns None on any error.
    pub fn read_u64(name: &str) -> Option<u64> {
        let c = CString::new(name).ok()?;
        let mut value: u64 = 0;
        let mut len: libc::size_t = std::mem::size_of::<u64>();
        // SAFETY: sysctlbyname reads up to `len` bytes into `&mut value`,
        // and sets `len` to the actual count. `value` is a stack u64.
        let r = unsafe {
            libc::sysctlbyname(
                c.as_ptr(),
                &mut value as *mut u64 as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 {
            // Some sysctls store as u32 even when read with size 8 — but
            // FreeBSD writes len back so we can detect and zero-extend.
            if len == std::mem::size_of::<u32>() {
                let v: u32 = (value & 0xFFFF_FFFF) as u32;
                Some(v as u64)
            } else {
                Some(value)
            }
        } else {
            None
        }
    }

    /// Read a sysctl name into an array of u64 (e.g. `kern.cp_time` is 5
    /// uint64_t). Returns None on size mismatch or syscall error.
    pub fn read_u64_array<const N: usize>(name: &str) -> Option<[u64; N]> {
        let c = CString::new(name).ok()?;
        let mut out: [u64; N] = [0; N];
        let mut len: libc::size_t = std::mem::size_of::<[u64; N]>();
        // SAFETY: sysctlbyname fills `out` with up to `len` bytes.
        let r = unsafe {
            libc::sysctlbyname(
                c.as_ptr(),
                out.as_mut_ptr() as *mut libc::c_void,
                &mut len,
                std::ptr::null_mut(),
                0,
            )
        };
        if r == 0 && len == std::mem::size_of::<[u64; N]>() {
            Some(out)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "freebsd"))]
pub mod sysctl {
    /// Linux / non-FreeBSD: sysctlbyname doesn't exist; callers fall back
    /// to their defaults.
    pub fn read_u64(_name: &str) -> Option<u64> {
        None
    }
    pub fn read_u64_array<const N: usize>(_name: &str) -> Option<[u64; N]> {
        None
    }
}

/// Resident set size of a process, in MiB, via a single O(1) syscall — no
/// `ps` fork (PERF-H12 #356). Returns None if the pid is gone or the query
/// fails, so callers keep their `unwrap_or(0.0)` dashboard fallback.
#[cfg(target_os = "freebsd")]
pub fn process_rss_mb(pid: u32) -> Option<f64> {
    let page_size = sysctl::read_u64("hw.pagesize").unwrap_or(4096);
    // MIB for `kern.proc.pid.<pid>`, which returns a single `struct
    // kinfo_proc` for the target process.
    let mut mib: [libc::c_int; 4] = [
        libc::CTL_KERN,
        libc::KERN_PROC,
        libc::KERN_PROC_PID,
        pid as libc::c_int,
    ];
    let mut kp: libc::kinfo_proc = unsafe { std::mem::zeroed() };
    let mut len: libc::size_t = std::mem::size_of::<libc::kinfo_proc>();
    // SAFETY: `mib` is a valid 4-element MIB (kern.proc.pid.<pid>). `kp` is a
    // stack-allocated `kinfo_proc` and `len` its byte length; sysctl writes at
    // most `len` bytes into it and updates `len` to the count written. We read
    // only the plain integer field `ki_rssize` afterward — no embedded pointer
    // in `kp` is dereferenced. `newp` is null (read-only query).
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            &mut kp as *mut libc::kinfo_proc as *mut libc::c_void,
            &mut len,
            std::ptr::null(),
            0,
        )
    };
    if r != 0 || len == 0 {
        return None;
    }
    // ki_rssize is the current resident set size in pages.
    let pages = (kp.ki_rssize as i64).max(0) as u64;
    Some(pages.saturating_mul(page_size) as f64 / (1024.0 * 1024.0))
}

/// Linux / dev fallback: read resident pages from `/proc/<pid>/statm`
/// (field 2). FreeBSD's procfs isn't mounted on the appliance, so the real
/// path above uses sysctl; this keeps the dashboard coherent in dev/CI.
#[cfg(not(target_os = "freebsd"))]
pub fn process_rss_mb(pid: u32) -> Option<f64> {
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    // Linux default page size; exact value would need sysconf(_SC_PAGESIZE),
    // but this path is dev-only and x86-64 pages are 4 KiB.
    Some((resident_pages.saturating_mul(4096)) as f64 / (1024.0 * 1024.0))
}

/// Read a pidfile (e.g. `/var/run/aifw_daemon.pid`) into a pid. Returns None
/// if the file is missing/unreadable or doesn't contain a number.
pub fn read_pidfile(path: &str) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Hostname via `gethostname(3)`. Cached for the lifetime of the process —
/// hostname can change at runtime via `sysrc`, but the dashboard refresh
/// already pays an rc-config restart for that, so a stale value would only
/// last until the next service bounce.
pub fn hostname() -> String {
    static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOSTNAME
        .get_or_init(|| {
            nix::unistd::gethostname()
                .ok()
                .and_then(|os| os.into_string().ok())
                .unwrap_or_else(|| "aifw".to_string())
        })
        .clone()
}

/// OS version string — cached. On FreeBSD the legacy `freebsd-version`
/// shell-out wraps `sysctl kern.osrelease`, so we read it directly. On
/// Linux we read `/etc/os-release` `PRETTY_NAME`.
pub fn os_version() -> String {
    static OS_VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    OS_VERSION
        .get_or_init(|| {
            #[cfg(target_os = "freebsd")]
            {
                let release = read_sysctl_string("kern.osrelease").unwrap_or_default();
                let userland = read_sysctl_string("kern.version").unwrap_or_default();
                if !release.is_empty() {
                    return format!("FreeBSD {release}");
                }
                if !userland.is_empty() {
                    return userland;
                }
                "FreeBSD".to_string()
            }
            #[cfg(not(target_os = "freebsd"))]
            {
                std::fs::read_to_string("/etc/os-release")
                    .ok()
                    .and_then(|c| {
                        c.lines()
                            .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|s| s.to_string()))
                    })
                    .map(|s| s.trim_matches('"').to_string())
                    .unwrap_or_else(|| "Linux".to_string())
            }
        })
        .clone()
}

#[cfg(target_os = "freebsd")]
fn read_sysctl_string(name: &str) -> Option<String> {
    use std::ffi::CString;
    let c = CString::new(name).ok()?;
    // First call: query size.
    let mut len: libc::size_t = 0;
    // SAFETY: requesting the length via NULL oldp is the documented usage.
    let r = unsafe {
        libc::sysctlbyname(
            c.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 || len == 0 {
        return None;
    }
    let mut buf: Vec<u8> = vec![0; len];
    // SAFETY: buf has at least `len` bytes; sysctl writes up to that.
    let r = unsafe {
        libc::sysctlbyname(
            c.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    // Trim trailing NUL + whitespace.
    while buf.last() == Some(&0) {
        buf.pop();
    }
    String::from_utf8(buf).ok().map(|s| s.trim().to_string())
}

/// Single mounted filesystem.
pub struct DiskInfo {
    pub mount: String,
    pub filesystem: String,
    pub total: u64,
    pub used: u64,
    pub pct: f64,
}

/// Native disk-usage scan via `statvfs`. Returns one entry per mounted
/// filesystem matching the supplied fs-type filter (only `ufs` and `zfs`
/// today, mirroring the old `df -t ufs,zfs` call).
pub fn disk_usage() -> Vec<DiskInfo> {
    let mut out = Vec::new();
    #[cfg(target_os = "freebsd")]
    {
        use_freebsd_getmntinfo(&mut out);
    }
    #[cfg(target_os = "linux")]
    {
        use_linux_proc_mounts(&mut out);
    }
    out
}

#[cfg(target_os = "freebsd")]
fn use_freebsd_getmntinfo(out: &mut Vec<DiskInfo>) {
    // `getmntinfo` returns an in-kernel array of statfs structs; safe to
    // iterate without copying.
    let mut mntbuf: *mut libc::statfs = std::ptr::null_mut();
    // SAFETY: getmntinfo writes its internal buffer pointer to `mntbuf` and
    // returns the count. The buffer is kernel-owned and lives until the
    // next getmntinfo call on this thread.
    let count = unsafe { libc::getmntinfo(&mut mntbuf, libc::MNT_NOWAIT) };
    if count <= 0 || mntbuf.is_null() {
        return;
    }
    // SAFETY: slice of `count` valid `statfs` entries.
    let slice = unsafe { std::slice::from_raw_parts(mntbuf, count as usize) };
    for sb in slice {
        // SAFETY: zero-terminated C strings from the kernel.
        let fstype = unsafe { c_str_to_string(sb.f_fstypename.as_ptr()) };
        if fstype != "ufs" && fstype != "zfs" {
            continue;
        }
        let total = sb.f_blocks as u64 * sb.f_bsize as u64;
        let avail = sb.f_bavail as u64 * sb.f_bsize as u64;
        let used = total.saturating_sub(avail);
        let pct = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        // SAFETY: zero-terminated C strings from the kernel.
        out.push(DiskInfo {
            mount: unsafe { c_str_to_string(sb.f_mntonname.as_ptr()) },
            filesystem: unsafe { c_str_to_string(sb.f_mntfromname.as_ptr()) },
            total,
            used,
            pct,
        });
    }
}

/// # Safety
///
/// `p` must be either null or a pointer to a nul-terminated C string that
/// remains valid for the duration of the call.
#[cfg(target_os = "freebsd")]
unsafe fn c_str_to_string(p: *const libc::c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: caller asserts `p` is a nul-terminated C string.
    let c = unsafe { std::ffi::CStr::from_ptr(p) };
    c.to_string_lossy().into_owned()
}

#[cfg(target_os = "linux")]
fn use_linux_proc_mounts(out: &mut Vec<DiskInfo>) {
    use nix::sys::statvfs::statvfs;
    let Ok(mounts) = std::fs::read_to_string("/proc/mounts") else {
        return;
    };
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }
        let device = parts[0];
        let mount = parts[1];
        let fstype = parts[2];
        // Linux dev: include common local filesystems but skip pseudo-fs.
        if !matches!(fstype, "ext4" | "ext3" | "xfs" | "btrfs" | "zfs" | "ufs") {
            continue;
        }
        let Ok(s) = statvfs(std::path::Path::new(mount)) else {
            continue;
        };
        let total = s.blocks() * s.fragment_size();
        let avail = s.blocks_available() * s.fragment_size();
        let used = total.saturating_sub(avail);
        let pct = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        out.push(DiskInfo {
            mount: mount.to_string(),
            filesystem: device.to_string(),
            total,
            used,
            pct,
        });
    }
}

/// Per-interface address info from `getifaddrs(3)`.
/// `address` is the first AF_INET address found on the iface; `subnet` is
/// `<network>/<prefix>` derived from the address + netmask. Either may be
/// None for interfaces without an IPv4 address. The `up` flag is the
/// `IFF_UP` bit.
pub struct IfaceInfo {
    pub name: String,
    pub address: Option<String>,
    pub subnet: Option<String>,
    pub up: bool,
}

/// Enumerate interfaces via `getifaddrs(3)`. Replaces a `ifconfig -l` shell
/// plus per-iface `ifconfig <iface>` calls with a single C-library walk.
pub fn iface_list() -> Vec<IfaceInfo> {
    let mut out = Vec::new();
    let Ok(iter) = nix::ifaddrs::getifaddrs() else {
        return out;
    };
    use std::collections::HashMap;
    // getifaddrs returns one entry per (iface, address family). Collapse to
    // one entry per iface name, preferring the first IPv4 we see.
    let mut by_name: HashMap<String, IfaceInfo> = HashMap::new();
    for ia in iter {
        let name = ia.interface_name.clone();
        let up = ia.flags.contains(nix::net::if_::InterfaceFlags::IFF_UP);
        let entry = by_name.entry(name.clone()).or_insert_with(|| IfaceInfo {
            name: name.clone(),
            address: None,
            subnet: None,
            up,
        });
        entry.up = entry.up || up;
        if entry.address.is_some() {
            continue;
        }
        let Some(addr) = ia.address else { continue };
        let Some(v4) = addr.as_sockaddr_in() else {
            continue;
        };
        let octets = v4.ip().octets();
        let addr_str = format!("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
        entry.address = Some(addr_str.clone());
        // Build the CIDR subnet from the netmask if available.
        if let Some(nm) = ia.netmask
            && let Some(nm4) = nm.as_sockaddr_in()
        {
            let mask = u32::from(nm4.ip());
            let prefix = mask.count_ones();
            let ip_u32 = u32::from(v4.ip());
            let net = ip_u32 & mask;
            entry.subnet = Some(format!(
                "{}.{}.{}.{}/{}",
                net >> 24,
                (net >> 16) & 0xff,
                (net >> 8) & 0xff,
                net & 0xff,
                prefix
            ));
        }
    }
    out.extend(by_name.into_values());
    out
}

/// Uptime in seconds. Native via `kern.boottime` sysctl on FreeBSD;
/// `CLOCK_BOOTTIME` on Linux.
pub fn uptime_secs() -> u64 {
    #[cfg(target_os = "freebsd")]
    {
        // kern.boottime returns a `struct timeval`; we only care about sec.
        // It's 16 bytes on 64-bit FreeBSD (sec + usec as long).
        if let Some([sec, _usec]) = sysctl::read_u64_array::<2>("kern.boottime") {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return now.saturating_sub(sec);
        }
        0
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/uptime") {
            return s
                .split_whitespace()
                .next()
                .and_then(|n| n.parse::<f64>().ok())
                .map(|f| f as u64)
                .unwrap_or(0);
        }
        0
    }
    #[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
    {
        0
    }
}

#[cfg(test)]
mod rss_tests {
    use super::{process_rss_mb, read_pidfile};

    // PERF-H12: the current process always has a resident set. On Linux/CI
    // this exercises the /proc/<pid>/statm path; on FreeBSD, the sysctl path.
    #[test]
    fn self_rss_is_positive() {
        let rss = process_rss_mb(std::process::id());
        assert!(rss.is_some(), "self RSS should be readable");
        assert!(rss.unwrap() > 0.0, "self RSS should be > 0 MiB");
    }

    #[test]
    fn dead_pid_is_none_or_zeroish() {
        // pid 0 is never a normal userland process; the query should not
        // yield a real RSS. (None on both platforms.)
        assert!(process_rss_mb(0).unwrap_or(0.0) == 0.0);
    }

    #[test]
    fn read_pidfile_parses_and_handles_missing() {
        let path = std::env::temp_dir().join(format!("aifw-pidtest-{}.pid", std::process::id()));
        std::fs::write(&path, "  4242\n").unwrap();
        assert_eq!(read_pidfile(path.to_str().unwrap()), Some(4242));
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_pidfile("/no/such/aifw/pidfile"), None);
    }
}
