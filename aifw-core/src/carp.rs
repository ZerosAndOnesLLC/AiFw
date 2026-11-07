//! CARP / pfsync kernel control and kernel-state reads (#712).
//!
//! Every change to CARP or pfsync kernel state goes through the root helper
//! `/usr/local/libexec/aifw-sudo-carp` (the API and daemon run as the
//! unprivileged `aifw` user). Reads (`ifconfig`, `sysctl -n`, the demotion
//! ledger) need no privilege and are done directly.
//!
//! Demotion is reason-tracked. `net.inet.carp.demotion` is an adjustment,
//! not a level: writing N adds N. The helper keeps one ledger file per held
//! [`DemoteReason`] and adds/subtracts 240 exactly once per reason, so
//! independent subsystems (health checks, maintenance, boot hold) can hold
//! and release demotion without undoing each other.

use aifw_common::{CarpTiming, CarpVip, PfsyncConfig};
use std::net::IpAddr;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const SUDO: &str = "/usr/local/bin/sudo";
const HELPER: &str = "/usr/local/libexec/aifw-sudo-carp";
/// Ledger directory the helper maintains (one empty file per held reason).
pub const LEDGER_DIR: &str = "/var/run/aifw-carp";
/// Flag file marking persistent maintenance mode (re-applied at boot).
pub const MAINTENANCE_FLAG: &str = "/var/db/aifw/carp-maintenance";

/// Why this node is holding a CARP demotion. Closed set — must match the
/// helper's `valid_reason` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DemoteReason {
    /// Held from early boot until pf rules are loaded and pfsync's bulk
    /// update has completed.
    Boot,
    /// System shutdown/reboot — hand the VIPs over before interfaces drop.
    Shutdown,
    /// A local health check is failing.
    Health,
    /// Operator demote (cleared on reboot).
    Manual,
    /// Persistent maintenance mode (survives reboot).
    Maintenance,
    /// Software update in progress.
    Update,
}

impl DemoteReason {
    /// All reasons, in display order.
    pub const ALL: [DemoteReason; 6] = [
        Self::Boot,
        Self::Shutdown,
        Self::Health,
        Self::Manual,
        Self::Maintenance,
        Self::Update,
    ];

    /// Wire / ledger name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::Shutdown => "shutdown",
            Self::Health => "health",
            Self::Manual => "manual",
            Self::Maintenance => "maintenance",
            Self::Update => "update",
        }
    }

    /// Parse a ledger / wire name.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == s)
    }
}

impl std::fmt::Display for DemoteReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

async fn helper(args: &[&str], stdin: Option<&[u8]>) -> std::io::Result<()> {
    // Like the pf backend (PfMock off FreeBSD), kernel CARP control is a
    // FreeBSD-only effect; dev/test hosts record the call and succeed.
    if !cfg!(target_os = "freebsd") {
        tracing::debug!(
            verb = args.first().copied().unwrap_or(""),
            "carp: no-op off FreeBSD"
        );
        return Ok(());
    }
    let mut cmd = Command::new(SUDO);
    cmd.arg(HELPER).args(args);
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let output = if let Some(data) = stdin {
        cmd.stdin(std::process::Stdio::piped());
        let mut child = cmd.spawn()?;
        if let Some(mut pipe) = child.stdin.take() {
            pipe.write_all(data).await?;
            pipe.write_all(b"\n").await?;
            pipe.shutdown().await?;
        }
        child.wait_with_output().await?
    } else {
        cmd.stdin(std::process::Stdio::null());
        cmd.output().await?
    };
    if output.status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "aifw-sudo-carp {} failed ({}): {}",
            args.first().copied().unwrap_or(""),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

/// Hold a demotion for `reason` (idempotent).
pub async fn demote(reason: DemoteReason) -> std::io::Result<()> {
    helper(&["demote", reason.as_str()], None).await
}

/// Release the demotion held for `reason` (idempotent).
pub async fn undemote(reason: DemoteReason) -> std::io::Result<()> {
    helper(&["undemote", reason.as_str()], None).await
}

/// Enter or leave persistent maintenance mode.
pub async fn set_maintenance(on: bool) -> std::io::Result<()> {
    helper(&["maintenance", if on { "on" } else { "off" }], None).await
}

/// Enable CARP preemption. Required for demotion to move a VIP and for a
/// failure on one interface to move every VIP with it.
pub async fn enable_preempt() -> std::io::Result<()> {
    helper(&["preempt"], None).await
}

/// Configure (or retune) a CARP vhid and its address. The password goes
/// over stdin so it never shows up in the helper's argv.
pub async fn vip_set(vip: &CarpVip, timing: CarpTiming) -> std::io::Result<()> {
    let vhid = vip.vhid.to_string();
    let advskew = timing.advskew.to_string();
    let advbase = timing.advbase.to_string();
    let cidr = format!("{}/{}", vip.virtual_ip, vip.prefix);
    helper(
        &[
            "vip-set",
            &vip.interface.0,
            &vhid,
            &advskew,
            &advbase,
            family(&vip.virtual_ip),
            &cidr,
        ],
        Some(vip.password.as_bytes()),
    )
    .await
}

/// Remove a CARP address from `iface` (the vhid goes with its last address).
pub async fn vip_del(iface: &str, addr: &IpAddr) -> std::io::Result<()> {
    helper(&["vip-del", iface, family(addr), &addr.to_string()], None).await
}

/// Bring pfsync0 up on the configured sync interface, or down when the
/// config is disabled.
pub async fn pfsync_apply(cfg: &PfsyncConfig) -> std::io::Result<()> {
    if !cfg.enabled {
        return helper(&["pfsync-down"], None).await;
    }
    let peer = cfg
        .sync_peer
        .map(|p| p.to_string())
        .unwrap_or_else(|| "-".to_string());
    helper(
        &[
            "pfsync-set",
            &cfg.sync_interface.0,
            &peer,
            if cfg.defer { "defer" } else { "nodefer" },
        ],
        None,
    )
    .await
}

/// Take pfsync0 down (no pfsync configured).
pub async fn pfsync_down() -> std::io::Result<()> {
    helper(&["pfsync-down"], None).await
}

fn family(addr: &IpAddr) -> &'static str {
    if addr.is_ipv4() { "inet" } else { "inet6" }
}

// ============================================================
// Reads
// ============================================================

/// Demotion reasons currently held, from the helper's ledger.
pub async fn held_reasons() -> Vec<DemoteReason> {
    let mut out = Vec::new();
    let Ok(mut dir) = tokio::fs::read_dir(LEDGER_DIR).await else {
        return out;
    };
    while let Ok(Some(entry)) = dir.next_entry().await {
        if let Some(r) = entry.file_name().to_str().and_then(DemoteReason::parse) {
            out.push(r);
        }
    }
    out.sort_by_key(|r| DemoteReason::ALL.iter().position(|a| a == r));
    out
}

/// True when this node is in persistent maintenance mode.
pub async fn maintenance_persisted() -> bool {
    tokio::fs::metadata(MAINTENANCE_FLAG).await.is_ok()
}

async fn sysctl_int(name: &str) -> Option<i64> {
    let out = Command::new("sysctl")
        .args(["-n", name])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Current kernel demotion counter (`None` when carp(4) isn't loaded).
pub async fn demotion_level() -> Option<i64> {
    sysctl_int("net.inet.carp.demotion").await
}

/// Whether `net.inet.carp.preempt` is on (`None` when carp(4) isn't loaded).
pub async fn preempt_enabled() -> Option<bool> {
    sysctl_int("net.inet.carp.preempt").await.map(|v| v != 0)
}

/// One CARP vhid as the kernel reports it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KernelVhid {
    /// Interface the vhid lives on
    pub interface: String,
    /// Virtual host id
    pub vhid: u8,
    /// `master`, `backup` or `init`
    pub state: String,
    /// Advertisement base, seconds
    pub advbase: u8,
    /// Advertisement skew
    pub advskew: u8,
}

/// An address bound to a CARP vhid.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KernelCarpAddr {
    /// Interface the address is on
    pub interface: String,
    /// The address
    pub addr: IpAddr,
    /// The vhid it belongs to
    pub vhid: u8,
}

/// pfsync0 as the kernel reports it.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct KernelPfsync {
    /// pfsync0 exists and is UP
    pub up: bool,
    /// Sync interface, if set
    pub syncdev: Option<String>,
    /// Unicast peer, if set
    pub syncpeer: Option<String>,
    /// Defer mode on
    pub defer: bool,
    /// Bulk update done (`syncok: 1`); `None` when the kernel doesn't report it
    pub syncok: Option<bool>,
}

/// CARP + pfsync view parsed from one `ifconfig` run.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct KernelCarpView {
    /// Every configured vhid
    pub vhids: Vec<KernelVhid>,
    /// Every address bound to a vhid
    pub addrs: Vec<KernelCarpAddr>,
    /// pfsync0, when it exists
    pub pfsync: Option<KernelPfsync>,
    /// Non-CARP addresses configured on local interfaces
    pub local_addrs: Vec<IpAddr>,
}

impl KernelCarpView {
    /// Aggregate role across all vhids: `master` only when every vhid is
    /// MASTER, `backup` when every vhid is BACKUP, `split` when they
    /// disagree, `init` while any is still initialising, `none` without CARP.
    pub fn aggregate_state(&self) -> &'static str {
        if self.vhids.is_empty() {
            return "none";
        }
        if self.vhids.iter().any(|v| v.state == "init") {
            return "init";
        }
        let masters = self.vhids.iter().filter(|v| v.state == "master").count();
        if masters == self.vhids.len() {
            "master"
        } else if masters == 0 {
            "backup"
        } else {
            "split"
        }
    }

    /// State of one vhid, if the kernel has it.
    pub fn vhid_state(&self, vhid: u8) -> Option<&str> {
        self.vhids
            .iter()
            .find(|v| v.vhid == vhid)
            .map(|v| v.state.as_str())
    }
}

/// Run `ifconfig` and parse the CARP / pfsync state out of it. Empty view
/// on a host without ifconfig (Linux dev) or carp.
pub async fn kernel_view() -> KernelCarpView {
    match Command::new("ifconfig").output().await {
        Ok(o) if o.status.success() => parse_ifconfig(&String::from_utf8_lossy(&o.stdout)),
        _ => KernelCarpView::default(),
    }
}

/// Pure parse of `ifconfig` (all interfaces) output.
pub fn parse_ifconfig(out: &str) -> KernelCarpView {
    let mut view = KernelCarpView::default();
    let mut iface = String::new();
    for line in out.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // "vtnet1: flags=...": a new interface block.
            if let Some((name, rest)) = line.split_once(": ") {
                iface = name.to_string();
                if iface == "pfsync0" {
                    view.pfsync = Some(KernelPfsync {
                        up: rest.contains("<UP") || rest.contains(",UP"),
                        ..KernelPfsync::default()
                    });
                }
            }
            continue;
        }
        let t = line.trim();
        let words: Vec<&str> = t.split_whitespace().collect();
        if let Some(rest) = t.strip_prefix("carp:") {
            let w: Vec<&str> = rest.split_whitespace().collect();
            let state = w
                .first()
                .map(|s| s.to_ascii_lowercase())
                .unwrap_or_default();
            let vhid = value_after(&w, "vhid");
            let advbase = value_after(&w, "advbase").unwrap_or(1);
            let advskew = value_after(&w, "advskew").unwrap_or(0);
            if let Some(vhid) = vhid {
                view.vhids.push(KernelVhid {
                    interface: iface.clone(),
                    vhid,
                    state,
                    advbase,
                    advskew,
                });
            }
        } else if matches!(words.first(), Some(&"inet") | Some(&"inet6")) {
            // inet6 link-local carries a %scope suffix
            let addr = words
                .get(1)
                .and_then(|raw| raw.split('%').next())
                .and_then(|bare| bare.parse::<IpAddr>().ok());
            match (addr, value_after(&words, "vhid")) {
                (Some(addr), Some(vhid)) => view.addrs.push(KernelCarpAddr {
                    interface: iface.clone(),
                    addr,
                    vhid,
                }),
                (Some(addr), None) => view.local_addrs.push(addr),
                _ => {}
            }
        } else if iface == "pfsync0"
            && let Some(p) = view.pfsync.as_mut()
        {
            let mut i = 0;
            while i < words.len() {
                match words[i] {
                    "syncdev:" => p.syncdev = words.get(i + 1).map(|s| s.to_string()),
                    "syncpeer:" => p.syncpeer = words.get(i + 1).map(|s| s.to_string()),
                    "defer:" => p.defer = words.get(i + 1) == Some(&"on"),
                    "syncok:" => p.syncok = words.get(i + 1).map(|s| *s != "0"),
                    _ => {}
                }
                i += 1;
            }
        }
    }
    view
}

fn value_after(words: &[&str], key: &str) -> Option<u8> {
    words
        .iter()
        .position(|w| *w == key)
        .and_then(|i| words.get(i + 1))
        .and_then(|v| v.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
vtnet0: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\toptions=4c079b<RXCSUM,TXCSUM>
\tether 52:54:00:12:34:56
\tinet 203.0.113.2 netmask 0xffffff00 broadcast 203.0.113.255
\tinet 203.0.113.1 netmask 0xffffff00 broadcast 203.0.113.255 vhid 2
\tcarp: BACKUP vhid 2 advbase 1 advskew 100
\t      peer 224.0.0.18 peer6 ff02::12
vtnet1: flags=1008843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST,LOWER_UP> metric 0 mtu 1500
\tinet 10.0.0.2 netmask 0xffffff00 broadcast 10.0.0.255
\tinet 10.0.0.1 netmask 0xffffff00 broadcast 10.0.0.255 vhid 1
\tinet6 fd00::1 prefixlen 64 vhid 3
\tcarp: MASTER vhid 1 advbase 1 advskew 100
\tcarp: MASTER vhid 3 advbase 1 advskew 100
pfsync0: flags=41<UP,RUNNING> metric 0 mtu 1500
\tsyncdev: vtnet2 syncpeer: 10.9.9.2 maxupd: 128 defer: off version: 1400
\tsyncok: 1
lo0: flags=1008049<UP,LOOPBACK,RUNNING,MULTICAST,LOWER_UP> metric 0 mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
";

    #[test]
    fn parses_vhids_addresses_and_pfsync() {
        let v = parse_ifconfig(SAMPLE);
        assert_eq!(v.vhids.len(), 3);
        assert_eq!(
            v.vhids[0],
            KernelVhid {
                interface: "vtnet0".into(),
                vhid: 2,
                state: "backup".into(),
                advbase: 1,
                advskew: 100
            }
        );
        assert_eq!(v.vhid_state(1), Some("master"));
        assert_eq!(v.vhid_state(3), Some("master"));
        assert_eq!(v.addrs.len(), 3);
        assert!(
            v.addrs
                .iter()
                .any(|a| a.addr == "fd00::1".parse::<IpAddr>().unwrap() && a.vhid == 3)
        );
        // non-CARP addresses are listed as local, not as CARP
        assert!(!v.addrs.iter().any(|a| a.addr.to_string() == "10.0.0.2"));
        assert!(
            v.local_addrs
                .contains(&"10.0.0.2".parse::<IpAddr>().unwrap())
        );
        assert!(
            !v.local_addrs
                .contains(&"10.0.0.1".parse::<IpAddr>().unwrap())
        );
        let p = v.pfsync.expect("pfsync0 parsed");
        assert!(p.up);
        assert_eq!(p.syncdev.as_deref(), Some("vtnet2"));
        assert_eq!(p.syncpeer.as_deref(), Some("10.9.9.2"));
        assert!(!p.defer);
        assert_eq!(p.syncok, Some(true));
    }

    #[test]
    fn aggregate_state_reports_split_vhids() {
        let v = parse_ifconfig(SAMPLE);
        assert_eq!(v.aggregate_state(), "split");
        assert_eq!(KernelCarpView::default().aggregate_state(), "none");
        let all_master =
            parse_ifconfig("em0: flags=8843<UP>\n\tcarp: MASTER vhid 1 advbase 1 advskew 0\n");
        assert_eq!(all_master.aggregate_state(), "master");
        let init = parse_ifconfig(
            "em0: flags=8843<UP>\n\tcarp: MASTER vhid 1 advbase 1 advskew 0\n\tcarp: INIT vhid 2 advbase 1 advskew 0\n",
        );
        assert_eq!(init.aggregate_state(), "init");
    }

    #[test]
    fn pfsync_syncok_zero_is_not_ready() {
        let v = parse_ifconfig(
            "pfsync0: flags=41<UP,RUNNING> metric 0 mtu 1500\n\tsyncdev: em2 maxupd: 128 defer: on\n\tsyncok: 0\n",
        );
        let p = v.pfsync.unwrap();
        assert_eq!(p.syncok, Some(false));
        assert!(p.defer);
        assert_eq!(p.syncpeer, None);
    }

    #[test]
    fn reasons_round_trip_and_match_helper_allowlist() {
        let helper = include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-carp");
        let line = helper
            .lines()
            .find(|l| l.trim_start().starts_with("boot|shutdown"))
            .expect("valid_reason case arm in aifw-sudo-carp");
        let arm = line.trim().trim_end_matches(") return 0 ;;").trim();
        let mut helper_set: Vec<&str> = arm.split('|').collect();
        helper_set.sort_unstable();
        let mut ours: Vec<&str> = DemoteReason::ALL.iter().map(|r| r.as_str()).collect();
        ours.sort_unstable();
        assert_eq!(
            helper_set, ours,
            "DemoteReason and aifw-sudo-carp valid_reason drifted"
        );
        for r in DemoteReason::ALL {
            assert_eq!(DemoteReason::parse(r.as_str()), Some(r));
        }
        assert_eq!(DemoteReason::parse("bogus"), None);
    }

    /// #712 guard: only aifw-sudo-carp may write the CARP sysctls. A direct
    /// `sysctl net.inet.carp.demotion=…` from the aifw user fails (EPERM), and
    /// from root it bypasses the ledger — writing 0 does nothing and 240 stacks.
    #[test]
    fn only_the_helper_writes_carp_sysctls() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if p.is_dir() {
                    if !matches!(name, "target" | "node_modules" | ".git" | "out" | ".next") {
                        walk(&p, out);
                    }
                } else {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut files = Vec::new();
        for sub in [
            "aifw-api",
            "aifw-core",
            "aifw-daemon",
            "aifw-setup",
            "aifw-cli",
            "freebsd",
        ] {
            walk(&root.join(sub), &mut files);
        }
        let needles = ["carp.demotion=", "carp.preempt="];
        let mut offenders = Vec::new();
        for f in files {
            let name = f.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == "aifw-sudo-carp" || name == "carp.rs" {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                let code = line.trim_start();
                if code.starts_with("//") || code.starts_with('#') {
                    continue;
                }
                if needles.iter().any(|n| line.contains(n)) {
                    offenders.push(format!("{}:{}", f.display(), i + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "CARP sysctls written outside aifw-sudo-carp: {offenders:?}"
        );
    }
}
