use serde::{Deserialize, Serialize};
use std::path::Path;

/// Complete hardware profile of the system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemProfile {
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub nics: Vec<NicInfo>,
    pub disk: DiskInfo,
    pub crypto: CryptoInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    pub cores: usize,
    pub threads: usize,
    pub model: String,
    pub has_aesni: bool,
    pub has_sha_ni: bool,
    pub has_hyperthreading: bool,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_mb: u64,
    pub total_gb: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NicInfo {
    pub name: String,
    pub driver: String,
    pub has_tso: bool,
    pub has_lro: bool,
    pub has_rxcsum: bool,
    pub has_txcsum: bool,
    pub has_rss: bool,
    pub rss_queues: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub is_ssd: bool,
    pub root_device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoInfo {
    pub has_aesni: bool,
    pub has_sha_ni: bool,
    pub has_qat: bool,
    pub has_arm_crypto: bool,
}

impl SystemProfile {
    /// Detect the full system profile
    pub fn detect() -> Self {
        Self {
            cpu: detect_cpu(),
            memory: detect_memory(),
            nics: detect_nics(),
            disk: detect_disk(),
            crypto: detect_crypto(),
        }
    }

    /// Summary string for display
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("CPU:     {} ({} cores / {} threads)",
            self.cpu.model, self.cpu.cores, self.cpu.threads));
        lines.push(format!("Arch:    {}", self.cpu.arch));
        lines.push(format!("RAM:     {:.1} GB ({} MB)", self.memory.total_gb, self.memory.total_mb));
        lines.push(format!("Disk:    {} ({})",
            self.disk.root_device,
            if self.disk.is_ssd { "SSD" } else { "HDD" }));

        let mut crypto_caps = Vec::new();
        if self.crypto.has_aesni { crypto_caps.push("AES-NI"); }
        if self.crypto.has_sha_ni { crypto_caps.push("SHA-NI"); }
        if self.crypto.has_qat { crypto_caps.push("Intel QAT"); }
        if self.crypto.has_arm_crypto { crypto_caps.push("ARM Crypto"); }
        if crypto_caps.is_empty() { crypto_caps.push("none"); }
        lines.push(format!("Crypto:  {}", crypto_caps.join(", ")));

        if self.cpu.has_hyperthreading {
            lines.push("HT:      enabled (consider disabling for security)".to_string());
        }

        lines.push(format!("NICs:    {} detected", self.nics.len()));
        for nic in &self.nics {
            let mut caps: Vec<String> = Vec::new();
            if nic.has_rxcsum { caps.push("rxcsum".into()); }
            if nic.has_txcsum { caps.push("txcsum".into()); }
            if nic.has_tso { caps.push("TSO".into()); }
            if nic.has_lro { caps.push("LRO".into()); }
            if nic.has_rss { caps.push(format!("RSS({}q)", nic.rss_queues)); }
            lines.push(format!("  {}:  driver={} caps=[{}]",
                nic.name, nic.driver, caps.join(", ")));
        }

        lines
    }
}

// ============================================================
// CPU Detection
// ============================================================

fn detect_cpu() -> CpuInfo {
    let mut info = CpuInfo {
        cores: 1,
        threads: 1,
        model: "Unknown".to_string(),
        has_aesni: false,
        has_sha_ni: false,
        has_hyperthreading: false,
        arch: std::env::consts::ARCH.to_string(),
    };

    // Linux: /proc/cpuinfo
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        let mut processors = 0;
        let mut core_ids = std::collections::HashSet::new();

        for line in cpuinfo.lines() {
            if line.starts_with("processor") {
                processors += 1;
            }
            if let Some(model) = line.strip_prefix("model name")
                && let Some(val) = model.split(':').nth(1) {
                    info.model = val.trim().to_string();
                }
            if let Some(flags) = line.strip_prefix("flags") {
                let flags = flags.to_lowercase();
                info.has_aesni = flags.contains("aes");
                info.has_sha_ni = flags.contains("sha_ni");
            }
            if let Some(core_id) = line.strip_prefix("core id")
                && let Some(val) = core_id.split(':').nth(1) {
                    core_ids.insert(val.trim().to_string());
                }
        }

        info.threads = processors.max(1);
        info.cores = if core_ids.is_empty() { info.threads } else { core_ids.len() };
        info.has_hyperthreading = info.threads > info.cores;
    }

    // FreeBSD: sysctl
    #[cfg(target_os = "freebsd")]
    {
        if let Ok(out) = std::process::Command::new("sysctl").arg("-n").arg("hw.ncpu").output() {
            info.threads = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(1);
        }
        if let Ok(out) = std::process::Command::new("sysctl").arg("-n").arg("hw.model").output() {
            info.model = String::from_utf8_lossy(&out.stdout).trim().to_string();
        }
        if let Ok(out) = std::process::Command::new("sysctl").arg("-n").arg("kern.features").output() {
            let features = String::from_utf8_lossy(&out.stdout).to_lowercase();
            info.has_aesni = features.contains("aesni");
        }
        // Detect physical cores vs HT
        if let Ok(out) = std::process::Command::new("sysctl").arg("-n").arg("kern.smp.cores").output() {
            info.cores = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(info.threads);
            info.has_hyperthreading = info.threads > info.cores;
        }
    }

    info
}

// ============================================================
// Memory Detection
// ============================================================

fn detect_memory() -> MemoryInfo {
    let mut total_mb: u64 = 1024; // 1 GB fallback

    // Linux: /proc/meminfo
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if let Some(rest) = line.strip_prefix("MemTotal:") {
                let kb_str = rest.trim().trim_end_matches("kB").trim();
                if let Ok(kb) = kb_str.parse::<u64>() {
                    total_mb = kb / 1024;
                }
                break;
            }
        }
    }

    // FreeBSD: sysctl
    #[cfg(target_os = "freebsd")]
    {
        if let Ok(out) = std::process::Command::new("sysctl").arg("-n").arg("hw.physmem").output() {
            if let Ok(bytes) = String::from_utf8_lossy(&out.stdout).trim().parse::<u64>() {
                total_mb = bytes / (1024 * 1024);
            }
        }
    }

    MemoryInfo {
        total_mb,
        total_gb: total_mb as f64 / 1024.0,
    }
}

// ============================================================
// NIC Detection
// ============================================================

fn detect_nics() -> Vec<NicInfo> {
    let mut nics = Vec::new();

    // Linux: /sys/class/net
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" || name.starts_with("veth") || name.starts_with("docker") || name.starts_with("br-") {
                continue;
            }

            let driver = read_sys_file(&format!("/sys/class/net/{name}/device/driver"))
                .and_then(|p| p.split('/').next_back().map(String::from))
                .unwrap_or_else(|| "unknown".to_string());

            let features = read_sys_file(&format!("/sys/class/net/{name}/features"))
                .unwrap_or_default()
                .to_lowercase();

            // Check ethtool features via /sys
            let has_tso = features.contains("tx-tcp-segmentation: on") || check_sys_flag(&name, "tso");
            let has_lro = features.contains("large-receive-offload: on") || check_sys_flag(&name, "lro");
            let has_rxcsum = features.contains("rx-checksum: on") || true; // most modern NICs
            let has_txcsum = features.contains("tx-checksum") || true;

            // RSS queues
            let rss_queues = count_rss_queues(&name);

            nics.push(NicInfo {
                name,
                driver,
                has_tso,
                has_lro,
                has_rxcsum,
                has_txcsum,
                has_rss: rss_queues > 1,
                rss_queues,
            });
        }
    }

    // FreeBSD: ifconfig -l + sysctl
    #[cfg(target_os = "freebsd")]
    if nics.is_empty() {
        if let Ok(out) = std::process::Command::new("ifconfig").arg("-l").output() {
            for name in String::from_utf8_lossy(&out.stdout).split_whitespace() {
                if name.starts_with("lo") || name.starts_with("pflog") || name.starts_with("pfsync") {
                    continue;
                }
                nics.push(NicInfo {
                    name: name.to_string(),
                    driver: detect_freebsd_nic_driver(name),
                    has_tso: true,
                    has_lro: true,
                    has_rxcsum: true,
                    has_txcsum: true,
                    has_rss: false,
                    rss_queues: 1,
                });
            }
        }
    }

    nics
}

fn read_sys_file(path: &str) -> Option<String> {
    // Try to read the link target (for driver symlinks) or file content
    if let Ok(target) = std::fs::read_link(path) {
        return Some(target.to_string_lossy().to_string());
    }
    std::fs::read_to_string(path).ok()
}

fn check_sys_flag(iface: &str, _flag: &str) -> bool {
    // Simplified — real implementation would parse ethtool -k output
    Path::new(&format!("/sys/class/net/{iface}/device")).exists()
}

fn count_rss_queues(iface: &str) -> usize {
    // Count /sys/class/net/{iface}/queues/rx-*
    let queue_dir = format!("/sys/class/net/{iface}/queues");
    if let Ok(entries) = std::fs::read_dir(&queue_dir) {
        entries
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("rx-"))
            .count()
            .max(1)
    } else {
        1
    }
}

#[cfg(target_os = "freebsd")]
fn detect_freebsd_nic_driver(iface: &str) -> String {
    // Strip trailing digits to get driver name: em0 -> em, igb1 -> igb
    iface.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
}

// ============================================================
// Disk Detection
// ============================================================

fn detect_disk() -> DiskInfo {
    let mut is_ssd = false;
    let mut root_device = "unknown".to_string();

    // Linux: check /sys/block/*/queue/rotational
    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("loop") || name.starts_with("ram") {
                continue;
            }
            let rot_path = format!("/sys/block/{name}/queue/rotational");
            if let Ok(val) = std::fs::read_to_string(&rot_path) {
                if val.trim() == "0" {
                    is_ssd = true;
                }
                root_device = format!("/dev/{name}");
                break;
            }
        }
    }

    // FreeBSD: camcontrol or sysctl
    #[cfg(target_os = "freebsd")]
    {
        if let Ok(out) = std::process::Command::new("sysctl").arg("-n").arg("kern.disks").output() {
            let disks = String::from_utf8_lossy(&out.stdout);
            if let Some(first) = disks.split_whitespace().next() {
                root_device = format!("/dev/{first}");
            }
        }
        // Check for NVMe or SSD indicators
        if let Ok(out) = std::process::Command::new("camcontrol").arg("identify").arg("ada0").output() {
            let output = String::from_utf8_lossy(&out.stdout).to_lowercase();
            if output.contains("solid state") || output.contains("ssd") {
                is_ssd = true;
            }
        }
        if root_device.contains("nvd") || root_device.contains("nvme") {
            is_ssd = true;
        }
    }

    DiskInfo { is_ssd, root_device }
}

// ============================================================
// Crypto Detection
// ============================================================

fn detect_crypto() -> CryptoInfo {
    let cpu = detect_cpu();

    let has_qat = Path::new("/dev/qat_adf_ctl").exists()
        || Path::new("/sys/bus/pci/drivers/qat_c62x").exists()
        || Path::new("/sys/bus/pci/drivers/qat_4xxx").exists();

    let has_arm_crypto = if cfg!(target_arch = "aarch64") {
        // Check /proc/cpuinfo for "aes" feature on ARM
        std::fs::read_to_string("/proc/cpuinfo")
            .map(|s| s.to_lowercase().contains("aes"))
            .unwrap_or(false)
    } else {
        false
    };

    CryptoInfo {
        has_aesni: cpu.has_aesni,
        has_sha_ni: cpu.has_sha_ni,
        has_qat,
        has_arm_crypto,
    }
}
