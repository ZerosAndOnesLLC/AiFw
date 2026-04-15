use crate::console;
use crate::hwdetect::SystemProfile;
use serde::{Deserialize, Serialize};

/// A single tuning recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningItem {
    pub key: String,
    pub value: String,
    pub target: TuningTarget,
    pub reason: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum TuningTarget {
    Sysctl,
    LoaderConf,
    KernelModule,
    NicConfig,
}

impl std::fmt::Display for TuningTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TuningTarget::Sysctl => write!(f, "sysctl"),
            TuningTarget::LoaderConf => write!(f, "loader.conf"),
            TuningTarget::KernelModule => write!(f, "kldload"),
            TuningTarget::NicConfig => write!(f, "ifconfig"),
        }
    }
}

/// Generate all tuning recommendations based on detected hardware
pub fn generate_recommendations(profile: &SystemProfile) -> Vec<TuningItem> {
    let mut items = Vec::new();

    // ── IP Forwarding (always for a firewall) ────────────────
    items.push(TuningItem {
        key: "net.inet.ip.forwarding".into(),
        value: "1".into(),
        target: TuningTarget::Sysctl,
        reason: "Enable IPv4 packet forwarding (required for routing)".into(),
        enabled: true,
    });
    items.push(TuningItem {
        key: "net.inet6.ip6.forwarding".into(),
        value: "1".into(),
        target: TuningTarget::Sysctl,
        reason: "Enable IPv6 packet forwarding".into(),
        enabled: true,
    });
    items.push(TuningItem {
        key: "net.inet.ip.fastforwarding".into(),
        value: "1".into(),
        target: TuningTarget::Sysctl,
        reason: "Fast path forwarding (skip firewall for established states)".into(),
        enabled: true,
    });

    // ── SYN Flood Protection ─────────────────────────────────
    items.push(TuningItem {
        key: "net.inet.tcp.syncookies".into(),
        value: "1".into(),
        target: TuningTarget::Sysctl,
        reason: "SYN cookie protection against SYN flood attacks".into(),
        enabled: true,
    });

    // ── pf State Table (scale with RAM) ──────────────────────
    let states_hashsize = match profile.memory.total_mb {
        0..=1024 => 32768,
        1025..=4096 => 131072,
        4097..=16384 => 524288,
        _ => 1048576,
    };
    items.push(TuningItem {
        key: "net.pf.states_hashsize".into(),
        value: states_hashsize.to_string(),
        target: TuningTarget::LoaderConf,
        reason: format!("pf state hash table size (scaled for {} MB RAM)", profile.memory.total_mb),
        enabled: true,
    });

    // ── Socket Buffers (scale with RAM) ──────────────────────
    let maxsockbuf = match profile.memory.total_mb {
        0..=2048 => 2097152,     // 2 MB
        2049..=8192 => 4194304,  // 4 MB
        _ => 16777216,           // 16 MB
    };
    items.push(TuningItem {
        key: "kern.ipc.maxsockbuf".into(),
        value: maxsockbuf.to_string(),
        target: TuningTarget::Sysctl,
        reason: format!("Max socket buffer size ({} MB)", maxsockbuf / 1048576),
        enabled: true,
    });

    let tcp_buf = maxsockbuf / 2;
    items.push(TuningItem {
        key: "net.inet.tcp.sendbuf_max".into(),
        value: tcp_buf.to_string(),
        target: TuningTarget::Sysctl,
        reason: "TCP send buffer max".into(),
        enabled: true,
    });
    items.push(TuningItem {
        key: "net.inet.tcp.recvbuf_max".into(),
        value: tcp_buf.to_string(),
        target: TuningTarget::Sysctl,
        reason: "TCP receive buffer max".into(),
        enabled: true,
    });

    // ── Parallel Packet Processing (multi-core) ──────────────
    if profile.cpu.cores > 1 {
        items.push(TuningItem {
            key: "net.isr.dispatch".into(),
            value: "deferred".into(),
            target: TuningTarget::Sysctl,
            reason: format!("Parallel netisr dispatch ({} cores detected)", profile.cpu.cores),
            enabled: true,
        });
        items.push(TuningItem {
            key: "net.isr.maxthreads".into(),
            value: profile.cpu.cores.to_string(),
            target: TuningTarget::Sysctl,
            reason: format!("netisr threads = {} (one per core)", profile.cpu.cores),
            enabled: true,
        });
    }

    // ── DDoS Resilience ──────────────────────────────────────
    let maxfrag = match profile.memory.total_mb {
        0..=2048 => 2048,
        _ => 8192,
    };
    items.push(TuningItem {
        key: "net.inet.ip.maxfragpackets".into(),
        value: maxfrag.to_string(),
        target: TuningTarget::Sysctl,
        reason: "Max fragmented packets in reassembly queue (DDoS resilience)".into(),
        enabled: true,
    });
    items.push(TuningItem {
        key: "net.inet6.ip6.maxfragpackets".into(),
        value: maxfrag.to_string(),
        target: TuningTarget::Sysctl,
        reason: "IPv6 fragment reassembly limit".into(),
        enabled: true,
    });

    // ── Crypto Hardware ──────────────────────────────────────
    if profile.crypto.has_aesni {
        items.push(TuningItem {
            key: "aesni".into(),
            value: "load".into(),
            target: TuningTarget::KernelModule,
            reason: "AES-NI hardware acceleration (detected)".into(),
            enabled: true,
        });
        items.push(TuningItem {
            key: "aesni_load".into(),
            value: "YES".into(),
            target: TuningTarget::LoaderConf,
            reason: "Load AES-NI module at boot".into(),
            enabled: true,
        });
    }

    if profile.crypto.has_arm_crypto {
        items.push(TuningItem {
            key: "armv8crypto".into(),
            value: "load".into(),
            target: TuningTarget::KernelModule,
            reason: "ARM crypto extensions (detected)".into(),
            enabled: true,
        });
        items.push(TuningItem {
            key: "armv8crypto_load".into(),
            value: "YES".into(),
            target: TuningTarget::LoaderConf,
            reason: "Load ARM crypto module at boot".into(),
            enabled: true,
        });
    }

    if profile.crypto.has_qat {
        items.push(TuningItem {
            key: "qat".into(),
            value: "load".into(),
            target: TuningTarget::KernelModule,
            reason: "Intel QAT bulk crypto offload (detected)".into(),
            enabled: true,
        });
        items.push(TuningItem {
            key: "qat_load".into(),
            value: "YES".into(),
            target: TuningTarget::LoaderConf,
            reason: "Load Intel QAT module at boot".into(),
            enabled: true,
        });
    }

    // ── NIC Tuning ───────────────────────────────────────────
    for nic in &profile.nics {
        // Disable TSO on firewall (breaks packet inspection/rewriting)
        if nic.has_tso {
            items.push(TuningItem {
                key: format!("ifconfig_{}_tso", nic.name),
                value: format!("ifconfig {} -tso", nic.name),
                target: TuningTarget::NicConfig,
                reason: format!("{}: disable TSO (interferes with pf packet rewriting)", nic.name),
                enabled: true,
            });
        }

        // Disable LRO on forwarding interfaces
        if nic.has_lro {
            items.push(TuningItem {
                key: format!("ifconfig_{}_lro", nic.name),
                value: format!("ifconfig {} -lro", nic.name),
                target: TuningTarget::NicConfig,
                reason: format!("{}: disable LRO (breaks IP forwarding)", nic.name),
                enabled: true,
            });
        }

        // Enable RSS if available and multi-core
        if nic.has_rss && profile.cpu.cores > 1 {
            let queues = nic.rss_queues.min(profile.cpu.cores);
            items.push(TuningItem {
                key: format!("hw.{}.num_queues", nic.driver),
                value: queues.to_string(),
                target: TuningTarget::Sysctl,
                reason: format!("{}: RSS with {} queues (matched to {} cores)", nic.name, queues, profile.cpu.cores),
                enabled: true,
            });
        }
    }

    // ── Hyperthreading Warning ────────────────────────────────
    if profile.cpu.has_hyperthreading {
        items.push(TuningItem {
            key: "machdep.hyperthreading_allowed".into(),
            value: "0".into(),
            target: TuningTarget::Sysctl,
            reason: "Disable HyperThreading (security hardening — mitigates Spectre/MDS)".into(),
            enabled: false, // disabled by default — user must opt in
        });
    }

    // ── SSD Tuning ───────────────────────────────────────────
    if profile.disk.is_ssd {
        items.push(TuningItem {
            key: "vfs.zfs.trim.enabled".into(),
            value: "1".into(),
            target: TuningTarget::Sysctl,
            reason: "Enable ZFS TRIM for SSD (if using ZFS)".into(),
            enabled: true,
        });
    }

    items
}

/// Interactive tuning wizard step. Shows recommendations and lets user
/// accept defaults or customize each one.
pub fn run_tuning_wizard(profile: &SystemProfile) -> Vec<TuningItem> {
    let mut items = generate_recommendations(profile);

    console::header("Step 4/11 — System Detection & Performance Tuning");

    // Show detected hardware
    console::info("Detected hardware:");
    for line in profile.summary_lines() {
        console::info(&format!("  {line}"));
    }
    println!();

    // Show recommendations summary
    let enabled_count = items.iter().filter(|i| i.enabled).count();
    let disabled_count = items.iter().filter(|i| !i.enabled).count();
    console::info(&format!("{} tuning recommendations ({} enabled, {} optional):",
        items.len(), enabled_count, disabled_count));
    println!();

    for (i, item) in items.iter().enumerate() {
        let status = if item.enabled { "[x]" } else { "[ ]" };
        console::info(&format!(
            "  {:2}. {} {:<40} = {:<12}  ({})",
            i + 1, status, item.key, item.value, item.reason
        ));
    }
    println!();

    // Ask: defaults or customize?
    let choice = console::select(
        "Apply these tuning recommendations?",
        &[
            "Accept all defaults (recommended)",
            "Customize — toggle individual items",
            "Skip tuning entirely",
        ],
        0,
    );

    match choice {
        0 => {
            console::success(&format!("{enabled_count} tunings will be applied"));
        }
        1 => {
            // Let user toggle each item
            println!();
            console::info("Enter item numbers to toggle (space-separated), or 'done' to finish:");
            loop {
                let input = console::prompt("Toggle items", "done");
                if input == "done" || input.is_empty() {
                    break;
                }
                for part in input.split_whitespace() {
                    if let Ok(num) = part.parse::<usize>()
                        && num >= 1 && num <= items.len() {
                            items[num - 1].enabled = !items[num - 1].enabled;
                            let item = &items[num - 1];
                            let state = if item.enabled { "ENABLED" } else { "DISABLED" };
                            console::info(&format!("  {} — {}", item.key, state));
                        }
                }
            }
            let final_count = items.iter().filter(|i| i.enabled).count();
            console::success(&format!("{final_count} tunings will be applied"));
        }
        _ => {
            for item in &mut items {
                item.enabled = false;
            }
            console::info("Tuning skipped. You can run 'aifw-setup --reconfigure' later.");
        }
    }

    items
}

/// Generate sysctl.conf content from enabled tuning items
pub fn generate_sysctl_conf(items: &[TuningItem]) -> String {
    let mut lines = vec![
        "# AiFw — Generated sysctl.conf".to_string(),
        format!("# Generated by aifw-setup on {}", chrono::Utc::now().to_rfc3339()),
        String::new(),
    ];

    for item in items.iter().filter(|i| i.enabled && i.target == TuningTarget::Sysctl) {
        lines.push(format!("# {}", item.reason));
        lines.push(format!("{}={}", item.key, item.value));
    }

    lines.join("\n")
}

/// Generate loader.conf content from enabled tuning items
pub fn generate_loader_conf(items: &[TuningItem]) -> String {
    let mut lines = vec![
        "# AiFw — Generated loader.conf".to_string(),
        format!("# Generated by aifw-setup on {}", chrono::Utc::now().to_rfc3339()),
        String::new(),
    ];

    for item in items.iter().filter(|i| i.enabled && i.target == TuningTarget::LoaderConf) {
        lines.push(format!("# {}", item.reason));
        lines.push(format!("{}=\"{}\"", item.key, item.value));
    }

    lines.join("\n")
}

/// Generate NIC configuration commands
pub fn generate_nic_commands(items: &[TuningItem]) -> Vec<String> {
    items
        .iter()
        .filter(|i| i.enabled && i.target == TuningTarget::NicConfig)
        .map(|i| i.value.clone())
        .collect()
}

/// Get list of kernel modules to load
pub fn kernel_modules_to_load(items: &[TuningItem]) -> Vec<String> {
    items
        .iter()
        .filter(|i| i.enabled && i.target == TuningTarget::KernelModule)
        .map(|i| i.key.clone())
        .collect()
}

// ============================================================
// Scaling helpers (used in tests)
// ============================================================

#[cfg(test)]
pub fn scale_states_hashsize(ram_mb: u64) -> u64 {
    match ram_mb {
        0..=1024 => 32768,
        1025..=4096 => 131072,
        4097..=16384 => 524288,
        _ => 1048576,
    }
}

#[cfg(test)]
pub fn scale_maxsockbuf(ram_mb: u64) -> u64 {
    match ram_mb {
        0..=2048 => 2097152,
        2049..=8192 => 4194304,
        _ => 16777216,
    }
}
