#[cfg(test)]
mod tests {
    use crate::apply;
    use crate::config::{DefaultPolicy, SetupConfig, WanMode};
    use crate::console;
    use crate::hwdetect::{CpuInfo, CryptoInfo, DiskInfo, MemoryInfo, NicInfo, SystemProfile};
    use crate::totp;
    use crate::tuning;

    #[test]
    fn test_password_validation() {
        assert!(console::validate_password("Abcdef1!").is_ok());
        assert!(console::validate_password("StrongP4ss").is_ok());

        // Too short
        assert!(console::validate_password("Ab1").is_err());
        // No uppercase
        assert!(console::validate_password("abcdefg1").is_err());
        // No lowercase
        assert!(console::validate_password("ABCDEFG1").is_err());
        // No digit
        assert!(console::validate_password("Abcdefgh").is_err());
    }

    #[test]
    fn test_ip_validation() {
        assert!(console::validate_ip("192.168.1.1"));
        assert!(console::validate_ip("10.0.0.1"));
        assert!(console::validate_ip("::1"));
        assert!(!console::validate_ip("not-an-ip"));
        assert!(!console::validate_ip("256.1.1.1"));
    }

    #[test]
    fn test_cidr_validation() {
        assert!(console::validate_cidr("192.168.1.0/24"));
        assert!(console::validate_cidr("10.0.0.0/8"));
        assert!(console::validate_cidr("::1/128"));
        assert!(!console::validate_cidr("192.168.1.0"));
        assert!(!console::validate_cidr("not/valid"));
        assert!(!console::validate_cidr("192.168.1.0/999")); // out of range
    }

    #[test]
    fn test_totp_generate_and_verify() {
        let secret = totp::generate_secret();
        assert!(!secret.is_empty());
        // Can't easily test verify without time control, but ensure it doesn't panic
        assert!(!totp::verify(&secret, "000000")); // almost certainly wrong
    }

    #[test]
    fn test_recovery_codes() {
        let codes = totp::generate_recovery_codes(8);
        assert_eq!(codes.len(), 8);
        // All unique
        let mut u = codes.clone();
        u.sort();
        u.dedup();
        assert_eq!(u.len(), 8);
    }

    #[test]
    fn test_provisioning_uri() {
        let uri = totp::provisioning_uri("JBSWY3DPEHPK3PXP", "admin", "AiFw");
        assert!(uri.starts_with("otpauth://totp/AiFw:admin"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn test_pf_conf_standard() {
        let config = SetupConfig {
            wan_interface: "em0".to_string(),
            lan_interface: Some("em1".to_string()),
            lan_ip: Some("192.168.1.1/24".to_string()),
            api_port: 8080,
            default_policy: DefaultPolicy::Standard,
            nat_enabled: true,
            ..Default::default()
        };
        let pf = apply::generate_pf_conf(&config);

        assert!(pf.contains("wan_if = \"em0\""));
        assert!(pf.contains("lan_if = \"em1\""));
        assert!(pf.contains("block in log all"));
        assert!(pf.contains("pass out all keep state"));
        assert!(pf.contains("antispoof quick for $wan_if"));
        assert!(pf.contains("antispoof quick for $lan_if"));
        assert!(pf.contains("nat on $wan_if"));
        assert!(pf.contains("port 8080"));
        assert!(pf.contains("anchor \"aifw\""));
        assert!(pf.contains("table <bruteforce>"));
        assert!(pf.contains("table <ai_blocked>"));
        assert!(pf.contains("scrub in all"));
        assert!(pf.contains("set skip on lo0"));
        assert!(pf.contains("set skip on pfsync0"));
        assert!(pf.contains("set state-policy floating"));
        assert!(!pf.contains("if-bound"));
    }

    #[test]
    fn test_pf_conf_state_policy_floating() {
        // Verify pf.conf always emits floating state-policy and pfsync skip
        // regardless of cluster config — the pf.conf change is unconditional.
        let config = SetupConfig::default();
        let pf = apply::generate_pf_conf(&config);
        assert!(pf.contains("set state-policy floating"), "expected floating: {pf}");
        assert!(pf.contains("set skip on pfsync0"), "expected pfsync0 skip: {pf}");
        assert!(!pf.contains("if-bound"), "should not contain if-bound: {pf}");
    }

    #[test]
    fn test_pf_conf_strict() {
        let config = SetupConfig {
            default_policy: DefaultPolicy::Strict,
            ..Default::default()
        };
        let pf = apply::generate_pf_conf(&config);
        assert!(pf.contains("block log all"));
        assert!(!pf.contains("pass out all"));
    }

    #[test]
    fn test_pf_conf_permissive() {
        let config = SetupConfig {
            default_policy: DefaultPolicy::Permissive,
            ..Default::default()
        };
        let pf = apply::generate_pf_conf(&config);
        assert!(pf.contains("pass all keep state"));
    }

    #[test]
    fn test_pf_conf_no_lan() {
        let config = SetupConfig {
            lan_interface: None,
            ..Default::default()
        };
        let pf = apply::generate_pf_conf(&config);
        assert!(!pf.contains("lan_if"));
        assert!(!pf.contains("nat on"));
    }

    #[test]
    fn test_config_serialization() {
        let config = SetupConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SetupConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hostname, config.hostname);
        assert_eq!(parsed.api_port, config.api_port);
    }

    #[test]
    fn test_wan_mode_display() {
        assert_eq!(WanMode::Dhcp.to_string(), "DHCP");
        assert_eq!(WanMode::Static.to_string(), "Static");
        assert_eq!(WanMode::Pppoe.to_string(), "PPPoE");
    }

    #[test]
    fn test_default_policy_display() {
        let s = DefaultPolicy::Standard.to_string();
        assert!(s.contains("block inbound"));
    }

    // ── Hardware detection / tuning tests ─────────────────────

    fn mock_profile(cores: usize, ram_mb: u64, aesni: bool) -> SystemProfile {
        SystemProfile {
            cpu: CpuInfo {
                cores,
                threads: cores * 2,
                model: "Test CPU".to_string(),
                has_aesni: aesni,
                has_sha_ni: false,
                has_hyperthreading: cores > 1,
                arch: "x86_64".to_string(),
            },
            memory: MemoryInfo {
                total_mb: ram_mb,
                total_gb: ram_mb as f64 / 1024.0,
            },
            nics: vec![NicInfo {
                name: "em0".to_string(),
                driver: "em".to_string(),
                has_tso: true,
                has_lro: true,
                has_rxcsum: true,
                has_txcsum: true,
                has_rss: true,
                rss_queues: 4,
            }],
            disk: DiskInfo {
                is_ssd: true,
                root_device: "/dev/nvd0".to_string(),
            },
            crypto: CryptoInfo {
                has_aesni: aesni,
                has_sha_ni: false,
                has_qat: false,
                has_arm_crypto: false,
            },
        }
    }

    #[test]
    fn test_scaling_states_hashsize() {
        assert_eq!(tuning::scale_states_hashsize(512), 32768);
        assert_eq!(tuning::scale_states_hashsize(2048), 131072);
        assert_eq!(tuning::scale_states_hashsize(8192), 524288);
        assert_eq!(tuning::scale_states_hashsize(32768), 1048576);
    }

    #[test]
    fn test_scaling_maxsockbuf() {
        assert_eq!(tuning::scale_maxsockbuf(1024), 2097152);
        assert_eq!(tuning::scale_maxsockbuf(4096), 4194304);
        assert_eq!(tuning::scale_maxsockbuf(16384), 16777216);
    }

    #[test]
    fn test_recommendations_include_forwarding() {
        let profile = mock_profile(1, 1024, false);
        let items = tuning::generate_recommendations(&profile);
        assert!(
            items
                .iter()
                .any(|i| i.key == "net.inet.ip.forwarding" && i.value == "1")
        );
        assert!(
            items
                .iter()
                .any(|i| i.key == "net.inet.tcp.syncookies" && i.value == "1")
        );
    }

    #[test]
    fn test_recommendations_aesni_detected() {
        let profile = mock_profile(4, 8192, true);
        let items = tuning::generate_recommendations(&profile);
        assert!(
            items
                .iter()
                .any(|i| i.key == "aesni" && i.target == tuning::TuningTarget::KernelModule)
        );
        assert!(
            items
                .iter()
                .any(|i| i.key == "aesni_load" && i.value == "YES")
        );
    }

    #[test]
    fn test_recommendations_no_aesni() {
        let profile = mock_profile(4, 8192, false);
        let items = tuning::generate_recommendations(&profile);
        assert!(!items.iter().any(|i| i.key == "aesni"));
    }

    #[test]
    fn test_recommendations_multicore_netisr() {
        let profile = mock_profile(8, 16384, true);
        let items = tuning::generate_recommendations(&profile);
        assert!(
            items
                .iter()
                .any(|i| i.key == "net.isr.dispatch" && i.value == "deferred")
        );
        assert!(
            items
                .iter()
                .any(|i| i.key == "net.isr.maxthreads" && i.value == "8")
        );
    }

    #[test]
    fn test_recommendations_singlecore_no_netisr() {
        let profile = mock_profile(1, 1024, false);
        let items = tuning::generate_recommendations(&profile);
        assert!(!items.iter().any(|i| i.key == "net.isr.dispatch"));
    }

    #[test]
    fn test_recommendations_nic_tso_lro_disabled() {
        let profile = mock_profile(2, 4096, false);
        let items = tuning::generate_recommendations(&profile);
        // TSO and LRO should be disabled for firewall
        assert!(
            items
                .iter()
                .any(|i| i.key.contains("tso") && i.value.contains("-tso"))
        );
        assert!(
            items
                .iter()
                .any(|i| i.key.contains("lro") && i.value.contains("-lro"))
        );
    }

    #[test]
    fn test_recommendations_ht_disabled_by_default() {
        let profile = mock_profile(4, 8192, false); // has_hyperthreading = true (threads > cores)
        let items = tuning::generate_recommendations(&profile);
        let ht = items
            .iter()
            .find(|i| i.key == "machdep.hyperthreading_allowed");
        assert!(ht.is_some());
        assert!(!ht.unwrap().enabled); // disabled by default — user must opt in
    }

    #[test]
    fn test_generate_sysctl_conf() {
        let profile = mock_profile(4, 8192, true);
        let items = tuning::generate_recommendations(&profile);
        let sysctl = tuning::generate_sysctl_conf(&items);
        assert!(sysctl.contains("net.inet.ip.forwarding=1"));
        assert!(sysctl.contains("net.inet.tcp.syncookies=1"));
        assert!(sysctl.contains("net.isr.dispatch=deferred"));
    }

    #[test]
    fn test_generate_loader_conf() {
        let profile = mock_profile(2, 4096, true);
        let items = tuning::generate_recommendations(&profile);
        let loader = tuning::generate_loader_conf(&items);
        assert!(loader.contains("aesni_load=\"YES\""));
        assert!(loader.contains("net.pf.states_hashsize"));
    }

    #[test]
    fn test_kernel_modules_list() {
        let profile = mock_profile(2, 4096, true);
        let items = tuning::generate_recommendations(&profile);
        let modules = tuning::kernel_modules_to_load(&items);
        assert!(modules.contains(&"aesni".to_string()));
    }

    #[test]
    fn test_system_profile_summary() {
        let profile = mock_profile(4, 8192, true);
        let lines = profile.summary_lines();
        assert!(lines.iter().any(|l| l.contains("4 cores")));
        assert!(lines.iter().any(|l| l.contains("8.0 GB")));
        assert!(lines.iter().any(|l| l.contains("AES-NI")));
        assert!(lines.iter().any(|l| l.contains("SSD")));
    }

    #[test]
    fn test_ssd_zfs_trim() {
        let profile = mock_profile(1, 1024, false);
        let items = tuning::generate_recommendations(&profile);
        assert!(
            items
                .iter()
                .any(|i| i.key == "vfs.zfs.trim.enabled" && i.value == "1")
        );
    }
}
