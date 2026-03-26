#[cfg(test)]
mod tests {
    use crate::apply;
    use crate::config::{DefaultPolicy, SetupConfig, WanMode};
    use crate::console;
    use crate::totp;

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
}
