#[cfg(test)]
mod tests {
    use crate::nat::*;
    use crate::ratelimit::*;
    use crate::rule::*;
    use crate::types::*;
    use crate::vpn::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_address_parse_any() {
        assert_eq!(Address::parse("any").unwrap(), Address::Any);
    }

    #[test]
    fn test_address_parse_single_ipv4() {
        let addr = Address::parse("192.168.1.1").unwrap();
        assert_eq!(
            addr,
            Address::Single(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
    }

    #[test]
    fn test_address_parse_single_ipv6() {
        let addr = Address::parse("::1").unwrap();
        assert_eq!(
            addr,
            Address::Single(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn test_address_parse_network() {
        let addr = Address::parse("10.0.0.0/8").unwrap();
        assert_eq!(
            addr,
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)
        );
    }

    #[test]
    fn test_address_parse_table() {
        let addr = Address::parse("<blocklist>").unwrap();
        assert_eq!(addr, Address::Table("blocklist".to_string()));
    }

    #[test]
    fn test_address_display() {
        assert_eq!(Address::Any.to_string(), "any");
        assert_eq!(
            Address::Single(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).to_string(),
            "1.2.3.4"
        );
        assert_eq!(
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8).to_string(),
            "10.0.0.0/8"
        );
        assert_eq!(
            Address::Table("bruteforce".to_string()).to_string(),
            "<bruteforce>"
        );
    }

    #[test]
    fn test_protocol_parse() {
        assert_eq!(Protocol::parse("tcp").unwrap(), Protocol::Tcp);
        assert_eq!(Protocol::parse("UDP").unwrap(), Protocol::Udp);
        assert_eq!(Protocol::parse("icmp").unwrap(), Protocol::Icmp);
        assert_eq!(Protocol::parse("any").unwrap(), Protocol::Any);
        assert!(Protocol::parse("bogus").is_err());
    }

    #[test]
    fn test_port_range_display() {
        let single = PortRange {
            start: 80,
            end: 80,
        };
        assert_eq!(single.to_string(), "80");

        let range = PortRange {
            start: 8000,
            end: 9000,
        };
        assert_eq!(range.to_string(), "8000:9000");
    }

    #[test]
    fn test_rule_to_pf_block_ssh() {
        let rule = Rule::new(
            Action::Block,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange {
                    start: 22,
                    end: 22,
                }),
            },
        );
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(pf, "block in quick proto tcp to any port 22 keep state");
    }

    #[test]
    fn test_rule_to_pf_pass_web() {
        let mut rule = Rule::new(
            Action::Pass,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
            },
        );
        rule.log = true;
        rule.label = Some("allow-https".to_string());
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(
            pf,
            "pass in quick proto tcp to any port 443 keep state log label \"allow-https\""
        );
    }

    #[test]
    fn test_rule_to_pf_block_network() {
        let rule = Rule::new(
            Action::BlockDrop,
            Direction::In,
            Protocol::Any,
            RuleMatch {
                src_addr: Address::Network(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24),
                src_port: None,
                dst_addr: Address::Any,
                dst_port: None,
            },
        );
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(pf, "block drop in quick from 192.168.1.0/24 keep state");
    }

    #[test]
    fn test_rule_to_pf_table() {
        let rule = Rule::new(
            Action::BlockReturn,
            Direction::In,
            Protocol::Any,
            RuleMatch {
                src_addr: Address::Table("bruteforce".to_string()),
                src_port: None,
                dst_addr: Address::Any,
                dst_port: None,
            },
        );
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(pf, "block return in quick from <bruteforce> keep state");
    }

    #[test]
    fn test_rule_to_pf_modulate_state() {
        let mut rule = Rule::new(
            Action::Pass,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange { start: 22, end: 22 }),
            },
        );
        rule.state_options.tracking = StateTracking::ModulateState;
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(pf, "pass in quick proto tcp to any port 22 modulate state");
    }

    #[test]
    fn test_rule_to_pf_synproxy_state() {
        let mut rule = Rule::new(
            Action::Pass,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange { start: 80, end: 80 }),
            },
        );
        rule.state_options.tracking = StateTracking::SynproxyState;
        rule.state_options.policy = Some(StatePolicy::IfBound);
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(pf, "pass in quick proto tcp to any port 80 synproxy state (if-bound)");
    }

    #[test]
    fn test_rule_to_pf_no_state() {
        let mut rule = Rule::new(
            Action::Block,
            Direction::In,
            Protocol::Any,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: None,
            },
        );
        rule.state_options.tracking = StateTracking::None;
        let pf = rule.to_pf_rule("aifw");
        assert_eq!(pf, "block in quick");
    }

    // --- NAT tests ---

    #[test]
    fn test_nat_type_parse() {
        assert_eq!(NatType::parse("snat").unwrap(), NatType::Snat);
        assert_eq!(NatType::parse("dnat").unwrap(), NatType::Dnat);
        assert_eq!(NatType::parse("rdr").unwrap(), NatType::Dnat);
        assert_eq!(NatType::parse("masquerade").unwrap(), NatType::Masquerade);
        assert_eq!(NatType::parse("masq").unwrap(), NatType::Masquerade);
        assert_eq!(NatType::parse("binat").unwrap(), NatType::Binat);
        assert_eq!(NatType::parse("nat64").unwrap(), NatType::Nat64);
        assert_eq!(NatType::parse("nat46").unwrap(), NatType::Nat46);
        assert!(NatType::parse("bogus").is_err());
    }

    #[test]
    fn test_nat_snat_pf_rule() {
        let rule = NatRule::new(
            NatType::Snat,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Network(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24),
            Address::Any,
            NatRedirect {
                address: Address::Single(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
                port: None,
            },
        );
        let pf = rule.to_pf_rule();
        assert_eq!(pf, "nat on em0 from 192.168.1.0/24 to any -> 203.0.113.1");
    }

    #[test]
    fn test_nat_dnat_pf_rule() {
        let mut rule = NatRule::new(
            NatType::Dnat,
            Interface("em0".to_string()),
            Protocol::Tcp,
            Address::Any,
            Address::Single(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            NatRedirect {
                address: Address::Single(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
                port: Some(PortRange { start: 8080, end: 8080 }),
            },
        );
        rule.dst_port = Some(PortRange { start: 80, end: 80 });
        let pf = rule.to_pf_rule();
        assert_eq!(
            pf,
            "rdr on em0 proto tcp to 203.0.113.1 port 80 -> 192.168.1.10 port 8080"
        );
    }

    #[test]
    fn test_nat_masquerade_pf_rule() {
        let rule = NatRule::new(
            NatType::Masquerade,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            Address::Any,
            NatRedirect {
                address: Address::Any,
                port: None,
            },
        );
        let pf = rule.to_pf_rule();
        assert_eq!(pf, "nat on em0 from 10.0.0.0/8 to any -> (em0)");
    }

    #[test]
    fn test_nat_binat_pf_rule() {
        let rule = NatRule::new(
            NatType::Binat,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Single(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            Address::Any,
            NatRedirect {
                address: Address::Single(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
                port: None,
            },
        );
        let pf = rule.to_pf_rule();
        assert_eq!(
            pf,
            "binat on em0 from 192.168.1.10 to any -> 203.0.113.10"
        );
    }

    #[test]
    fn test_nat_with_label() {
        let mut rule = NatRule::new(
            NatType::Snat,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            Address::Any,
            NatRedirect {
                address: Address::Single(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                port: None,
            },
        );
        rule.label = Some("outbound-nat".to_string());
        let pf = rule.to_pf_rule();
        assert!(pf.ends_with("label \"outbound-nat\""));
    }

    #[test]
    fn test_nat64_pf_rule() {
        let rule = NatRule::new(
            NatType::Nat64,
            Interface("em0".to_string()),
            Protocol::Any,
            Address::Network(IpAddr::V6("64:ff9b::".parse().unwrap()), 96),
            Address::Any,
            NatRedirect {
                address: Address::Single(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0))),
                port: None,
            },
        );
        let pf = rule.to_pf_rule();
        assert!(pf.starts_with("nat on em0 inet6"));
    }

    // --- Rate limiting / queue tests ---

    #[test]
    fn test_bandwidth_parse() {
        let bw = Bandwidth::parse("100Mb").unwrap();
        assert_eq!(bw.value, 100);
        assert_eq!(bw.unit, BandwidthUnit::Mbps);
        assert_eq!(bw.to_bits_per_sec(), 100_000_000);

        let bw = Bandwidth::parse("1Gb").unwrap();
        assert_eq!(bw.to_bits_per_sec(), 1_000_000_000);

        let bw = Bandwidth::parse("500Kb").unwrap();
        assert_eq!(bw.to_string(), "500Kb");
    }

    #[test]
    fn test_bandwidth_display() {
        let bw = Bandwidth { value: 10, unit: BandwidthUnit::Mbps };
        assert_eq!(bw.to_string(), "10Mb");
        let bw = Bandwidth { value: 1000, unit: BandwidthUnit::Bps };
        assert_eq!(bw.to_string(), "1000b");
    }

    #[test]
    fn test_queue_type_parse() {
        assert_eq!(QueueType::parse("codel").unwrap(), QueueType::Codel);
        assert_eq!(QueueType::parse("hfsc").unwrap(), QueueType::Hfsc);
        assert_eq!(QueueType::parse("priq").unwrap(), QueueType::Priq);
        assert!(QueueType::parse("bogus").is_err());
    }

    #[test]
    fn test_traffic_class_priority() {
        assert!(TrafficClass::Voip.priority() > TrafficClass::Interactive.priority());
        assert!(TrafficClass::Interactive.priority() > TrafficClass::Default.priority());
        assert!(TrafficClass::Default.priority() > TrafficClass::Bulk.priority());
    }

    #[test]
    fn test_queue_config_pf() {
        let mut q = QueueConfig::new(
            Interface("em0".to_string()),
            QueueType::Priq,
            Bandwidth { value: 100, unit: BandwidthUnit::Mbps },
            "voip_queue".to_string(),
            TrafficClass::Voip,
        );
        q.default = false;
        let pf = q.to_pf_queue();
        assert!(pf.contains("queue voip_queue"));
        assert!(pf.contains("priority 7"));

        assert_eq!(q.to_pf_parent_queue(), "queue on em0 bandwidth 100Mb");
    }

    #[test]
    fn test_queue_config_default() {
        let mut q = QueueConfig::new(
            Interface("em0".to_string()),
            QueueType::Codel,
            Bandwidth { value: 50, unit: BandwidthUnit::Mbps },
            "std".to_string(),
            TrafficClass::Default,
        );
        q.default = true;
        let pf = q.to_pf_queue();
        assert!(pf.contains("default"));
    }

    #[test]
    fn test_queue_config_bandwidth_pct() {
        let mut q = QueueConfig::new(
            Interface("em0".to_string()),
            QueueType::Hfsc,
            Bandwidth { value: 100, unit: BandwidthUnit::Mbps },
            "web".to_string(),
            TrafficClass::Default,
        );
        q.bandwidth_pct = Some(30);
        let pf = q.to_pf_queue();
        assert!(pf.contains("bandwidth 30%"));
    }

    #[test]
    fn test_rate_limit_pf_rule() {
        let mut rl = RateLimitRule::new(
            "ssh-brute".to_string(),
            Protocol::Tcp,
            5,
            30,
            "bruteforce".to_string(),
        );
        rl.dst_port = Some(PortRange { start: 22, end: 22 });
        let pf = rl.to_pf_rule();
        assert!(pf.contains("proto tcp"));
        assert!(pf.contains("port 22"));
        assert!(pf.contains("max-src-conn 5"));
        assert!(pf.contains("max-src-conn-rate 5/30"));
        assert!(pf.contains("overload <bruteforce>"));
        assert!(pf.contains("flush global"));
    }

    #[test]
    fn test_rate_limit_table() {
        let rl = RateLimitRule::new(
            "test".to_string(),
            Protocol::Tcp,
            10,
            60,
            "flood".to_string(),
        );
        assert_eq!(rl.to_pf_table(), "table <flood> persist");
        assert!(rl.to_pf_block_rule().contains("block in quick from <flood>"));
    }

    #[test]
    fn test_rate_limit_no_flush() {
        let mut rl = RateLimitRule::new(
            "test".to_string(),
            Protocol::Tcp,
            10,
            60,
            "overload".to_string(),
        );
        rl.flush_states = false;
        let pf = rl.to_pf_rule();
        assert!(!pf.contains("flush"));
    }

    #[test]
    fn test_syn_flood_config() {
        let cfg = SynFloodConfig {
            interface: Interface("em0".to_string()),
            max_src_conn: 100,
            max_src_conn_rate: 15,
            rate_window_secs: 5,
            overload_table: "synflood".to_string(),
        };
        let rules = cfg.to_pf_rules();
        assert_eq!(rules.len(), 3);
        assert!(rules[0].contains("table <synflood>"));
        assert!(rules[1].contains("block in quick from <synflood>"));
        assert!(rules[2].contains("max-src-conn 100"));
        assert!(rules[2].contains("max-src-conn-rate 15/5"));
    }

    // --- VPN tests ---

    #[test]
    fn test_wg_tunnel_creation() {
        let tunnel = WgTunnel::new(
            "wg0-tunnel".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24),
        );
        assert_eq!(tunnel.name, "wg0-tunnel");
        assert_eq!(tunnel.listen_port, 51820);
        assert!(!tunnel.private_key.is_empty());
        assert!(!tunnel.public_key.is_empty());
        assert_ne!(tunnel.private_key, tunnel.public_key);
        assert_eq!(tunnel.status, VpnStatus::Down);
    }

    #[test]
    fn test_wg_tunnel_pf_rules() {
        let tunnel = WgTunnel::new(
            "wg0".to_string(),
            Interface("wg0".to_string()),
            51820,
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 24),
        );
        let rules = tunnel.to_pf_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].contains("proto udp"));
        assert!(rules[0].contains("port 51820"));
        assert!(rules[1].contains("on wg0"));
    }

    #[test]
    fn test_wg_peer_cmd() {
        let mut peer = WgPeer::new(
            uuid::Uuid::new_v4(),
            "office".to_string(),
            "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789+/=AAA=".to_string(),
        );
        peer.endpoint = Some("1.2.3.4:51820".to_string());
        peer.allowed_ips = vec![
            Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24),
        ];
        peer.persistent_keepalive = Some(25);

        let cmd = peer.to_wg_cmd(&Interface("wg0".to_string()));
        assert!(cmd.contains("wg set wg0 peer"));
        assert!(cmd.contains("endpoint 1.2.3.4:51820"));
        assert!(cmd.contains("allowed-ips 10.0.0.0/24"));
        assert!(cmd.contains("persistent-keepalive 25"));
    }

    #[test]
    fn test_ipsec_sa_pf_rules() {
        let sa = IpsecSa::new(
            "office-vpn".to_string(),
            Address::Single(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))),
            Address::Single(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            IpsecProtocol::Esp,
            IpsecMode::Tunnel,
        );
        let rules = sa.to_pf_rules();
        assert_eq!(rules.len(), 5); // 2 esp + 2 ike + 1 enc0
        assert!(rules[0].contains("proto esp"));
        assert!(rules[2].contains("port { 500 4500 }"));
        assert!(rules[4].contains("on enc0"));
    }

    #[test]
    fn test_ipsec_transport_mode() {
        let sa = IpsecSa::new(
            "host-to-host".to_string(),
            Address::Single(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            Address::Single(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))),
            IpsecProtocol::Esp,
            IpsecMode::Transport,
        );
        let rules = sa.to_pf_rules();
        assert_eq!(rules.len(), 4); // no enc0 rule in transport mode
    }

    #[test]
    fn test_ipsec_protocol_parse() {
        assert_eq!(IpsecProtocol::parse("esp").unwrap(), IpsecProtocol::Esp);
        assert_eq!(IpsecProtocol::parse("ah").unwrap(), IpsecProtocol::Ah);
        assert_eq!(IpsecProtocol::parse("esp+ah").unwrap(), IpsecProtocol::EspAh);
        assert!(IpsecProtocol::parse("bogus").is_err());
    }

    #[test]
    fn test_wg_key_generation() {
        let (priv1, pub1) = generate_wg_keypair();
        let (priv2, pub2) = generate_wg_keypair();
        // Keys should be non-empty and different each time
        assert!(!priv1.is_empty());
        assert!(!pub1.is_empty());
        assert_ne!(priv1, priv2);
        assert_ne!(pub1, pub2);
    }
}
