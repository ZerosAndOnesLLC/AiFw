#[cfg(test)]
mod tests {
    use crate::geoip::*;
    use crate::ha::*;
    use crate::nat::*;
    use crate::ratelimit::*;
    use crate::rule::*;
    use crate::tls::*;
    use crate::types::*;
    use crate::vpn::*;
    use chrono::Utc;
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
        assert_eq!(addr, Address::Single(IpAddr::V6(Ipv6Addr::LOCALHOST)));
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
        let single = PortRange { start: 80, end: 80 };
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
                dst_port: Some(PortRange { start: 22, end: 22 }),
            },
        );
        let pf = rule.to_pf_rule("aifw");
        // Block rules always log, state tracking only on pass rules
        assert_eq!(pf, "block in log quick proto tcp to any port 22");
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
        // log comes before quick in pf syntax
        assert_eq!(
            pf,
            "pass in log quick proto tcp to any port 443 keep state label \"allow-https\""
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
        // block drop doesn't auto-log (only plain "block" does), no state tracking on block
        assert_eq!(pf, "block drop in quick from 192.168.1.0/24");
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
        assert_eq!(pf, "block return in quick from <bruteforce>");
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
        assert_eq!(
            pf,
            "pass in quick proto tcp to any port 80 synproxy state (if-bound)"
        );
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
        // Block rules always log
        assert_eq!(pf, "block in log quick");
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
                port: Some(PortRange {
                    start: 8080,
                    end: 8080,
                }),
            },
        );
        rule.dst_port = Some(PortRange { start: 80, end: 80 });
        let pf = rule.to_pf_rule();
        // DNAT emits two rules: the rdr itself and a NAT reflection rule
        // that SNATs forwarded traffic so replies route back through the
        // firewall (fixes asymmetric routing — commit 492b947).
        assert_eq!(
            pf,
            "rdr on em0 proto tcp to 203.0.113.1 port 80 -> 192.168.1.10 port 8080\n\
             nat on em0 proto tcp from any to 192.168.1.10 port 8080 -> (em0)"
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
        assert_eq!(pf, "binat on em0 from 192.168.1.10 to any -> 203.0.113.10");
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
        // pf NAT rules don't support labels — label stored in DB for UI only
        assert!(pf.starts_with("nat on em0"));
        assert!(!pf.contains("label"));
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
        let bw = Bandwidth {
            value: 10,
            unit: BandwidthUnit::Mbps,
        };
        assert_eq!(bw.to_string(), "10Mb");
        let bw = Bandwidth {
            value: 1000,
            unit: BandwidthUnit::Bps,
        };
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
            Bandwidth {
                value: 100,
                unit: BandwidthUnit::Mbps,
            },
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
            Bandwidth {
                value: 50,
                unit: BandwidthUnit::Mbps,
            },
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
            Bandwidth {
                value: 100,
                unit: BandwidthUnit::Mbps,
            },
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
        assert!(
            rl.to_pf_block_rule()
                .contains("block in quick from <flood>")
        );
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
        peer.allowed_ips = vec![Address::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24)];
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
        assert_eq!(
            IpsecProtocol::parse("esp+ah").unwrap(),
            IpsecProtocol::EspAh
        );
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

    // --- Geo-IP tests ---

    #[test]
    fn test_country_code_valid() {
        assert!(CountryCode::new("US").is_ok());
        assert!(CountryCode::new("cn").is_ok()); // auto-uppercase
        assert_eq!(CountryCode::new("ru").unwrap().0, "RU");
    }

    #[test]
    fn test_country_code_invalid() {
        assert!(CountryCode::new("").is_err());
        assert!(CountryCode::new("A").is_err());
        assert!(CountryCode::new("ABC").is_err());
        assert!(CountryCode::new("12").is_err());
    }

    #[test]
    fn test_geoip_action_parse() {
        assert_eq!(GeoIpAction::parse("block").unwrap(), GeoIpAction::Block);
        assert_eq!(GeoIpAction::parse("allow").unwrap(), GeoIpAction::Allow);
        assert_eq!(GeoIpAction::parse("deny").unwrap(), GeoIpAction::Block);
        assert_eq!(GeoIpAction::parse("pass").unwrap(), GeoIpAction::Allow);
        assert!(GeoIpAction::parse("bogus").is_err());
    }

    #[test]
    fn test_geoip_rule_pf() {
        let rule = GeoIpRule::new(CountryCode::new("CN").unwrap(), GeoIpAction::Block);
        assert_eq!(rule.table_name(), "geoip_cn");
        assert_eq!(rule.to_pf_table(), "table <geoip_cn> persist");
        let pf = rule.to_pf_rule();
        assert!(pf.contains("block drop in quick from <geoip_cn>"));
    }

    #[test]
    fn test_geoip_rule_allow() {
        let mut rule = GeoIpRule::new(CountryCode::new("US").unwrap(), GeoIpAction::Allow);
        rule.label = Some("us-traffic".to_string());
        let pf = rule.to_pf_rule();
        assert!(pf.contains("pass in quick from <geoip_us>"));
        assert!(pf.contains("us-traffic"));
    }

    #[test]
    fn test_cidr_aggregation_removes_subnets() {
        let entries = vec![
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            (IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16), // subnet of /8
            (IpAddr::V4(Ipv4Addr::new(10, 2, 0, 0)), 16), // subnet of /8
        ];
        let result = aggregate_cidrs(entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, 8);
    }

    #[test]
    fn test_cidr_aggregation_merges_adjacent() {
        let entries = vec![
            (IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)), 24),
            (IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24),
        ];
        let result = aggregate_cidrs(entries);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, 23); // merged into /23
    }

    #[test]
    fn test_cidr_aggregation_no_merge() {
        let entries = vec![
            (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24),
            (IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 24),
        ];
        let result = aggregate_cidrs(entries);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_geolite2_csv_parse() {
        let blocks = "network,geoname_id,registered_country_geoname_id\n\
                       1.0.0.0/24,2077456,2077456\n\
                       1.0.1.0/24,1814991,1814991\n";
        let locations = "geoname_id,locale_code,continent_code,continent_name,country_iso_code\n\
                         2077456,en,OC,Oceania,AU\n\
                         1814991,en,AS,Asia,CN\n";

        let blocks_parsed = parse_geolite2_blocks_csv(blocks);
        assert_eq!(blocks_parsed.len(), 2);
        assert_eq!(blocks_parsed[0].2, 2077456); // AU geoname

        let locs = parse_geolite2_locations_csv(locations);
        assert_eq!(locs.get(&2077456).unwrap(), "AU");
        assert_eq!(locs.get(&1814991).unwrap(), "CN");
    }

    // --- TLS tests ---

    #[test]
    fn test_tls_version_parse() {
        assert_eq!(TlsVersion::parse("tls12").unwrap(), TlsVersion::Tls12);
        assert_eq!(TlsVersion::parse("TLS13").unwrap(), TlsVersion::Tls13);
        assert_eq!(TlsVersion::parse("ssl30").unwrap(), TlsVersion::Ssl30);
        assert!(TlsVersion::parse("bogus").is_err());
    }

    #[test]
    fn test_tls_version_deprecated() {
        assert!(TlsVersion::Ssl30.is_deprecated());
        assert!(TlsVersion::Tls10.is_deprecated());
        assert!(TlsVersion::Tls11.is_deprecated());
        assert!(!TlsVersion::Tls12.is_deprecated());
        assert!(!TlsVersion::Tls13.is_deprecated());
    }

    #[test]
    fn test_tls_version_ordering() {
        assert!(TlsVersion::Tls13 > TlsVersion::Tls12);
        assert!(TlsVersion::Tls12 > TlsVersion::Tls11);
        assert!(TlsVersion::Tls11 > TlsVersion::Tls10);
    }

    #[test]
    fn test_tls_version_from_protocol() {
        assert_eq!(
            TlsVersion::from_protocol_version(3, 3),
            Some(TlsVersion::Tls12)
        );
        assert_eq!(
            TlsVersion::from_protocol_version(3, 4),
            Some(TlsVersion::Tls13)
        );
        assert_eq!(TlsVersion::from_protocol_version(4, 0), None);
    }

    #[test]
    fn test_ja3_fingerprint() {
        let ja3 = Ja3Fingerprint::compute(
            771, // TLS 1.2
            &[49195, 49199, 49196, 49200, 52393, 52392],
            &[0, 23, 65281, 10, 11, 35],
            &[29, 23, 24],
            &[0],
        );
        assert!(!ja3.hash.is_empty());
        assert_eq!(ja3.hash.len(), 32); // MD5 hex = 32 chars
        assert!(ja3.raw.contains("771,"));
    }

    #[test]
    fn test_ja3s_fingerprint() {
        let ja3s = Ja3sFingerprint::compute(771, 49199, &[65281, 0, 11]);
        assert_eq!(ja3s.hash.len(), 32);
        assert!(ja3s.raw.starts_with("771,49199,"));
    }

    #[test]
    fn test_ja3_deterministic() {
        let a = Ja3Fingerprint::compute(771, &[49195], &[0], &[29], &[0]);
        let b = Ja3Fingerprint::compute(771, &[49195], &[0], &[29], &[0]);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn test_sni_rule_exact_match() {
        let rule = SniRule::new("example.com".to_string(), SniAction::Block);
        assert!(rule.matches("example.com"));
        assert!(rule.matches("Example.COM"));
        assert!(!rule.matches("sub.example.com"));
        assert!(!rule.matches("notexample.com"));
    }

    #[test]
    fn test_sni_rule_wildcard() {
        let rule = SniRule::new("*.example.com".to_string(), SniAction::Block);
        assert!(rule.matches("sub.example.com"));
        assert!(rule.matches("a.b.example.com"));
        assert!(rule.matches("example.com")); // bare domain matches too
        assert!(!rule.matches("example.org"));
    }

    #[test]
    fn test_tls_policy_version_check() {
        let policy = TlsPolicy::default(); // min = TLS 1.2
        assert!(!policy.is_version_allowed(TlsVersion::Ssl30));
        assert!(!policy.is_version_allowed(TlsVersion::Tls10));
        assert!(!policy.is_version_allowed(TlsVersion::Tls11));
        assert!(policy.is_version_allowed(TlsVersion::Tls12));
        assert!(policy.is_version_allowed(TlsVersion::Tls13));
    }

    #[test]
    fn test_tls_policy_cert_validation() {
        let policy = TlsPolicy::default();

        let valid_cert = CertInfo {
            subject: "CN=example.com".to_string(),
            issuer: "CN=Let's Encrypt".to_string(),
            serial: "abc123".to_string(),
            not_before: Utc::now() - chrono::Duration::days(30),
            not_after: Utc::now() + chrono::Duration::days(60),
            san: vec!["example.com".to_string()],
            is_self_signed: false,
            key_bits: 2048,
        };
        assert!(policy.validate_cert(&valid_cert).is_empty());

        let expired = CertInfo {
            not_after: Utc::now() - chrono::Duration::days(1),
            ..valid_cert.clone()
        };
        let violations = policy.validate_cert(&expired);
        assert!(violations.iter().any(|v| v.contains("expired")));

        let weak = CertInfo {
            key_bits: 1024,
            ..valid_cert.clone()
        };
        let violations = policy.validate_cert(&weak);
        assert!(violations.iter().any(|v| v.contains("weak")));
    }

    #[test]
    fn test_mitm_proxy_pf_rules() {
        let config = MitmProxyConfig {
            enabled: true,
            listen_port: 8443,
            interface: Interface("em0".to_string()),
            intercept_ports: vec![443, 8443],
            ..Default::default()
        };
        let rules = config.to_pf_rdr_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].contains("rdr on em0"));
        assert!(rules[0].contains("port 443"));
        assert!(rules[0].contains("-> 127.0.0.1 port 8443"));
    }

    #[test]
    fn test_mitm_disabled_no_rules() {
        let config = MitmProxyConfig::default(); // enabled = false
        assert!(config.to_pf_rdr_rules().is_empty());
    }

    #[test]
    fn test_ja3_blocklist_in_policy() {
        let mut policy = TlsPolicy::default();
        policy.blocked_ja3.push("abc123def456".to_string());
        assert!(policy.is_ja3_blocked("abc123def456"));
        assert!(!policy.is_ja3_blocked("other_hash"));
    }

    // --- HA / Clustering tests ---

    #[test]
    fn test_carp_vip_creation() {
        let vip = CarpVip::new(
            1,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100)),
            24,
            Interface("em0".to_string()),
            "s3cret".to_string(),
        );
        assert_eq!(vip.vhid, 1);
        assert_eq!(vip.status, CarpStatus::Init);
        assert_eq!(vip.advskew, 0);
    }

    #[test]
    fn test_carp_ifconfig_cmds() {
        let vip = CarpVip::new(
            5,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            24,
            Interface("em0".to_string()),
            "pass123".to_string(),
        );
        // Use Standalone so the stored advskew (0) is used as-is
        let cmds = vip.to_ifconfig_cmds_for_role(ClusterRole::Standalone);
        assert_eq!(cmds.len(), 1);
        let argv = &cmds[0];
        assert!(argv.contains(&"vhid".to_string()));
        assert!(argv.contains(&"5".to_string()));
        assert!(argv.contains(&"pass".to_string()));
        assert!(argv.contains(&"pass123".to_string()));
        assert!(argv.contains(&"192.168.1.100/24".to_string()));
        assert!(argv.contains(&"inet".to_string()));
        // Ensure the password is a discrete argument, not embedded in a shell string
        assert!(!argv[0].contains("sh"));
    }

    #[test]
    fn test_carp_pf_rules() {
        let vip = CarpVip::new(
            1,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            24,
            Interface("em0".to_string()),
            "pw".to_string(),
        );
        let rules = vip.to_pf_rules();
        assert_eq!(rules.len(), 1);
        assert!(rules[0].contains("proto carp"));
        assert!(rules[0].contains("carp-vhid-1"));
    }

    #[test]
    fn test_pfsync_ifconfig_cmds() {
        let mut config = PfsyncConfig::new(Interface("em1".to_string()));
        config.sync_peer = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

        let cmds = config.to_ifconfig_cmds();
        assert_eq!(cmds.len(), 2);
        // First argv: ifconfig pfsync0 create
        assert_eq!(cmds[0], vec!["ifconfig", "pfsync0", "create"]);
        // Second argv: ifconfig pfsync0 syncdev em1 syncpeer 10.0.0.2 defer up
        let config_argv = &cmds[1];
        assert!(config_argv.contains(&"syncdev".to_string()));
        assert!(config_argv.contains(&"em1".to_string()));
        assert!(config_argv.contains(&"syncpeer".to_string()));
        assert!(config_argv.contains(&"10.0.0.2".to_string()));
        assert!(config_argv.contains(&"defer".to_string()));
    }

    #[test]
    fn test_pfsync_disabled() {
        let mut config = PfsyncConfig::new(Interface("em1".to_string()));
        config.enabled = false;
        assert!(config.to_ifconfig_cmds().is_empty());
        assert!(config.to_pf_rules().is_empty());
    }

    #[test]
    fn test_pfsync_pf_rules() {
        let mut config = PfsyncConfig::new(Interface("em1".to_string()));
        config.sync_peer = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let rules = config.to_pf_rules();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].contains("proto pfsync"));
        assert!(rules[1].contains("from 10.0.0.2"));
    }

    #[test]
    fn test_cluster_role_parse() {
        assert_eq!(ClusterRole::parse("primary").unwrap(), ClusterRole::Primary);
        assert_eq!(
            ClusterRole::parse("secondary").unwrap(),
            ClusterRole::Secondary
        );
        assert_eq!(ClusterRole::parse("master").unwrap(), ClusterRole::Primary);
        assert_eq!(
            ClusterRole::parse("backup").unwrap(),
            ClusterRole::Secondary
        );
        assert!(ClusterRole::parse("bogus").is_err());
    }

    #[test]
    fn test_cluster_node() {
        let node = ClusterNode::new(
            "fw1".to_string(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ClusterRole::Primary,
        );
        assert_eq!(node.health, NodeHealth::Unknown);
        assert!(!node.is_reachable());
    }

    #[test]
    fn test_health_check_type_parse() {
        assert_eq!(
            HealthCheckType::parse("ping").unwrap(),
            HealthCheckType::Ping
        );
        assert_eq!(
            HealthCheckType::parse("tcp").unwrap(),
            HealthCheckType::TcpPort
        );
        assert_eq!(
            HealthCheckType::parse("http").unwrap(),
            HealthCheckType::HttpGet
        );
        assert_eq!(
            HealthCheckType::parse("pf").unwrap(),
            HealthCheckType::PfStatus
        );
        assert!(HealthCheckType::parse("bogus").is_err());
    }

    #[test]
    fn carp_advskew_renders_per_role() {
        use crate::{CarpVip, ClusterRole, Interface};
        use std::net::IpAddr;

        let mut vip = CarpVip::new(
            10,
            "192.0.2.1".parse::<IpAddr>().unwrap(),
            24,
            Interface("igb0".into()),
            "secret".into(),
        );
        vip.advskew = 100; // baseline configured skew

        let primary_cmds = vip.to_ifconfig_cmds_for_role(ClusterRole::Primary);
        let secondary_cmds = vip.to_ifconfig_cmds_for_role(ClusterRole::Secondary);

        // argv form: check discrete arguments
        let primary_argv = &primary_cmds[0];
        let secondary_argv = &secondary_cmds[0];
        let skew_pos_p = primary_argv.iter().position(|a| a == "advskew").expect("advskew arg");
        let skew_pos_s = secondary_argv.iter().position(|a| a == "advskew").expect("advskew arg");
        assert_eq!(primary_argv[skew_pos_p + 1], "0", "primary cmds: {primary_cmds:?}");
        assert_eq!(secondary_argv[skew_pos_s + 1], "100", "secondary cmds: {secondary_cmds:?}");
    }

    #[test]
    fn test_config_snapshot_diff() {
        let a = ConfigSnapshot::new(
            1,
            uuid::Uuid::new_v4(),
            "hash1".into(),
            "nat1".into(),
            "{}".into(),
        );
        let b = ConfigSnapshot::new(
            2,
            uuid::Uuid::new_v4(),
            "hash1".into(),
            "nat1".into(),
            "{}".into(),
        );
        let c = ConfigSnapshot::new(
            2,
            uuid::Uuid::new_v4(),
            "hash2".into(),
            "nat1".into(),
            "{}".into(),
        );

        assert!(!a.differs_from(&b)); // same hashes
        assert!(a.differs_from(&c)); // different rules_hash
    }
}
