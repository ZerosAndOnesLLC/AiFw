#[cfg(test)]
mod tests {
    use crate::nat::*;
    use crate::rule::*;
    use crate::types::*;
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
}
