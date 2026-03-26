#[cfg(test)]
mod tests {
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
        assert_eq!(pf, "block in quick proto tcp to any port 22");
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
            "pass in quick proto tcp to any port 443 log label \"allow-https\""
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
}
