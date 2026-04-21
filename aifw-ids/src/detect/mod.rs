pub mod multi_pattern;
pub mod threshold;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use aifw_common::ids::IdsAlert;

use crate::decode::DecodedPacket;
use crate::flow::{Flow, FlowDirection, FlowTable};
use crate::protocol::{ProtocolRegistry, StickyBuffers};
use crate::rules::{CompiledRule, ContentMatch, FlowConstraint, FlowbitOp, RuleDatabase};

use self::threshold::ThresholdTracker;

/// The detection engine — runs packets through the multi-stage detection pipeline.
pub struct DetectionEngine {
    rule_db: Arc<RuleDatabase>,
    flow_table: Arc<FlowTable>,
    protocol_registry: ProtocolRegistry,
    threshold_tracker: ThresholdTracker,
}

impl DetectionEngine {
    pub fn new(rule_db: Arc<RuleDatabase>, flow_table: Arc<FlowTable>) -> Self {
        Self {
            rule_db,
            flow_table,
            protocol_registry: ProtocolRegistry::new(),
            threshold_tracker: ThresholdTracker::new(),
        }
    }

    /// Accessor for the flow table so the capture worker can periodically
    /// expire idle flows. Each flow holds 2 MB of reassembly buffers, so
    /// without periodic expiry the flow table grows unbounded.
    pub fn flow_table(&self) -> &Arc<FlowTable> {
        &self.flow_table
    }

    /// Run the full detection pipeline on a decoded packet.
    /// Returns a list of matched alerts.
    pub fn detect(&self, packet: &DecodedPacket) -> Vec<IdsAlert> {
        let mut alerts = Vec::new();

        // Step 1: Track the flow
        let (flow_key, direction) = match self.flow_table.track_packet(packet) {
            Some(result) => result,
            None => return alerts,
        };

        // Step 2: Protocol detection & parsing
        let mut sticky_buffers: StickyBuffers = HashMap::new();

        if let Some(mut flow_ref) = self.flow_table.get_mut(&flow_key) {
            let flow = &mut *flow_ref;

            // Auto-detect protocol on first payload
            if flow.app_proto.is_none() && !packet.payload.is_empty() {
                let dst_port = packet.dst_port.unwrap_or(0);
                flow.app_proto =
                    self.protocol_registry
                        .detect(&packet.payload, dst_port, direction);
            }

            // Parse protocol and extract sticky buffers
            if flow.app_proto.is_some() {
                self.protocol_registry
                    .parse(flow, &packet.payload, direction, &mut sticky_buffers);
            }
        }

        // Step 3: Run detection rules
        let ruleset_guard = self.rule_db.ruleset();
        let ruleset = match ruleset_guard.as_ref() {
            Some(rs) => rs,
            None => return alerts,
        };

        // Step 3a: Prefilter — find candidate rules via Aho-Corasick
        let candidates = ruleset.prefilter(&packet.payload);

        // Step 3b: Full rule evaluation for each candidate
        // Snapshot flow state to avoid holding DashMap read lock during mutation
        let flow_snapshot: Option<(bool, std::collections::HashSet<String>)> = self
            .flow_table
            .get(&flow_key)
            .map(|f| (f.is_established(), f.flowbits.clone()));
        let flow_id: Option<String> = self.flow_table.get(&flow_key).map(|f| f.id.to_string());

        for &rule_idx in &candidates {
            if rule_idx >= ruleset.rules.len() {
                continue;
            }

            let rule = &ruleset.rules[rule_idx];

            // Evaluate rule using a temporary flow reference (short-lived borrow)
            let matched = {
                let flow_ref = self.flow_table.get(&flow_key);
                let flow = flow_ref.as_deref();
                self.evaluate_rule(rule, packet, flow, direction, &sticky_buffers)
            };

            if matched {
                // Step 3c: Check threshold
                if let Some(ref threshold) = rule.threshold {
                    let ip = match threshold.track {
                        crate::rules::TrackBy::BySrc => packet.src_ip,
                        crate::rules::TrackBy::ByDst => packet.dst_ip,
                    };
                    if let Some(ip) = ip {
                        let sid = rule.sid.unwrap_or(0);
                        if !self.threshold_tracker.check(sid, ip, threshold) {
                            continue;
                        }
                    }
                }

                // Step 3d: Check flowbits (use snapshot to avoid lock)
                let flowbits_ok = if let Some((_, ref bits)) = flow_snapshot {
                    rule.flowbits.iter().all(|fb| match fb {
                        FlowbitOp::IsSet(name) => bits.contains(name),
                        _ => true,
                    })
                } else {
                    !rule
                        .flowbits
                        .iter()
                        .any(|fb| matches!(fb, FlowbitOp::IsSet(_)))
                };

                if !flowbits_ok {
                    continue;
                }

                // Step 3e: Apply flowbit mutations (separate mutable borrow)
                if let Some(mut flow_mut) = self.flow_table.get_mut(&flow_key) {
                    self.apply_flowbits(rule, &mut flow_mut);
                }

                // Step 3f: Check for noalert flowbit
                if rule
                    .flowbits
                    .iter()
                    .any(|fb| matches!(fb, FlowbitOp::NoAlert))
                {
                    continue;
                }

                // Build alert
                let src_ip = packet
                    .src_ip
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let dst_ip = packet
                    .dst_ip
                    .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
                let mut alert = IdsAlert::new(
                    rule.msg.clone(),
                    rule.severity,
                    src_ip,
                    dst_ip,
                    &packet.protocol.to_string(),
                    rule.action,
                    rule.source,
                );
                alert.signature_id = rule.sid;
                alert.src_port = packet.src_port;
                alert.dst_port = packet.dst_port;
                alert.flow_id = flow_id.clone();

                if !packet.payload.is_empty() {
                    let excerpt_len = packet.payload.len().min(256);
                    let excerpt = &packet.payload[..excerpt_len];
                    if excerpt.is_ascii() {
                        alert.payload_excerpt = Some(String::from_utf8_lossy(excerpt).to_string());
                    } else {
                        alert.payload_excerpt = Some(
                            excerpt
                                .iter()
                                .map(|b| format!("{b:02X}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                        );
                    }
                }

                if !rule.metadata.is_empty() {
                    alert.metadata = Some(
                        rule.metadata
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect(),
                    );
                }

                alerts.push(alert);
            }
        }

        // Sort by severity (most severe first)
        alerts.sort_by_key(|a| a.severity.0);

        alerts
    }

    /// Evaluate a single rule against a packet.
    fn evaluate_rule(
        &self,
        rule: &CompiledRule,
        packet: &DecodedPacket,
        flow: Option<&Flow>,
        direction: FlowDirection,
        sticky_buffers: &StickyBuffers,
    ) -> bool {
        // Check protocol
        if let Some(ref proto) = rule.protocol
            && !self.match_protocol(proto, packet, flow)
        {
            return false;
        }

        // Check flow constraint
        if let Some(ref flow_constraint) = rule.flow
            && !self.match_flow_constraint(flow_constraint, flow, direction)
        {
            return false;
        }

        // Check address constraints
        if let Some(ref src) = rule.src_addr
            && !self.match_address(src, packet.src_ip)
        {
            return false;
        }
        if let Some(ref dst) = rule.dst_addr
            && !self.match_address(dst, packet.dst_ip)
        {
            return false;
        }

        // Check port constraints
        if let Some(ref port) = rule.src_port
            && !self.match_port(port, packet.src_port)
        {
            return false;
        }
        if let Some(ref port) = rule.dst_port
            && !self.match_port(port, packet.dst_port)
        {
            return false;
        }

        // Check all content matches
        for content in &rule.contents {
            let data = if let Some(ref buffer_name) = content.buffer {
                match sticky_buffers.get(buffer_name) {
                    Some(buf) => buf.as_slice(),
                    None => {
                        // If the buffer doesn't exist, check flow reassembly buffers
                        match flow {
                            Some(f) => match direction {
                                FlowDirection::ToServer => &f.toserver_buf,
                                FlowDirection::ToClient => &f.toclient_buf,
                            },
                            None => &packet.payload,
                        }
                    }
                }
            } else {
                &packet.payload
            };

            let matched = content_match(content, data);
            if content.negated {
                if matched {
                    return false;
                }
            } else if !matched {
                return false;
            }
        }

        // Check PCRE patterns
        for pcre in &rule.pcre_patterns {
            let data = if let Some(ref buffer_name) = pcre.buffer {
                match sticky_buffers.get(buffer_name) {
                    Some(buf) => buf.as_slice(),
                    None => &packet.payload,
                }
            } else {
                &packet.payload
            };

            let data_str = String::from_utf8_lossy(data);
            // Use pre-compiled regex from the ruleset if available, otherwise compile
            let matched = self.rule_db.ruleset().as_ref().is_some_and(|rs| {
                rs.regex_patterns
                    .iter()
                    .any(|(re, _)| re.as_str() == pcre.pattern && re.is_match(&data_str))
            }) || regex::Regex::new(&pcre.pattern)
                .map(|re| re.is_match(&data_str))
                .unwrap_or(false);

            if pcre.negated {
                if matched {
                    return false;
                }
            } else if !matched {
                return false;
            }
        }

        true
    }

    fn match_protocol(&self, proto: &str, packet: &DecodedPacket, flow: Option<&Flow>) -> bool {
        match proto {
            "tcp" => packet.protocol == crate::decode::PacketProtocol::Tcp,
            "udp" => packet.protocol == crate::decode::PacketProtocol::Udp,
            "icmp" => packet.protocol == crate::decode::PacketProtocol::Icmpv4,
            "ip" => true, // any IP
            // App-layer protocols: check the flow's detected protocol
            "http" => flow.is_some_and(|f| f.app_proto == Some(crate::protocol::AppProto::Http)),
            "tls" => flow.is_some_and(|f| f.app_proto == Some(crate::protocol::AppProto::Tls)),
            "dns" => flow.is_some_and(|f| f.app_proto == Some(crate::protocol::AppProto::Dns)),
            "ssh" => flow.is_some_and(|f| f.app_proto == Some(crate::protocol::AppProto::Ssh)),
            "smtp" => flow.is_some_and(|f| f.app_proto == Some(crate::protocol::AppProto::Smtp)),
            _ => true,
        }
    }

    fn match_flow_constraint(
        &self,
        constraint: &FlowConstraint,
        flow: Option<&Flow>,
        direction: FlowDirection,
    ) -> bool {
        if constraint.stateless {
            return true;
        }

        if let Some(flow) = flow {
            if constraint.established && !flow.is_established() {
                return false;
            }

            if let Some(to_server) = constraint.to_server {
                if to_server && direction != FlowDirection::ToServer {
                    return false;
                }
                if !to_server && direction != FlowDirection::ToClient {
                    return false;
                }
            }
        } else if constraint.established {
            return false;
        }

        true
    }

    fn match_address(&self, constraint: &str, ip: Option<IpAddr>) -> bool {
        let ip = match ip {
            Some(ip) => ip,
            None => return false,
        };

        // Variable references (not expanded here — would need config)
        if constraint.starts_with('$') {
            return true; // TODO: expand variables
        }

        // Negation
        if let Some(inner) = constraint.strip_prefix('!') {
            return !self.match_address(inner, Some(ip));
        }

        // Group [addr1,addr2]
        if constraint.starts_with('[') && constraint.ends_with(']') {
            let inner = &constraint[1..constraint.len() - 1];
            return inner
                .split(',')
                .any(|a| self.match_address(a.trim(), Some(ip)));
        }

        // CIDR match
        if let Some((net, prefix_str)) = constraint.split_once('/')
            && let (Ok(net_ip), Ok(prefix)) = (net.parse::<IpAddr>(), prefix_str.parse::<u8>())
        {
            return ip_in_cidr(ip, net_ip, prefix);
        }

        // Exact IP match
        if let Ok(addr) = constraint.parse::<IpAddr>() {
            return ip == addr;
        }

        true // If we can't parse, don't block
    }

    fn match_port(&self, constraint: &str, port: Option<u16>) -> bool {
        let port = match port {
            Some(p) => p,
            None => return false,
        };

        if constraint.starts_with('$') {
            return true; // Variable reference
        }

        if let Some(inner) = constraint.strip_prefix('!') {
            return !self.match_port(inner, Some(port));
        }

        // Group [port1,port2]
        if constraint.starts_with('[') && constraint.ends_with(']') {
            let inner = &constraint[1..constraint.len() - 1];
            return inner
                .split(',')
                .any(|p| self.match_port(p.trim(), Some(port)));
        }

        // Range
        if let Some((low, high)) = constraint.split_once(':') {
            let low = low.parse::<u16>().unwrap_or(0);
            let high = high.parse::<u16>().unwrap_or(65535);
            return port >= low && port <= high;
        }

        // Single port
        if let Ok(p) = constraint.parse::<u16>() {
            return port == p;
        }

        true
    }

    fn apply_flowbits(&self, rule: &CompiledRule, flow: &mut Flow) {
        for fb in &rule.flowbits {
            match fb {
                FlowbitOp::Set(name) => {
                    flow.flowbits.insert(name.clone());
                }
                FlowbitOp::Unset(name) => {
                    flow.flowbits.remove(name);
                }
                FlowbitOp::Toggle(name) => {
                    if flow.flowbits.contains(name) {
                        flow.flowbits.remove(name);
                    } else {
                        flow.flowbits.insert(name.clone());
                    }
                }
                _ => {}
            }
        }
    }
}

/// Check if a content pattern matches data with position constraints.
fn content_match(content: &ContentMatch, data: &[u8]) -> bool {
    let pattern = if content.nocase {
        content.pattern.to_ascii_lowercase()
    } else {
        content.pattern.clone()
    };

    let search_data = if content.nocase {
        data.to_ascii_lowercase()
    } else {
        data.to_vec()
    };

    let start = content.offset.unwrap_or(0);
    let end = content
        .depth
        .map(|d| (start + d).min(search_data.len()))
        .unwrap_or(search_data.len());

    if start >= search_data.len() || end <= start {
        return false;
    }

    let search_range = &search_data[start..end];

    // Use memchr for single-byte patterns, otherwise search
    if pattern.len() == 1 {
        memchr::memchr(pattern[0], search_range).is_some()
    } else if !pattern.is_empty() {
        search_range
            .windows(pattern.len())
            .any(|window| window == pattern.as_slice())
    } else {
        true // empty pattern always matches
    }
}

fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}

impl std::fmt::Debug for DetectionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DetectionEngine")
            .field("rules", &self.rule_db.rule_count())
            .field("flows", &self.flow_table.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::PacketProtocol;
    use aifw_common::ids::RuleSource;

    fn setup_engine(rules_text: &str) -> DetectionEngine {
        let rule_db = Arc::new(RuleDatabase::new());
        let rules = crate::rules::suricata::parse_rules(rules_text, RuleSource::Custom);
        rule_db.load_rules(rules);

        let flow_table = Arc::new(FlowTable::new(1024));
        DetectionEngine::new(rule_db, flow_table)
    }

    fn tcp_packet(
        src_ip: &str,
        dst_ip: &str,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> DecodedPacket {
        DecodedPacket {
            timestamp_us: 1000,
            src_ip: Some(src_ip.parse().unwrap()),
            dst_ip: Some(dst_ip.parse().unwrap()),
            src_port: Some(src_port),
            dst_port: Some(dst_port),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: payload.to_vec(),
            packet_len: 64 + payload.len(),
        }
    }

    #[test]
    fn test_detect_simple_content() {
        let engine = setup_engine(
            r#"alert tcp any any -> any any (msg:"Test malware"; content:"malware"; sid:1;)"#,
        );

        let pkt = tcp_packet(
            "10.0.0.1",
            "10.0.0.2",
            12345,
            80,
            b"this contains malware string",
        );
        let alerts = engine.detect(&pkt);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].signature_msg, "Test malware");
        assert_eq!(alerts[0].signature_id, Some(1));
    }

    #[test]
    fn test_detect_no_match() {
        let engine =
            setup_engine(r#"alert tcp any any -> any any (msg:"Test"; content:"malware"; sid:1;)"#);

        let pkt = tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, b"safe traffic here");
        let alerts = engine.detect(&pkt);
        assert!(alerts.is_empty());
    }

    #[test]
    fn test_detect_nocase() {
        let engine = setup_engine(
            r#"alert tcp any any -> any any (msg:"Nocase test"; content:"MALWARE"; nocase; sid:2;)"#,
        );

        let pkt = tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, b"found Malware here");
        let alerts = engine.detect(&pkt);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn test_detect_multiple_rules() {
        let engine = setup_engine(
            r#"
alert tcp any any -> any any (msg:"Rule 1"; content:"evil"; sid:1;)
alert tcp any any -> any any (msg:"Rule 2"; content:"bad"; sid:2;)
"#,
        );

        let pkt = tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, b"this is evil and bad");
        let alerts = engine.detect(&pkt);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn test_detect_depth_offset() {
        let engine = setup_engine(
            r#"alert tcp any any -> any any (msg:"Depth test"; content:"GET"; depth:3; sid:1;)"#,
        );

        let pkt1 = tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, b"GET / HTTP/1.1");
        assert_eq!(engine.detect(&pkt1).len(), 1);

        let pkt2 = tcp_packet("10.0.0.1", "10.0.0.2", 12345, 80, b"POST / HTTP/1.1 GET");
        assert_eq!(engine.detect(&pkt2).len(), 0);
    }

    #[test]
    fn test_ip_in_cidr() {
        assert!(ip_in_cidr(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(ip_in_cidr(
            "10.255.255.255".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(!ip_in_cidr(
            "11.0.0.1".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            8
        ));
        assert!(ip_in_cidr(
            "192.168.1.1".parse().unwrap(),
            "192.168.1.0".parse().unwrap(),
            24
        ));
    }

    #[test]
    fn test_content_match_basic() {
        let content = ContentMatch {
            pattern: b"test".to_vec(),
            nocase: false,
            depth: None,
            offset: None,
            distance: None,
            within: None,
            fast_pattern: false,
            negated: false,
            buffer: None,
        };

        assert!(content_match(&content, b"this is a test"));
        assert!(!content_match(&content, b"no match here"));
    }
}
