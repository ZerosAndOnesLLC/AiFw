use crate::flow::{Flow, FlowDirection};

use super::{AppProto, ParseResult, ProbeResult, ProtocolParser, StickyBuffers};

/// DNS parser — extracts query name, type, response code, and answer data.
pub struct DnsParser;

impl ProtocolParser for DnsParser {
    fn name(&self) -> &str {
        "dns"
    }

    fn app_proto(&self) -> AppProto {
        AppProto::Dns
    }

    fn default_ports(&self) -> &[u16] {
        &[53, 5353]
    }

    fn probe(&self, payload: &[u8], _direction: FlowDirection) -> ProbeResult {
        // DNS header is 12 bytes minimum
        if payload.len() < 12 {
            return if payload.len() >= 4 {
                ProbeResult::NeedMore
            } else {
                ProbeResult::NoMatch
            };
        }

        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let opcode = (flags >> 11) & 0x0f;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);

        // Standard/inverse query, at least 1 question (or it's a response)
        if opcode <= 2 && (qdcount > 0 || flags & 0x8000 != 0) {
            // Additional sanity: qdcount shouldn't be absurdly large
            if qdcount <= 100 {
                return ProbeResult::Match;
            }
        }

        ProbeResult::NoMatch
    }

    fn parse(
        &self,
        _flow: &mut Flow,
        payload: &[u8],
        _direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult {
        if payload.len() < 12 {
            return ParseResult::Incomplete;
        }

        let _id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = flags & 0x8000 != 0;
        let opcode = (flags >> 11) & 0x0f;
        let rcode = flags & 0x000f;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);

        buffers.insert("dns.opcode".into(), opcode.to_string().into_bytes());

        if is_response {
            let rcode_str = match rcode {
                0 => "NOERROR",
                1 => "FORMERR",
                2 => "SERVFAIL",
                3 => "NXDOMAIN",
                4 => "NOTIMP",
                5 => "REFUSED",
                _ => "UNKNOWN",
            };
            buffers.insert("dns.rcode".into(), rcode_str.as_bytes().to_vec());
        }

        // Parse question section
        let mut pos = 12;
        for _ in 0..qdcount {
            if pos >= payload.len() {
                return ParseResult::Incomplete;
            }

            match self.parse_name(payload, pos) {
                Some((name, new_pos)) => {
                    buffers.insert("dns.query".into(), name.as_bytes().to_vec());

                    // Query type (2 bytes after name)
                    if new_pos + 4 <= payload.len() {
                        let qtype = u16::from_be_bytes([payload[new_pos], payload[new_pos + 1]]);
                        let qtype_str = match qtype {
                            1 => "A",
                            2 => "NS",
                            5 => "CNAME",
                            6 => "SOA",
                            12 => "PTR",
                            15 => "MX",
                            16 => "TXT",
                            28 => "AAAA",
                            33 => "SRV",
                            255 => "ANY",
                            _ => "UNKNOWN",
                        };
                        buffers.insert("dns.query.type".into(), qtype_str.as_bytes().to_vec());
                        pos = new_pos + 4; // skip qtype + qclass
                    } else {
                        return ParseResult::Incomplete;
                    }
                }
                None => return ParseResult::Error("invalid DNS name".into()),
            }
        }

        // Parse answer section (for responses)
        if is_response && ancount > 0 {
            let mut answers = Vec::new();
            for _ in 0..ancount {
                if pos >= payload.len() {
                    break;
                }
                match self.parse_rr(payload, pos) {
                    Some((rdata, new_pos)) => {
                        answers.push(rdata);
                        pos = new_pos;
                    }
                    None => break,
                }
            }
            if !answers.is_empty() {
                buffers.insert("dns.answer".into(), answers.join(",").into_bytes());
            }
        }

        ParseResult::Ok
    }
}

impl DnsParser {
    /// Parse a DNS name with label compression support.
    fn parse_name(&self, data: &[u8], mut pos: usize) -> Option<(String, usize)> {
        let mut labels = Vec::new();
        let mut end_pos = None;
        let mut jumps = 0;

        loop {
            if pos >= data.len() || jumps > 10 {
                return None;
            }

            let len = data[pos] as usize;

            if len == 0 {
                if end_pos.is_none() {
                    end_pos = Some(pos + 1);
                }
                break;
            }

            // Compression pointer
            if len & 0xc0 == 0xc0 {
                if pos + 1 >= data.len() {
                    return None;
                }
                let offset = (len & 0x3f) << 8 | data[pos + 1] as usize;
                if end_pos.is_none() {
                    end_pos = Some(pos + 2);
                }
                pos = offset;
                jumps += 1;
                continue;
            }

            pos += 1;
            if pos + len > data.len() {
                return None;
            }

            if let Ok(label) = std::str::from_utf8(&data[pos..pos + len]) {
                labels.push(label.to_string());
            } else {
                return None;
            }
            pos += len;
        }

        Some((labels.join("."), end_pos.unwrap_or(pos)))
    }

    /// Parse a resource record, return (rdata_string, new_position).
    fn parse_rr(&self, data: &[u8], pos: usize) -> Option<(String, usize)> {
        let (_name, mut pos) = self.parse_name(data, pos)?;

        if pos + 10 > data.len() {
            return None;
        }

        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let _ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if pos + rdlen > data.len() {
            return None;
        }

        let rdata = match rtype {
            1 if rdlen == 4 => {
                // A record
                format!(
                    "{}.{}.{}.{}",
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3]
                )
            }
            28 if rdlen == 16 => {
                // AAAA record
                let mut parts = Vec::new();
                for i in (0..16).step_by(2) {
                    parts.push(format!(
                        "{:x}",
                        u16::from_be_bytes([data[pos + i], data[pos + i + 1]])
                    ));
                }
                parts.join(":")
            }
            5 | 2 | 12 => {
                // CNAME, NS, PTR
                self.parse_name(data, pos)
                    .map(|(n, _)| n)
                    .unwrap_or_default()
            }
            _ => format!("type={rtype} len={rdlen}"),
        };

        Some((rdata, pos + rdlen))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_probe_dns_query() {
        let parser = DnsParser;
        // DNS query: ID=0x1234, flags=0x0100 (standard query, recursion desired), qdcount=1
        let payload = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            parser.probe(payload, FlowDirection::ToServer),
            ProbeResult::Match
        );
    }

    #[test]
    fn test_probe_not_dns() {
        let parser = DnsParser;
        // "GET /" is 5 bytes — DNS needs 12 for full header, but >= 4 returns NeedMore
        assert_eq!(
            parser.probe(b"GET /", FlowDirection::ToServer),
            ProbeResult::NeedMore
        );
        // With enough data, non-DNS is rejected
        assert_eq!(
            parser.probe(b"GET / HTTP/1.1\r\n", FlowDirection::ToServer),
            ProbeResult::NoMatch
        );
    }

    #[test]
    fn test_parse_dns_query() {
        let parser = DnsParser;
        let mut buffers: StickyBuffers = HashMap::new();

        // Build a DNS query for "example.com" type A
        let mut payload = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // flags: standard query, RD
            0x00, 0x01, // qdcount = 1
            0x00, 0x00, // ancount = 0
            0x00, 0x00, // nscount = 0
            0x00, 0x00, // arcount = 0
        ];
        // example.com as labels
        payload.push(7);
        payload.extend_from_slice(b"example");
        payload.push(3);
        payload.extend_from_slice(b"com");
        payload.push(0); // root label
        payload.extend_from_slice(&[0x00, 0x01]); // type A
        payload.extend_from_slice(&[0x00, 0x01]); // class IN

        let mut flow = test_flow();
        let result = parser.parse(&mut flow, &payload, FlowDirection::ToServer, &mut buffers);
        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(
            String::from_utf8_lossy(buffers.get("dns.query").unwrap()),
            "example.com"
        );
        assert_eq!(
            String::from_utf8_lossy(buffers.get("dns.query.type").unwrap()),
            "A"
        );
    }

    fn test_flow() -> Flow {
        use crate::decode::PacketProtocol;
        use crate::flow::FlowKey;
        let key = FlowKey::from_packet(
            "10.0.0.1".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            5353,
            53,
            17,
        );
        let pkt = crate::decode::DecodedPacket {
            timestamp_us: 0,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("8.8.8.8".parse().unwrap()),
            src_port: Some(5353),
            dst_port: Some(53),
            protocol: PacketProtocol::Udp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 0,
        };
        Flow::new(key, &pkt, 65536)
    }
}
