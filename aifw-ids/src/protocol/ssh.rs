use crate::flow::{Flow, FlowDirection};

use super::{AppProto, ParseResult, ProbeResult, ProtocolParser, StickyBuffers};

/// SSH parser — extracts banner (software version) and protocol version.
pub struct SshParser;

impl ProtocolParser for SshParser {
    fn name(&self) -> &str {
        "ssh"
    }

    fn app_proto(&self) -> AppProto {
        AppProto::Ssh
    }

    fn default_ports(&self) -> &[u16] {
        &[22, 2222]
    }

    fn probe(&self, payload: &[u8], _direction: FlowDirection) -> ProbeResult {
        if payload.len() < 4 {
            return ProbeResult::NeedMore;
        }
        if payload.starts_with(b"SSH-") {
            ProbeResult::Match
        } else {
            ProbeResult::NoMatch
        }
    }

    fn parse(
        &self,
        _flow: &mut Flow,
        payload: &[u8],
        direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult {
        if !payload.starts_with(b"SSH-") {
            return ParseResult::Ok;
        }

        // Find end of banner line
        let end = payload
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .unwrap_or(payload.len().min(255));

        let banner = &payload[..end];

        // Parse "SSH-protoversion-softwareversion comments"
        let banner_str = String::from_utf8_lossy(banner);
        let parts: Vec<&str> = banner_str.splitn(3, '-').collect();

        if parts.len() >= 3 {
            buffers.insert("ssh.proto".into(), parts[1].as_bytes().to_vec());
            // Software version may have a space-separated comment
            let software = parts[2].split(' ').next().unwrap_or(parts[2]);
            buffers.insert("ssh.software".into(), software.as_bytes().to_vec());
        }

        // Store full banner based on direction
        match direction {
            FlowDirection::ToServer => {
                buffers.insert("ssh.client_banner".into(), banner.to_vec());
            }
            FlowDirection::ToClient => {
                buffers.insert("ssh.server_banner".into(), banner.to_vec());
            }
        }

        ParseResult::Ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_probe_ssh() {
        let parser = SshParser;
        assert_eq!(
            parser.probe(b"SSH-2.0-OpenSSH_9.0\r\n", FlowDirection::ToServer),
            ProbeResult::Match
        );
        assert_eq!(
            parser.probe(b"GET /", FlowDirection::ToServer),
            ProbeResult::NoMatch
        );
        assert_eq!(
            parser.probe(b"SS", FlowDirection::ToServer),
            ProbeResult::NeedMore
        );
    }

    #[test]
    fn test_parse_server_banner() {
        let parser = SshParser;
        let mut buffers: StickyBuffers = HashMap::new();
        let mut flow = test_flow();

        let payload = b"SSH-2.0-OpenSSH_9.0p1 Ubuntu-1\r\n";
        let result = parser.parse(&mut flow, payload, FlowDirection::ToClient, &mut buffers);

        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(buffers.get("ssh.proto").unwrap(), b"2.0");
        assert_eq!(buffers.get("ssh.software").unwrap(), b"OpenSSH_9.0p1");
        assert!(buffers.contains_key("ssh.server_banner"));
    }

    #[test]
    fn test_parse_client_banner() {
        let parser = SshParser;
        let mut buffers: StickyBuffers = HashMap::new();
        let mut flow = test_flow();

        let payload = b"SSH-2.0-PuTTY_Release_0.78\r\n";
        let result = parser.parse(&mut flow, payload, FlowDirection::ToServer, &mut buffers);

        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(buffers.get("ssh.software").unwrap(), b"PuTTY_Release_0.78");
        assert!(buffers.contains_key("ssh.client_banner"));
    }

    fn test_flow() -> Flow {
        use crate::decode::PacketProtocol;
        use crate::flow::FlowKey;
        let key = FlowKey::from_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1234,
            22,
            6,
        );
        let pkt = crate::decode::DecodedPacket {
            timestamp_us: 0,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(22),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 0,
        };
        Flow::new(key, &pkt, 65536)
    }
}
