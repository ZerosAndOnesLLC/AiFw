use crate::flow::{Flow, FlowDirection};

use super::{AppProto, ParseResult, ProbeResult, ProtocolParser, StickyBuffers};

/// SMTP parser — extracts HELO, MAIL FROM, RCPT TO, and command/response data.
pub struct SmtpParser;

impl ProtocolParser for SmtpParser {
    fn name(&self) -> &str {
        "smtp"
    }

    fn app_proto(&self) -> AppProto {
        AppProto::Smtp
    }

    fn default_ports(&self) -> &[u16] {
        &[25, 587, 2525]
    }

    fn probe(&self, payload: &[u8], direction: FlowDirection) -> ProbeResult {
        if payload.len() < 4 {
            return ProbeResult::NeedMore;
        }

        match direction {
            FlowDirection::ToClient => {
                // SMTP greeting: "220 ..."
                if payload.starts_with(b"220 ") || payload.starts_with(b"220-") {
                    return ProbeResult::Match;
                }
            }
            FlowDirection::ToServer => {
                let upper: Vec<u8> = payload.iter().take(8).map(|b| b.to_ascii_uppercase()).collect();
                if upper.starts_with(b"EHLO ")
                    || upper.starts_with(b"HELO ")
                    || upper.starts_with(b"MAIL ")
                {
                    return ProbeResult::Match;
                }
            }
        }

        ProbeResult::NoMatch
    }

    fn parse(
        &self,
        _flow: &mut Flow,
        payload: &[u8],
        direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult {
        let text = match std::str::from_utf8(payload) {
            Ok(s) => s,
            Err(_) => return ParseResult::Error("invalid UTF-8 in SMTP".into()),
        };

        match direction {
            FlowDirection::ToServer => self.parse_command(text, buffers),
            FlowDirection::ToClient => self.parse_response(text, buffers),
        }
    }
}

impl SmtpParser {
    fn parse_command(&self, text: &str, buffers: &mut StickyBuffers) -> ParseResult {
        for line in text.lines() {
            let upper = line.to_ascii_uppercase();

            if upper.starts_with("EHLO ") || upper.starts_with("HELO ") {
                let domain = line[5..].trim();
                buffers.insert("smtp.helo".into(), domain.as_bytes().to_vec());
            } else if upper.starts_with("MAIL FROM:") {
                let from = extract_angle_bracket(&line[10..]);
                buffers.insert("smtp.mail_from".into(), from.as_bytes().to_vec());
            } else if upper.starts_with("RCPT TO:") {
                let to = extract_angle_bracket(&line[8..]);
                buffers.insert("smtp.rcpt_to".into(), to.as_bytes().to_vec());
            } else if upper.starts_with("DATA") {
                buffers.insert("smtp.command".into(), b"DATA".to_vec());
            } else if upper.starts_with("AUTH ") {
                let method = line[5..].split_whitespace().next().unwrap_or("UNKNOWN");
                buffers.insert("smtp.auth_method".into(), method.as_bytes().to_vec());
            }
        }

        ParseResult::Ok
    }

    fn parse_response(&self, text: &str, buffers: &mut StickyBuffers) -> ParseResult {
        // SMTP response: "NNN text" or "NNN-text" for multiline
        if let Some(line) = text.lines().next()
            && line.len() >= 3 {
                let code = &line[..3];
                if code.bytes().all(|b| b.is_ascii_digit()) {
                    buffers.insert("smtp.reply_code".into(), code.as_bytes().to_vec());
                    if line.len() > 4 {
                        buffers.insert("smtp.reply_msg".into(), line[4..].as_bytes().to_vec());
                    }
                    // Greeting banner
                    if code == "220" {
                        buffers.insert("smtp.banner".into(), line[4..].trim().as_bytes().to_vec());
                    }
                }
            }

        ParseResult::Ok
    }
}

/// Extract content from angle brackets: "<user@domain>" → "user@domain"
fn extract_angle_bracket(s: &str) -> String {
    let trimmed = s.trim();
    if let Some(start) = trimmed.find('<')
        && let Some(end) = trimmed.find('>')
            && end > start {
                return trimmed[start + 1..end].to_string();
            }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_probe_smtp_greeting() {
        let parser = SmtpParser;
        assert_eq!(
            parser.probe(b"220 mail.example.com ESMTP\r\n", FlowDirection::ToClient),
            ProbeResult::Match
        );
    }

    #[test]
    fn test_probe_smtp_command() {
        let parser = SmtpParser;
        assert_eq!(
            parser.probe(b"EHLO client.example.com\r\n", FlowDirection::ToServer),
            ProbeResult::Match
        );
    }

    #[test]
    fn test_parse_commands() {
        let parser = SmtpParser;
        let mut buffers: StickyBuffers = HashMap::new();
        let mut flow = test_flow();

        let payload = "EHLO client.example.com\r\nMAIL FROM:<sender@example.com>\r\nRCPT TO:<rcpt@example.org>\r\n";
        let result = parser.parse(
            &mut flow,
            payload.as_bytes(),
            FlowDirection::ToServer,
            &mut buffers,
        );

        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(buffers.get("smtp.helo").unwrap(), b"client.example.com");
        assert_eq!(buffers.get("smtp.mail_from").unwrap(), b"sender@example.com");
        assert_eq!(buffers.get("smtp.rcpt_to").unwrap(), b"rcpt@example.org");
    }

    #[test]
    fn test_parse_response() {
        let parser = SmtpParser;
        let mut buffers: StickyBuffers = HashMap::new();
        let mut flow = test_flow();

        let payload = b"220 mail.example.com ESMTP Postfix\r\n";
        let result = parser.parse(&mut flow, payload, FlowDirection::ToClient, &mut buffers);

        assert!(matches!(result, ParseResult::Ok));
        assert_eq!(buffers.get("smtp.reply_code").unwrap(), b"220");
        assert_eq!(
            buffers.get("smtp.banner").unwrap(),
            b"mail.example.com ESMTP Postfix"
        );
    }

    #[test]
    fn test_extract_angle_bracket() {
        assert_eq!(extract_angle_bracket("<user@domain>"), "user@domain");
        assert_eq!(extract_angle_bracket("  <test@test.com>  "), "test@test.com");
        assert_eq!(extract_angle_bracket("bare@domain"), "bare@domain");
    }

    fn test_flow() -> Flow {
        use crate::decode::PacketProtocol;
        use crate::flow::FlowKey;
        let key = FlowKey::from_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1234, 25, 6,
        );
        let pkt = crate::decode::DecodedPacket {
            timestamp_us: 0,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(25),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 0,
        };
        Flow::new(key, &pkt, 65536)
    }
}
