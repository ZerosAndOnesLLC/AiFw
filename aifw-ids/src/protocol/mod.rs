pub mod dns;
pub mod http;
pub mod smtp;
pub mod ssh;
pub mod tls;

use std::collections::HashMap;

use crate::flow::{Flow, FlowDirection};

/// Detected application-layer protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppProto {
    Http,
    Tls,
    Dns,
    Ssh,
    Smtp,
    Unknown,
}

impl std::fmt::Display for AppProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Tls => write!(f, "tls"),
            Self::Dns => write!(f, "dns"),
            Self::Ssh => write!(f, "ssh"),
            Self::Smtp => write!(f, "smtp"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// Result of probing a payload for protocol detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeResult {
    /// Definitely this protocol
    Match,
    /// Definitely not this protocol
    NoMatch,
    /// Need more data to decide
    NeedMore,
}

/// Result of parsing a payload
#[derive(Debug)]
pub enum ParseResult {
    /// Successfully parsed, extracted fields
    Ok,
    /// Need more data
    Incomplete,
    /// Parse error (protocol violation)
    Error(String),
}

/// Sticky buffer values — named fields extracted from protocol parsing
/// that Suricata-style rules can match against.
pub type StickyBuffers = HashMap<String, Vec<u8>>;

/// Trait for application-layer protocol parsers.
pub trait ProtocolParser: Send + Sync {
    /// Protocol name
    fn name(&self) -> &str;

    /// Which app proto this parser handles
    fn app_proto(&self) -> AppProto;

    /// Default ports for port-based hinting
    fn default_ports(&self) -> &[u16];

    /// Quick check: does this payload look like this protocol?
    fn probe(&self, payload: &[u8], direction: FlowDirection) -> ProbeResult;

    /// Parse payload and extract sticky buffers.
    fn parse(
        &self,
        flow: &mut Flow,
        payload: &[u8],
        direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult;
}

/// Registry of all available protocol parsers.
pub struct ProtocolRegistry {
    parsers: Vec<Box<dyn ProtocolParser>>,
}

impl ProtocolRegistry {
    pub fn new() -> Self {
        let parsers: Vec<Box<dyn ProtocolParser>> = vec![
            Box::new(http::HttpParser),
            Box::new(tls::TlsParser),
            Box::new(dns::DnsParser),
            Box::new(ssh::SshParser),
            Box::new(smtp::SmtpParser),
        ];
        Self { parsers }
    }

    /// Try to detect the application protocol for a flow.
    /// First checks port-based hints, then probes each parser.
    pub fn detect(
        &self,
        payload: &[u8],
        dst_port: u16,
        direction: FlowDirection,
    ) -> Option<AppProto> {
        if payload.is_empty() {
            return None;
        }

        // Port-based hint: try expected parser first
        for parser in &self.parsers {
            if parser.default_ports().contains(&dst_port)
                && parser.probe(payload, direction) == ProbeResult::Match
            {
                return Some(parser.app_proto());
            }
        }

        // Probe all parsers
        for parser in &self.parsers {
            if parser.probe(payload, direction) == ProbeResult::Match {
                return Some(parser.app_proto());
            }
        }

        None
    }

    /// Get the parser for a specific protocol.
    pub fn get_parser(&self, proto: AppProto) -> Option<&dyn ProtocolParser> {
        self.parsers
            .iter()
            .find(|p| p.app_proto() == proto)
            .map(|p| p.as_ref())
    }

    /// Parse payload using the appropriate parser for the flow's detected protocol.
    pub fn parse(
        &self,
        flow: &mut Flow,
        payload: &[u8],
        direction: FlowDirection,
        buffers: &mut StickyBuffers,
    ) -> ParseResult {
        let proto = match flow.app_proto {
            Some(p) => p,
            None => return ParseResult::Ok,
        };

        match self.get_parser(proto) {
            Some(parser) => parser.parse(flow, payload, direction, buffers),
            None => ParseResult::Ok,
        }
    }
}

impl Default for ProtocolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_detect_http() {
        let reg = ProtocolRegistry::new();
        let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        let result = reg.detect(payload, 80, FlowDirection::ToServer);
        assert_eq!(result, Some(AppProto::Http));
    }

    #[test]
    fn test_registry_detect_dns() {
        let reg = ProtocolRegistry::new();
        // Minimal DNS query header: ID=0x1234, flags=0x0100 (standard query), 1 question
        let payload = &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = reg.detect(payload, 53, FlowDirection::ToServer);
        assert_eq!(result, Some(AppProto::Dns));
    }

    #[test]
    fn test_registry_detect_empty() {
        let reg = ProtocolRegistry::new();
        assert_eq!(reg.detect(b"", 80, FlowDirection::ToServer), None);
    }
}
