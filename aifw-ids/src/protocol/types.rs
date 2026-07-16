//! Application-layer protocol model: the detected `AppProto`, probe/parse
//! result enums, the `StickyBuffers` extraction map, and the
//! `ProtocolParser` trait each parser submodule implements.

use std::collections::HashMap;

use crate::flow::{Flow, FlowDirection};

/// Detected application-layer protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AppProto {
    /// HTTP/1.x
    Http,
    /// TLS/SSL
    Tls,
    /// DNS
    Dns,
    /// SSH
    Ssh,
    /// SMTP
    Smtp,
    /// Payload didn't match any known protocol
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
