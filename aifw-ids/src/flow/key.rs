//! Flow identity and connection state: the canonical `FlowKey`, the
//! initiator-relative `FlowDirection`, and the TCP `FlowState`.

use std::net::IpAddr;

/// Flow direction relative to the initiator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowDirection {
    /// Packet going from client to server (initiator → responder)
    ToServer,
    /// Packet going from server to client (responder → initiator)
    ToClient,
}

/// TCP connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowState {
    /// Flow seen but no TCP handshake observed yet (also used for non-TCP)
    #[default]
    New,
    /// Initiator's SYN seen, awaiting SYN+ACK
    SynSent,
    /// Responder's SYN+ACK seen, awaiting final ACK
    SynAckSeen,
    /// Handshake complete (or mid-stream pickup with ACK set)
    Established,
    /// FIN observed; connection is closing
    FinWait,
    /// Connection closed (FIN exchange complete or RST seen)
    Closed,
}

/// Canonical flow key — ordered so both directions map to the same flow.
///
/// `Ord` is derived for use as a tie-breaker in the LRU eviction heap; the
/// ordering itself isn't semantically meaningful, just total.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowKey {
    /// Lower IP address
    pub ip_a: IpAddr,
    /// Higher IP address
    pub ip_b: IpAddr,
    /// Port corresponding to ip_a
    pub port_a: u16,
    /// Port corresponding to ip_b
    pub port_b: u16,
    /// Protocol
    pub protocol: u8,
}

impl FlowKey {
    /// Create a canonical flow key from packet IPs/ports.
    /// The lower IP:port pair is always stored as (ip_a, port_a).
    pub fn from_packet(
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        if (src_ip, src_port) <= (dst_ip, dst_port) {
            Self {
                ip_a: src_ip,
                ip_b: dst_ip,
                port_a: src_port,
                port_b: dst_port,
                protocol,
            }
        } else {
            Self {
                ip_a: dst_ip,
                ip_b: src_ip,
                port_a: dst_port,
                port_b: src_port,
                protocol,
            }
        }
    }

    /// Determine direction relative to the flow initiator.
    pub fn direction(&self, src_ip: IpAddr, src_port: u16) -> FlowDirection {
        if src_ip == self.ip_a && src_port == self.port_a {
            FlowDirection::ToServer
        } else {
            FlowDirection::ToClient
        }
    }
}
