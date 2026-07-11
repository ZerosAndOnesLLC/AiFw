use etherparse::{NetSlice, TransportSlice};
use std::net::IpAddr;

/// A decoded packet with parsed headers and payload reference.
#[derive(Debug)]
pub struct DecodedPacket {
    /// Packet timestamp (microseconds since epoch)
    pub timestamp_us: i64,
    /// Source IP
    pub src_ip: Option<IpAddr>,
    /// Destination IP
    pub dst_ip: Option<IpAddr>,
    /// Source port (TCP/UDP)
    pub src_port: Option<u16>,
    /// Destination port (TCP/UDP)
    pub dst_port: Option<u16>,
    /// Protocol name
    pub protocol: PacketProtocol,
    /// TCP flags (if TCP)
    pub tcp_flags: Option<TcpFlags>,
    /// Application layer payload (after transport header)
    pub payload: Vec<u8>,
    /// Total packet length on wire
    pub packet_len: usize,
}

/// Simplified protocol enum for classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketProtocol {
    Tcp,
    Udp,
    Icmpv4,
    Icmpv6,
    Other(u8),
}

impl std::fmt::Display for PacketProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp => write!(f, "tcp"),
            Self::Udp => write!(f, "udp"),
            Self::Icmpv4 => write!(f, "icmp"),
            Self::Icmpv6 => write!(f, "icmpv6"),
            Self::Other(n) => write!(f, "proto_{n}"),
        }
    }
}

/// TCP flag bits
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    pub fn from_header(h: &etherparse::TcpHeader) -> Self {
        Self {
            syn: h.syn,
            ack: h.ack,
            fin: h.fin,
            rst: h.rst,
            psh: h.psh,
            urg: h.urg,
        }
    }

    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }
}

/// Decode a raw packet buffer into a `DecodedPacket`.
///
/// Uses `etherparse` for zero-allocation header parsing. Handles:
/// - Ethernet II → IPv4/IPv6 → TCP/UDP/ICMP
/// - VLAN-tagged frames (802.1Q)
/// - Raw IP packets (no Ethernet header)
pub fn decode_packet(data: &[u8], timestamp_us: i64) -> Option<DecodedPacket> {
    // Try raw IP first (tcpdump -x outputs IP headers, not Ethernet),
    // fall back to Ethernet framing for direct BPF capture.
    let result = etherparse::SlicedPacket::from_ip(data)
        .or_else(|_| etherparse::SlicedPacket::from_ethernet(data));

    let sliced = result.ok()?;

    let (src_ip, dst_ip) = match &sliced.net {
        Some(NetSlice::Ipv4(ipv4)) => {
            let h = ipv4.header();
            (
                Some(IpAddr::V4(h.source_addr())),
                Some(IpAddr::V4(h.destination_addr())),
            )
        }
        Some(NetSlice::Ipv6(ipv6)) => {
            let h = ipv6.header();
            (
                Some(IpAddr::V6(h.source_addr())),
                Some(IpAddr::V6(h.destination_addr())),
            )
        }
        _ => (None, None),
    };

    let (src_port, dst_port, protocol, tcp_flags, payload) = match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let h = tcp.to_header();
            (
                Some(h.source_port),
                Some(h.destination_port),
                PacketProtocol::Tcp,
                Some(TcpFlags::from_header(&h)),
                tcp.payload().to_vec(),
            )
        }
        Some(TransportSlice::Udp(udp)) => {
            let h = udp.to_header();
            (
                Some(h.source_port),
                Some(h.destination_port),
                PacketProtocol::Udp,
                None,
                udp.payload().to_vec(),
            )
        }
        Some(TransportSlice::Icmpv4(icmp)) => (
            None,
            None,
            PacketProtocol::Icmpv4,
            None,
            icmp.payload().to_vec(),
        ),
        Some(TransportSlice::Icmpv6(icmp)) => (
            None,
            None,
            PacketProtocol::Icmpv6,
            None,
            icmp.payload().to_vec(),
        ),
        _ => {
            let proto = match &sliced.net {
                Some(NetSlice::Ipv4(ipv4)) => PacketProtocol::Other(ipv4.header().protocol().0),
                Some(NetSlice::Ipv6(ipv6)) => PacketProtocol::Other(ipv6.header().next_header().0),
                _ => PacketProtocol::Other(0),
            };
            let pl = sliced
                .ip_payload()
                .map(|p| p.payload.to_vec())
                .unwrap_or_default();
            (None, None, proto, None, pl)
        }
    };

    Some(DecodedPacket {
        timestamp_us,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        tcp_flags,
        payload,
        packet_len: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid IPv4+TCP packet for testing
    fn build_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::PacketBuilder;

        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .tcp(src_port, dst_port, 1000, 65535);

        let mut buf = Vec::with_capacity(128 + payload.len());
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    fn build_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::PacketBuilder;

        let builder = PacketBuilder::ethernet2([0; 6], [0; 6])
            .ipv4(src_ip, dst_ip, 64)
            .udp(src_port, dst_port);

        let mut buf = Vec::with_capacity(128 + payload.len());
        builder.write(&mut buf, payload).unwrap();
        buf
    }

    #[test]
    fn test_decode_tcp() {
        let pkt = build_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            b"GET / HTTP/1.1\r\n",
        );
        let decoded = decode_packet(&pkt, 1000).unwrap();

        assert_eq!(
            decoded.src_ip.unwrap(),
            IpAddr::V4("10.0.0.1".parse().unwrap())
        );
        assert_eq!(
            decoded.dst_ip.unwrap(),
            IpAddr::V4("10.0.0.2".parse().unwrap())
        );
        assert_eq!(decoded.src_port, Some(12345));
        assert_eq!(decoded.dst_port, Some(80));
        assert_eq!(decoded.protocol, PacketProtocol::Tcp);
        assert!(decoded.payload.starts_with(b"GET /"));
    }

    #[test]
    fn test_decode_udp() {
        let pkt = build_udp_packet([192, 168, 1, 1], [8, 8, 8, 8], 5353, 53, b"\x00\x01");
        let decoded = decode_packet(&pkt, 2000).unwrap();

        assert_eq!(decoded.protocol, PacketProtocol::Udp);
        assert_eq!(decoded.src_port, Some(5353));
        assert_eq!(decoded.dst_port, Some(53));
    }

    #[test]
    fn test_decode_invalid() {
        // Totally invalid data
        assert!(decode_packet(&[0xFF, 0xFF], 0).is_none());
    }

    #[test]
    fn test_tcp_flags() {
        let flags = TcpFlags {
            syn: true,
            ack: false,
            fin: false,
            rst: false,
            psh: false,
            urg: false,
        };
        assert!(flags.is_syn_only());
        assert!(!flags.is_syn_ack());
    }
}
