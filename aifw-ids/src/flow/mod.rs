use std::collections::HashSet;
use std::net::IpAddr;

use dashmap::DashMap;
use uuid::Uuid;

use crate::decode::{DecodedPacket, PacketProtocol, TcpFlags};
use crate::protocol::AppProto;

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
    #[default]
    New,
    SynSent,
    SynAckSeen,
    Established,
    FinWait,
    Closed,
}

/// Canonical flow key — ordered so both directions map to the same flow.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

/// A tracked network flow (bidirectional connection).
#[derive(Debug)]
pub struct Flow {
    pub id: Uuid,
    pub key: FlowKey,
    pub state: FlowState,
    /// Packets from initiator → responder
    pub pkts_toserver: u64,
    /// Packets from responder → initiator
    pub pkts_toclient: u64,
    /// Bytes from initiator → responder
    pub bytes_toserver: u64,
    /// Bytes from responder → initiator
    pub bytes_toclient: u64,
    /// Flow start time (microseconds since epoch)
    pub start_ts: i64,
    /// Last packet time (microseconds since epoch)
    pub last_ts: i64,
    /// Detected application protocol
    pub app_proto: Option<AppProto>,
    /// Reassembled toserver payload buffer
    pub toserver_buf: Vec<u8>,
    /// Reassembled toclient payload buffer
    pub toclient_buf: Vec<u8>,
    /// Maximum reassembly buffer depth per direction
    pub max_stream_depth: usize,
    /// Flowbits — per-flow flag set for multi-rule correlation
    pub flowbits: HashSet<String>,
    /// The initiator (first-seen) source IP
    pub initiator_ip: IpAddr,
    /// The initiator source port
    pub initiator_port: u16,
}

impl Flow {
    pub fn new(key: FlowKey, packet: &DecodedPacket, max_stream_depth: usize) -> Self {
        let src_ip = packet
            .src_ip
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let src_port = packet.src_port.unwrap_or(0);

        // Determine initial TCP state from first packet flags
        let initial_state = if let Some(ref flags) = packet.tcp_flags {
            if flags.is_syn_only() {
                FlowState::SynSent
            } else if flags.is_syn_ack() {
                FlowState::SynAckSeen
            } else if flags.ack {
                FlowState::Established
            } else {
                FlowState::New
            }
        } else {
            FlowState::New
        };

        let mut toserver_buf = Vec::new();
        if !packet.payload.is_empty() && toserver_buf.len() < max_stream_depth {
            let to_copy = max_stream_depth.min(packet.payload.len());
            toserver_buf.extend_from_slice(&packet.payload[..to_copy]);
        }

        Self {
            id: Uuid::new_v4(),
            key,
            state: initial_state,
            pkts_toserver: 1,
            pkts_toclient: 0,
            bytes_toserver: packet.packet_len as u64,
            bytes_toclient: 0,
            start_ts: packet.timestamp_us,
            last_ts: packet.timestamp_us,
            app_proto: None,
            toserver_buf,
            toclient_buf: Vec::new(),
            max_stream_depth,
            flowbits: HashSet::new(),
            initiator_ip: src_ip,
            initiator_port: src_port,
        }
    }

    /// Update flow with a new packet.
    pub fn update(&mut self, packet: &DecodedPacket, direction: FlowDirection) {
        self.last_ts = packet.timestamp_us;

        match direction {
            FlowDirection::ToServer => {
                self.pkts_toserver += 1;
                self.bytes_toserver += packet.packet_len as u64;
                // Reassemble payload
                if self.toserver_buf.len() < self.max_stream_depth {
                    let remaining = self.max_stream_depth - self.toserver_buf.len();
                    let to_copy = remaining.min(packet.payload.len());
                    self.toserver_buf
                        .extend_from_slice(&packet.payload[..to_copy]);
                }
            }
            FlowDirection::ToClient => {
                self.pkts_toclient += 1;
                self.bytes_toclient += packet.packet_len as u64;
                if self.toclient_buf.len() < self.max_stream_depth {
                    let remaining = self.max_stream_depth - self.toclient_buf.len();
                    let to_copy = remaining.min(packet.payload.len());
                    self.toclient_buf
                        .extend_from_slice(&packet.payload[..to_copy]);
                }
            }
        }

        // Update TCP state
        if let Some(flags) = &packet.tcp_flags {
            self.update_tcp_state(flags, direction);
        }
    }

    fn update_tcp_state(&mut self, flags: &TcpFlags, direction: FlowDirection) {
        self.state = match (self.state, direction) {
            (FlowState::New, FlowDirection::ToServer) if flags.is_syn_only() => FlowState::SynSent,
            (FlowState::SynSent, FlowDirection::ToClient) if flags.is_syn_ack() => {
                FlowState::SynAckSeen
            }
            (FlowState::SynAckSeen, FlowDirection::ToServer) if flags.ack => FlowState::Established,
            (FlowState::Established, _) if flags.fin => FlowState::FinWait,
            (FlowState::FinWait, _) if flags.fin || flags.ack => FlowState::Closed,
            (_, _) if flags.rst => FlowState::Closed,
            // SYN without prior state → new connection
            (FlowState::New, _) if flags.ack || !flags.syn => FlowState::Established,
            (state, _) => state,
        };
    }

    /// Check if the flow is established (or beyond).
    pub fn is_established(&self) -> bool {
        matches!(
            self.state,
            FlowState::Established | FlowState::FinWait | FlowState::Closed
        )
    }

    /// Get flow age in seconds.
    pub fn age_secs(&self) -> f64 {
        (self.last_ts - self.start_ts) as f64 / 1_000_000.0
    }
}

/// Concurrent flow table — lock-free per-entry access via DashMap.
pub struct FlowTable {
    table: DashMap<FlowKey, Flow>,
    max_stream_depth: usize,
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            table: DashMap::with_capacity(capacity),
            max_stream_depth: 1024 * 1024, // 1MB default stream depth
        }
    }

    pub fn with_stream_depth(mut self, depth: usize) -> Self {
        self.max_stream_depth = depth;
        self
    }

    /// Look up or create a flow for this packet. Returns the flow direction.
    pub fn track_packet(&self, packet: &DecodedPacket) -> Option<(FlowKey, FlowDirection)> {
        let src_ip = packet.src_ip?;
        let dst_ip = packet.dst_ip?;
        let src_port = packet.src_port.unwrap_or(0);
        let dst_port = packet.dst_port.unwrap_or(0);

        let proto = match packet.protocol {
            PacketProtocol::Tcp => 6,
            PacketProtocol::Udp => 17,
            PacketProtocol::Icmpv4 => 1,
            PacketProtocol::Icmpv6 => 58,
            PacketProtocol::Other(n) => n,
        };

        let key = FlowKey::from_packet(src_ip, dst_ip, src_port, dst_port, proto);
        let direction = key.direction(src_ip, src_port);

        self.table
            .entry(key.clone())
            .and_modify(|flow| flow.update(packet, direction))
            .or_insert_with(|| Flow::new(key.clone(), packet, self.max_stream_depth));

        Some((key, direction))
    }

    /// Get a reference to a flow by key.
    pub fn get(&self, key: &FlowKey) -> Option<dashmap::mapref::one::Ref<'_, FlowKey, Flow>> {
        self.table.get(key)
    }

    /// Get a mutable reference to a flow by key.
    pub fn get_mut(
        &self,
        key: &FlowKey,
    ) -> Option<dashmap::mapref::one::RefMut<'_, FlowKey, Flow>> {
        self.table.get_mut(key)
    }

    /// Number of active flows.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Remove expired flows older than `timeout_us` microseconds.
    pub fn expire(&self, now_us: i64, timeout_us: i64) -> usize {
        let cutoff = now_us - timeout_us;
        let before = self.table.len();
        self.table.retain(|_, flow| flow.last_ts > cutoff);
        before - self.table.len()
    }

    /// Clear all flows.
    pub fn clear(&self) {
        self.table.clear();
    }
}

impl std::fmt::Debug for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlowTable")
            .field("len", &self.table.len())
            .field("max_stream_depth", &self.max_stream_depth)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_key_canonical() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let k1 = FlowKey::from_packet(ip1, ip2, 12345, 80, 6);
        let k2 = FlowKey::from_packet(ip2, ip1, 80, 12345, 6);

        assert_eq!(
            k1, k2,
            "canonical key should be the same regardless of direction"
        );
    }

    #[test]
    fn test_flow_direction() {
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let key = FlowKey::from_packet(ip1, ip2, 12345, 80, 6);
        assert_eq!(key.direction(ip1, 12345), FlowDirection::ToServer);
        assert_eq!(key.direction(ip2, 80), FlowDirection::ToClient);
    }

    #[test]
    fn test_flow_table_track() {
        let table = FlowTable::new(1024);

        let packet = DecodedPacket {
            timestamp_us: 1000,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(12345),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ..Default::default()
            }),
            payload: vec![],
            packet_len: 64,
        };

        let result = table.track_packet(&packet);
        assert!(result.is_some());
        assert_eq!(table.len(), 1);

        // Second packet in reverse direction
        let packet2 = DecodedPacket {
            timestamp_us: 2000,
            src_ip: Some("10.0.0.2".parse().unwrap()),
            dst_ip: Some("10.0.0.1".parse().unwrap()),
            src_port: Some(80),
            dst_port: Some(12345),
            protocol: PacketProtocol::Tcp,
            tcp_flags: Some(TcpFlags {
                syn: true,
                ack: true,
                ..Default::default()
            }),
            payload: vec![],
            packet_len: 64,
        };

        let (key, dir) = table.track_packet(&packet2).unwrap();
        assert_eq!(dir, FlowDirection::ToClient);
        assert_eq!(table.len(), 1); // Same flow

        let flow = table.get(&key).unwrap();
        assert_eq!(flow.pkts_toserver, 1);
        assert_eq!(flow.pkts_toclient, 1);
        assert_eq!(flow.state, FlowState::SynAckSeen);
    }

    #[test]
    fn test_flow_expiry() {
        let table = FlowTable::new(1024);

        let packet = DecodedPacket {
            timestamp_us: 1_000_000,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 64,
        };

        table.track_packet(&packet);
        assert_eq!(table.len(), 1);

        // Expire with timeout of 1 second, now = 100 seconds later
        let expired = table.expire(100_000_000, 1_000_000);
        assert_eq!(expired, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn test_stream_reassembly() {
        let table = FlowTable::new(1024).with_stream_depth(256);

        let packet = DecodedPacket {
            timestamp_us: 1000,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: b"GET / HTTP/1.1\r\n".to_vec(),
            packet_len: 70,
        };

        let (key, _) = table.track_packet(&packet).unwrap();
        let flow = table.get(&key).unwrap();
        assert_eq!(flow.toserver_buf, b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn test_flowbits() {
        let key = FlowKey::from_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            1234,
            80,
            6,
        );
        let pkt = DecodedPacket {
            timestamp_us: 0,
            src_ip: Some("10.0.0.1".parse().unwrap()),
            dst_ip: Some("10.0.0.2".parse().unwrap()),
            src_port: Some(1234),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 0,
        };
        let mut flow = Flow::new(key, &pkt, 1024);

        flow.flowbits.insert("http.detected".to_string());
        assert!(flow.flowbits.contains("http.detected"));
        assert!(!flow.flowbits.contains("tls.detected"));

        flow.flowbits.remove("http.detected");
        assert!(!flow.flowbits.contains("http.detected"));
    }
}
