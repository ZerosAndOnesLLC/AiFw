//! A single tracked flow: bidirectional counters, TCP state machine, and
//! per-direction reassembly buffers.

use std::collections::HashSet;
use std::net::IpAddr;

use uuid::Uuid;

use super::key::{FlowDirection, FlowKey, FlowState};
use crate::decode::{DecodedPacket, TcpFlags};
use crate::protocol::AppProto;

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
