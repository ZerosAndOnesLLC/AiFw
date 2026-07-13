//! The concurrent flow table: DashMap-backed lookup/insert, LRU + byte-
//! budget eviction, expiry, and the O(1) reassembly-byte accounting.

use std::sync::atomic::{AtomicUsize, Ordering};

use dashmap::DashMap;

use super::entry::Flow;
use super::key::{FlowDirection, FlowKey};
use crate::decode::{DecodedPacket, PacketProtocol};

/// Concurrent flow table — lock-free per-entry access via DashMap.
///
/// `reassembly_total` is an atomic counter maintained alongside the per-flow
/// `toserver_buf` / `toclient_buf` grows, so reassembly-budget checks are O(1)
/// instead of an O(N) iteration over the whole table on every packet.
pub struct FlowTable {
    table: DashMap<FlowKey, Flow>,
    max_stream_depth: usize,
    max_flows: usize,
    reassembly_budget_bytes: usize,
    reassembly_total: AtomicUsize,
}

/// Number of flows evicted per `evict_oldest_batch` pass. Amortizes the
/// O(N) scan over many evictions — the alternative (evict one at a time)
/// makes track_packet O(N) per call under cap pressure.
const EVICT_BATCH: usize = 128;

impl FlowTable {
    pub fn new(max_flows: usize) -> Self {
        Self {
            table: DashMap::with_capacity(max_flows),
            max_stream_depth: 65536, // 64 KB per direction — covers HTTP headers, TLS handshake, DNS, banners.
            max_flows,
            reassembly_budget_bytes: 256 * 1024 * 1024, // 256 MB
            reassembly_total: AtomicUsize::new(0),
        }
    }

    pub fn with_stream_depth(mut self, depth: usize) -> Self {
        self.max_stream_depth = depth;
        self
    }

    pub fn with_reassembly_budget(mut self, bytes: usize) -> Self {
        self.reassembly_budget_bytes = bytes;
        self
    }

    pub fn max_flows(&self) -> usize {
        self.max_flows
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

        // Evict if at cap and this is a new flow. For small tables we evict
        // exactly enough to make room (preserves the legacy "drop the single
        // oldest" semantic); for large tables we evict up to EVICT_BATCH so
        // the O(N) scan is amortized over many subsequent inserts.
        if !self.table.contains_key(&key) && self.table.len() >= self.max_flows {
            let table_len = self.table.len();
            let needed = table_len.saturating_sub(self.max_flows).saturating_add(1);
            // Amortize: when the table is large, sweep an EVICT_BATCH or
            // 10% of capacity, whichever is smaller (but never less than
            // the minimum needed to fit the new flow).
            let batched = (table_len / 10).min(EVICT_BATCH);
            self.evict_oldest_batch(needed.max(batched));
        }

        // Track reassembly delta atomically. We measure buf len before and
        // after the entry mutation so the global counter stays consistent
        // with the sum-of-bufs across all flows.
        let mut delta: i64 = 0;
        self.table
            .entry(key.clone())
            .and_modify(|flow| {
                let before = flow.toserver_buf.len() + flow.toclient_buf.len();
                flow.update(packet, direction);
                let after = flow.toserver_buf.len() + flow.toclient_buf.len();
                delta = after as i64 - before as i64;
            })
            .or_insert_with(|| {
                let flow = Flow::new(key.clone(), packet, self.max_stream_depth);
                delta = (flow.toserver_buf.len() + flow.toclient_buf.len()) as i64;
                flow
            });
        if delta != 0 {
            apply_signed_delta(&self.reassembly_total, delta);
        }

        // Enforce reassembly byte budget — batch-evict if over.
        if self.reassembly_total.load(Ordering::Relaxed) > self.reassembly_budget_bytes
            && !self.table.is_empty()
        {
            self.evict_oldest_batch(EVICT_BATCH);
        }

        Some((key, direction))
    }

    /// Evict up to `n` oldest entries in a single pass. O(N) scan + O(n log n)
    /// for partial sort, but amortized over n inserts → O(1) per insert when
    /// the table is at capacity.
    fn evict_oldest_batch(&self, n: usize) {
        // Bounded max-heap keyed by last_ts so we keep the smallest n entries
        // overall in one O(N log n) pass.
        use std::collections::BinaryHeap;
        let mut heap: BinaryHeap<(i64, FlowKey)> = BinaryHeap::with_capacity(n + 1);
        for entry in self.table.iter() {
            let ts = entry.value().last_ts;
            let key = entry.key().clone();
            if heap.len() < n {
                heap.push((ts, key));
            } else if let Some(&(top_ts, _)) = heap.peek()
                && ts < top_ts
            {
                heap.pop();
                heap.push((ts, key));
            }
        }
        // Remove the collected entries and decrement the reassembly counter.
        let mut freed: usize = 0;
        for (_, key) in heap.drain() {
            if let Some((_, flow)) = self.table.remove(&key) {
                freed += flow.toserver_buf.len() + flow.toclient_buf.len();
            }
        }
        if freed > 0 {
            self.reassembly_total.fetch_sub(freed, Ordering::Relaxed);
        }
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
        let mut freed: usize = 0;
        self.table.retain(|_, flow| {
            if flow.last_ts > cutoff {
                true
            } else {
                freed += flow.toserver_buf.len() + flow.toclient_buf.len();
                false
            }
        });
        if freed > 0 {
            self.reassembly_total.fetch_sub(freed, Ordering::Relaxed);
        }
        before - self.table.len()
    }

    /// Sum of toserver_buf.len() + toclient_buf.len() across all flows.
    /// O(1) — backed by an atomic counter maintained on insert/update/evict.
    pub fn reassembly_bytes(&self) -> usize {
        self.reassembly_total.load(Ordering::Relaxed)
    }

    /// Clear all flows.
    pub fn clear(&self) {
        self.table.clear();
        self.reassembly_total.store(0, Ordering::Relaxed);
    }
}

/// Apply a signed delta to an unsigned atomic counter, clamping at 0 on
/// underflow so a racing decrement can never produce a wrapped `usize::MAX`.
fn apply_signed_delta(counter: &AtomicUsize, delta: i64) {
    if delta >= 0 {
        counter.fetch_add(delta as usize, Ordering::Relaxed);
    } else {
        let dec = (-delta) as usize;
        let cur = counter.load(Ordering::Relaxed);
        let new = cur.saturating_sub(dec);
        counter.store(new, Ordering::Relaxed);
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
    use super::super::key::FlowState;
    use super::*;
    use crate::decode::TcpFlags;
    use std::net::IpAddr;

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
    fn default_stream_depth_is_64kb() {
        let table = FlowTable::new(1024);
        assert_eq!(table.max_stream_depth, 65536);
    }

    #[test]
    fn evicts_oldest_when_at_cap() {
        let table = FlowTable::new(3);
        let make_pkt = |src_octet: u8, ts: i64| DecodedPacket {
            timestamp_us: ts,
            src_ip: Some(format!("10.0.0.{src_octet}").parse().unwrap()),
            dst_ip: Some("10.0.1.1".parse().unwrap()),
            src_port: Some(1000),
            dst_port: Some(80),
            protocol: PacketProtocol::Tcp,
            tcp_flags: None,
            payload: vec![],
            packet_len: 64,
        };
        table.track_packet(&make_pkt(1, 1_000));
        table.track_packet(&make_pkt(2, 2_000));
        table.track_packet(&make_pkt(3, 3_000));
        assert_eq!(table.len(), 3);
        table.track_packet(&make_pkt(4, 4_000));
        assert_eq!(table.len(), 3, "should not exceed cap");
        // Oldest (src 1, ts 1000) should have been evicted.
        let oldest_key = FlowKey::from_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.1.1".parse().unwrap(),
            1000,
            80,
            6,
        );
        assert!(table.get(&oldest_key).is_none());
    }

    #[test]
    fn evicts_when_reassembly_budget_exceeded() {
        let table = FlowTable::new(1024).with_reassembly_budget(2048);
        let mut ts = 1_000;
        for i in 1..=10u8 {
            let pkt = DecodedPacket {
                timestamp_us: ts,
                src_ip: Some(format!("10.0.0.{i}").parse().unwrap()),
                dst_ip: Some("10.0.1.1".parse().unwrap()),
                src_port: Some(1000),
                dst_port: Some(80),
                protocol: PacketProtocol::Tcp,
                tcp_flags: None,
                payload: vec![0u8; 512], // 512 bytes per direction
                packet_len: 600,
            };
            table.track_packet(&pkt);
            ts += 1_000;
        }
        assert!(
            table.reassembly_bytes() <= 2048,
            "budget exceeded: {}",
            table.reassembly_bytes()
        );
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
