use aifw_pf::PfState;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;

/// Extracted traffic features for a single source IP over a time window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficFeatures {
    pub source_ip: IpAddr,
    pub window_secs: u64,
    /// Total connections in window
    pub connection_count: u64,
    /// Unique destination IPs contacted
    pub unique_dst_ips: u64,
    /// Unique destination ports contacted
    pub unique_dst_ports: u64,
    /// Total bytes sent
    pub bytes_out: u64,
    /// Total bytes received
    pub bytes_in: u64,
    /// Total packets
    pub packets_total: u64,
    /// TCP SYN count (half-open connections)
    pub syn_count: u64,
    /// Failed connection ratio (SYN without ESTABLISHED)
    pub failed_conn_ratio: f64,
    /// Connections per second
    pub conn_rate: f64,
    /// Average payload size
    pub avg_payload_size: f64,
    /// DNS query count (port 53)
    pub dns_query_count: u64,
    /// Connection duration variance
    pub duration_variance: f64,
    /// Port entropy (how spread out the destination ports are)
    pub port_entropy: f64,
}

impl TrafficFeatures {
    /// Convert features to a flat f64 vector for ML inference
    pub fn to_feature_vector(&self) -> Vec<f64> {
        vec![
            self.connection_count as f64,
            self.unique_dst_ips as f64,
            self.unique_dst_ports as f64,
            self.bytes_out as f64,
            self.bytes_in as f64,
            self.packets_total as f64,
            self.syn_count as f64,
            self.failed_conn_ratio,
            self.conn_rate,
            self.avg_payload_size,
            self.dns_query_count as f64,
            self.duration_variance,
            self.port_entropy,
        ]
    }
}

/// Extract traffic features from a set of pf states, grouped by source IP
pub fn extract_features(states: &[PfState], window_secs: u64) -> Vec<TrafficFeatures> {
    let mut by_src: HashMap<IpAddr, Vec<&PfState>> = HashMap::new();
    for s in states {
        by_src.entry(s.src_addr).or_default().push(s);
    }

    by_src
        .into_iter()
        .map(|(src_ip, conns)| extract_ip_features(src_ip, &conns, window_secs))
        .collect()
}

fn extract_ip_features(src_ip: IpAddr, conns: &[&PfState], window_secs: u64) -> TrafficFeatures {
    let mut unique_ips = std::collections::HashSet::new();
    let mut unique_ports = std::collections::HashSet::new();
    let mut bytes_out: u64 = 0;
    let mut bytes_in: u64 = 0;
    let mut packets_total: u64 = 0;
    let mut syn_count: u64 = 0;
    let mut established_count: u64 = 0;
    let mut dns_count: u64 = 0;
    let mut durations = Vec::new();
    let mut total_payload: u64 = 0;

    for c in conns {
        unique_ips.insert(c.dst_addr);
        unique_ports.insert(c.dst_port);
        bytes_out += c.bytes_out;
        bytes_in += c.bytes_in;
        packets_total += c.packets_in + c.packets_out;
        total_payload += c.bytes_in + c.bytes_out;
        durations.push(c.age_secs as f64);

        if c.state.contains("SYN") {
            syn_count += 1;
        }
        if c.state.contains("ESTABLISHED") {
            established_count += 1;
        }
        if c.dst_port == 53 {
            dns_count += 1;
        }
    }

    let count = conns.len() as u64;
    let failed_ratio = if count > 0 {
        1.0 - (established_count as f64 / count as f64)
    } else {
        0.0
    };

    let conn_rate = if window_secs > 0 {
        count as f64 / window_secs as f64
    } else {
        count as f64
    };

    let avg_payload = if count > 0 {
        total_payload as f64 / count as f64
    } else {
        0.0
    };

    let duration_var = variance(&durations);
    let port_ent = port_entropy(&unique_ports);

    TrafficFeatures {
        source_ip: src_ip,
        window_secs,
        connection_count: count,
        unique_dst_ips: unique_ips.len() as u64,
        unique_dst_ports: unique_ports.len() as u64,
        bytes_out,
        bytes_in,
        packets_total,
        syn_count,
        failed_conn_ratio: failed_ratio,
        conn_rate,
        avg_payload_size: avg_payload,
        dns_query_count: dns_count,
        duration_variance: duration_var,
        port_entropy: port_ent,
    }
}

fn variance(values: &[f64]) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }
    let mean = values.iter().sum::<f64>() / values.len() as f64;
    let var = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (values.len() - 1) as f64;
    var
}

fn port_entropy(ports: &std::collections::HashSet<u16>) -> f64 {
    if ports.len() <= 1 {
        return 0.0;
    }
    // Shannon entropy of port distribution
    let n = ports.len() as f64;
    let total = 65535.0_f64;
    let p = 1.0 / n;
    -n * p * (p).log2() / (total).log2().max(1.0)
}
