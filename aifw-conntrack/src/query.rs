use aifw_pf::PfState;
use std::net::IpAddr;

/// Criteria for filtering pf state entries. Every field is optional;
/// `None` means "match anything" for that dimension, and all set fields
/// must match (AND semantics).
#[derive(Debug, Clone, Default)]
pub struct ConnectionFilter {
    /// Protocol name, compared case-insensitively (e.g. "tcp")
    pub protocol: Option<String>,
    /// Exact source IP address
    pub src_addr: Option<IpAddr>,
    /// Exact destination IP address
    pub dst_addr: Option<IpAddr>,
    /// Exact source port
    pub src_port: Option<u16>,
    /// Exact destination port
    pub dst_port: Option<u16>,
    /// pf state string (e.g. "ESTABLISHED:ESTABLISHED"), compared case-insensitively
    pub state: Option<String>,
    /// Only match connections at least this old, in seconds
    pub min_age_secs: Option<u64>,
    /// Only match connections at most this old, in seconds
    pub max_age_secs: Option<u64>,
}

impl ConnectionFilter {
    /// Whether the given pf state entry satisfies every set criterion
    pub fn matches(&self, s: &PfState) -> bool {
        if let Some(ref proto) = self.protocol
            && !s.protocol.eq_ignore_ascii_case(proto)
        {
            return false;
        }
        if let Some(addr) = self.src_addr
            && s.src_addr != addr
        {
            return false;
        }
        if let Some(addr) = self.dst_addr
            && s.dst_addr != addr
        {
            return false;
        }
        if let Some(port) = self.src_port
            && s.src_port != port
        {
            return false;
        }
        if let Some(port) = self.dst_port
            && s.dst_port != port
        {
            return false;
        }
        if let Some(ref state) = self.state
            && !s.state.eq_ignore_ascii_case(state)
        {
            return false;
        }
        if let Some(min) = self.min_age_secs
            && s.age_secs < min
        {
            return false;
        }
        if let Some(max) = self.max_age_secs
            && s.age_secs > max
        {
            return false;
        }
        true
    }
}

/// Stateless query helpers over a slice of pf state entries
pub struct ConnectionQuery;

impl ConnectionQuery {
    /// Return clones of the states matching the filter
    pub fn filter(states: &[PfState], filter: &ConnectionFilter) -> Vec<PfState> {
        states
            .iter()
            .filter(|s| filter.matches(s))
            .cloned()
            .collect()
    }

    /// Count the states matching the filter without cloning them
    pub fn count(states: &[PfState], filter: &ConnectionFilter) -> usize {
        states.iter().filter(|s| filter.matches(s)).count()
    }

    /// Top `limit` IPs by total bytes transferred, descending. Each state's
    /// `bytes_out` is credited to its source IP and `bytes_in` to its
    /// destination IP.
    pub fn top_talkers(states: &[PfState], limit: usize) -> Vec<(IpAddr, u64)> {
        use std::collections::HashMap;
        let mut bytes_by_ip: HashMap<IpAddr, u64> = HashMap::new();
        for s in states {
            *bytes_by_ip.entry(s.src_addr).or_default() += s.bytes_out;
            *bytes_by_ip.entry(s.dst_addr).or_default() += s.bytes_in;
        }
        let mut sorted: Vec<_> = bytes_by_ip.into_iter().collect();
        sorted.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        sorted.truncate(limit);
        sorted
    }

    /// Connection counts grouped by lowercased protocol name, most common first
    pub fn connections_by_protocol(states: &[PfState]) -> Vec<(String, usize)> {
        use std::collections::HashMap;
        let mut counts: HashMap<String, usize> = HashMap::new();
        for s in states {
            *counts.entry(s.protocol.to_lowercase()).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by_key(|(_, v)| std::cmp::Reverse(*v));
        sorted
    }
}
