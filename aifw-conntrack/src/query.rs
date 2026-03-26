use aifw_pf::PfState;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct ConnectionFilter {
    pub protocol: Option<String>,
    pub src_addr: Option<IpAddr>,
    pub dst_addr: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub state: Option<String>,
    pub min_age_secs: Option<u64>,
    pub max_age_secs: Option<u64>,
}

impl ConnectionFilter {
    pub fn matches(&self, s: &PfState) -> bool {
        if let Some(ref proto) = self.protocol {
            if !s.protocol.eq_ignore_ascii_case(proto) {
                return false;
            }
        }
        if let Some(addr) = self.src_addr {
            if s.src_addr != addr {
                return false;
            }
        }
        if let Some(addr) = self.dst_addr {
            if s.dst_addr != addr {
                return false;
            }
        }
        if let Some(port) = self.src_port {
            if s.src_port != port {
                return false;
            }
        }
        if let Some(port) = self.dst_port {
            if s.dst_port != port {
                return false;
            }
        }
        if let Some(ref state) = self.state {
            if !s.state.eq_ignore_ascii_case(state) {
                return false;
            }
        }
        if let Some(min) = self.min_age_secs {
            if s.age_secs < min {
                return false;
            }
        }
        if let Some(max) = self.max_age_secs {
            if s.age_secs > max {
                return false;
            }
        }
        true
    }
}

pub struct ConnectionQuery;

impl ConnectionQuery {
    pub fn filter(states: &[PfState], filter: &ConnectionFilter) -> Vec<PfState> {
        states.iter().filter(|s| filter.matches(s)).cloned().collect()
    }

    pub fn count(states: &[PfState], filter: &ConnectionFilter) -> usize {
        states.iter().filter(|s| filter.matches(s)).count()
    }

    pub fn top_talkers(states: &[PfState], limit: usize) -> Vec<(IpAddr, u64)> {
        use std::collections::HashMap;
        let mut bytes_by_ip: HashMap<IpAddr, u64> = HashMap::new();
        for s in states {
            *bytes_by_ip.entry(s.src_addr).or_default() += s.bytes_out;
            *bytes_by_ip.entry(s.dst_addr).or_default() += s.bytes_in;
        }
        let mut sorted: Vec<_> = bytes_by_ip.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted.truncate(limit);
        sorted
    }

    pub fn connections_by_protocol(states: &[PfState]) -> Vec<(String, usize)> {
        use std::collections::HashMap;
        let mut counts: HashMap<String, usize> = HashMap::new();
        for s in states {
            *counts.entry(s.protocol.to_lowercase()).or_default() += 1;
        }
        let mut sorted: Vec<_> = counts.into_iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        sorted
    }
}
