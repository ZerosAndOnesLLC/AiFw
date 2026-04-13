use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfState {
    pub id: u64,
    pub protocol: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub state: String,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub age_secs: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtable: Option<u32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PfStats {
    pub states_count: u64,
    pub states_searches: u64,
    pub states_inserts: u64,
    pub states_removals: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rules_count: u64,
    pub running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfTableEntry {
    pub addr: IpAddr,
    pub prefix: u8,
    pub packets: u64,
    pub bytes: u64,
}
