// FreeBSD-only: real /dev/pf ioctl implementation
// This module only compiles on FreeBSD (cfg(target_os = "freebsd"))

use crate::backend::PfBackend;
use crate::error::PfError;
use crate::types::{PfState, PfStats, PfTableEntry};
use async_trait::async_trait;
use std::net::IpAddr;

pub struct PfIoctl {
    // Will hold the fd for /dev/pf when implemented
    _fd: i32,
}

impl PfIoctl {
    pub fn new() -> Result<Self, PfError> {
        // TODO: open /dev/pf via ioctl
        // let fd = unsafe { libc::open(b"/dev/pf\0".as_ptr() as *const _, libc::O_RDWR) };
        // if fd < 0 { return Err(PfError::DeviceOpen(...)); }
        Err(PfError::DeviceOpen(
            "FreeBSD ioctl backend not yet implemented".to_string(),
        ))
    }
}

impl Drop for PfIoctl {
    fn drop(&mut self) {
        // TODO: close fd
    }
}

#[async_trait]
impl PfBackend for PfIoctl {
    async fn add_rule(&self, _anchor: &str, _rule: &str) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: add_rule")
    }

    async fn flush_rules(&self, _anchor: &str) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: flush_rules")
    }

    async fn load_rules(&self, _anchor: &str, _rules: &[String]) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: load_rules")
    }

    async fn get_rules(&self, _anchor: &str) -> Result<Vec<String>, PfError> {
        todo!("FreeBSD ioctl: get_rules")
    }

    async fn get_states(&self) -> Result<Vec<PfState>, PfError> {
        todo!("FreeBSD ioctl: get_states")
    }

    async fn get_stats(&self) -> Result<PfStats, PfError> {
        todo!("FreeBSD ioctl: get_stats")
    }

    async fn add_table_entry(&self, _table: &str, _addr: IpAddr) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: add_table_entry")
    }

    async fn remove_table_entry(&self, _table: &str, _addr: IpAddr) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: remove_table_entry")
    }

    async fn flush_table(&self, _table: &str) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: flush_table")
    }

    async fn get_table_entries(&self, _table: &str) -> Result<Vec<PfTableEntry>, PfError> {
        todo!("FreeBSD ioctl: get_table_entries")
    }

    async fn is_running(&self) -> Result<bool, PfError> {
        todo!("FreeBSD ioctl: is_running")
    }

    async fn load_nat_rules(&self, _anchor: &str, _rules: &[String]) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: load_nat_rules")
    }

    async fn get_nat_rules(&self, _anchor: &str) -> Result<Vec<String>, PfError> {
        todo!("FreeBSD ioctl: get_nat_rules")
    }

    async fn flush_nat_rules(&self, _anchor: &str) -> Result<(), PfError> {
        todo!("FreeBSD ioctl: flush_nat_rules")
    }
}
