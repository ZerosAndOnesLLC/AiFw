use crate::types::{PfState, PfStats, PfTableEntry};
use async_trait::async_trait;
use std::net::IpAddr;

#[async_trait]
pub trait PfBackend: Send + Sync {
    /// Add a pf rule to the specified anchor
    async fn add_rule(&self, anchor: &str, rule: &str) -> Result<(), crate::PfError>;

    /// Remove all rules from the specified anchor
    async fn flush_rules(&self, anchor: &str) -> Result<(), crate::PfError>;

    /// Load a set of rules into the specified anchor (replaces existing)
    async fn load_rules(&self, anchor: &str, rules: &[String]) -> Result<(), crate::PfError>;

    /// Get all rules in the specified anchor
    async fn get_rules(&self, anchor: &str) -> Result<Vec<String>, crate::PfError>;

    /// Get the current state table
    async fn get_states(&self) -> Result<Vec<PfState>, crate::PfError>;

    /// Get pf statistics
    async fn get_stats(&self) -> Result<PfStats, crate::PfError>;

    /// Add an address to a pf table
    async fn add_table_entry(
        &self,
        table: &str,
        addr: IpAddr,
    ) -> Result<(), crate::PfError>;

    /// Remove an address from a pf table
    async fn remove_table_entry(
        &self,
        table: &str,
        addr: IpAddr,
    ) -> Result<(), crate::PfError>;

    /// Flush all entries from a pf table
    async fn flush_table(&self, table: &str) -> Result<(), crate::PfError>;

    /// Get all entries in a pf table
    async fn get_table_entries(
        &self,
        table: &str,
    ) -> Result<Vec<PfTableEntry>, crate::PfError>;

    /// Check if pf is enabled and running
    async fn is_running(&self) -> Result<bool, crate::PfError>;

    /// Load NAT rules into the specified anchor (replaces existing)
    async fn load_nat_rules(&self, anchor: &str, rules: &[String]) -> Result<(), crate::PfError>;

    /// Get all NAT rules in the specified anchor
    async fn get_nat_rules(&self, anchor: &str) -> Result<Vec<String>, crate::PfError>;

    /// Flush all NAT rules from the specified anchor
    async fn flush_nat_rules(&self, anchor: &str) -> Result<(), crate::PfError>;

    /// Load queue definitions
    async fn load_queues(&self, anchor: &str, queues: &[String]) -> Result<(), crate::PfError>;

    /// Get current queue definitions
    async fn get_queues(&self, anchor: &str) -> Result<Vec<String>, crate::PfError>;

    /// Flush all queue definitions
    async fn flush_queues(&self, anchor: &str) -> Result<(), crate::PfError>;
}
