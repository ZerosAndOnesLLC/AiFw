use crate::backend::PfBackend;
use crate::error::PfError;
use crate::types::{PfState, PfStats, PfTableEntry};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;

pub struct PfMock {
    rules: RwLock<HashMap<String, Vec<String>>>,
    tables: RwLock<HashMap<String, Vec<IpAddr>>>,
    states: RwLock<Vec<PfState>>,
    running: RwLock<bool>,
}

impl PfMock {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            tables: RwLock::new(HashMap::new()),
            states: RwLock::new(Vec::new()),
            running: RwLock::new(true),
        }
    }

    /// Inject mock states for testing
    pub async fn inject_states(&self, states: Vec<PfState>) {
        *self.states.write().await = states;
    }

    /// Set the running state for testing
    pub async fn set_running(&self, running: bool) {
        *self.running.write().await = running;
    }
}

impl Default for PfMock {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PfBackend for PfMock {
    async fn add_rule(&self, anchor: &str, rule: &str) -> Result<(), PfError> {
        tracing::debug!(anchor, rule, "mock: add_rule");
        let mut rules = self.rules.write().await;
        rules.entry(anchor.to_string()).or_default().push(rule.to_string());
        Ok(())
    }

    async fn flush_rules(&self, anchor: &str) -> Result<(), PfError> {
        tracing::debug!(anchor, "mock: flush_rules");
        let mut rules = self.rules.write().await;
        rules.remove(anchor);
        Ok(())
    }

    async fn load_rules(&self, anchor: &str, new_rules: &[String]) -> Result<(), PfError> {
        tracing::debug!(anchor, count = new_rules.len(), "mock: load_rules");
        let mut rules = self.rules.write().await;
        rules.insert(anchor.to_string(), new_rules.to_vec());
        Ok(())
    }

    async fn get_rules(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let rules = self.rules.read().await;
        Ok(rules.get(anchor).cloned().unwrap_or_default())
    }

    async fn get_states(&self) -> Result<Vec<PfState>, PfError> {
        Ok(self.states.read().await.clone())
    }

    async fn get_stats(&self) -> Result<PfStats, PfError> {
        let rules = self.rules.read().await;
        let total_rules: usize = rules.values().map(|v| v.len()).sum();
        let states = self.states.read().await;
        Ok(PfStats {
            states_count: states.len() as u64,
            rules_count: total_rules as u64,
            running: *self.running.read().await,
            ..Default::default()
        })
    }

    async fn add_table_entry(&self, table: &str, addr: IpAddr) -> Result<(), PfError> {
        tracing::debug!(%addr, table, "mock: add_table_entry");
        let mut tables = self.tables.write().await;
        let entries = tables.entry(table.to_string()).or_default();
        if !entries.contains(&addr) {
            entries.push(addr);
        }
        Ok(())
    }

    async fn remove_table_entry(&self, table: &str, addr: IpAddr) -> Result<(), PfError> {
        tracing::debug!(%addr, table, "mock: remove_table_entry");
        let mut tables = self.tables.write().await;
        if let Some(entries) = tables.get_mut(table) {
            entries.retain(|a| *a != addr);
        }
        Ok(())
    }

    async fn flush_table(&self, table: &str) -> Result<(), PfError> {
        tracing::debug!(table, "mock: flush_table");
        let mut tables = self.tables.write().await;
        tables.remove(table);
        Ok(())
    }

    async fn get_table_entries(&self, table: &str) -> Result<Vec<PfTableEntry>, PfError> {
        let tables = self.tables.read().await;
        let entries = tables.get(table).cloned().unwrap_or_default();
        Ok(entries
            .into_iter()
            .map(|addr| PfTableEntry {
                addr,
                prefix: if addr.is_ipv4() { 32 } else { 128 },
                packets: 0,
                bytes: 0,
            })
            .collect())
    }

    async fn is_running(&self) -> Result<bool, PfError> {
        Ok(*self.running.read().await)
    }
}
