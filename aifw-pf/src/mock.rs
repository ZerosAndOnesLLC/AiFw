use crate::backend::PfBackend;
use crate::error::PfError;
use crate::types::{PfState, PfStats, PfTableEntry};
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::sync::RwLock;

pub struct PfMock {
    rules: RwLock<HashMap<String, Vec<String>>>,
    nat_rules: RwLock<HashMap<String, Vec<String>>>,
    queues: RwLock<HashMap<String, Vec<String>>>,
    tables: RwLock<HashMap<String, Vec<IpAddr>>>,
    states: RwLock<Vec<PfState>>,
    running: RwLock<bool>,
    iface_fibs: RwLock<HashMap<String, u32>>,
    fib_count: RwLock<u32>,
}

impl PfMock {
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
            nat_rules: RwLock::new(HashMap::new()),
            queues: RwLock::new(HashMap::new()),
            tables: RwLock::new(HashMap::new()),
            states: RwLock::new(Vec::new()),
            running: RwLock::new(true),
            iface_fibs: RwLock::new(HashMap::new()),
            fib_count: RwLock::new(1),
        }
    }

    /// Override the number of available FIBs for testing multi-WAN scenarios.
    pub async fn set_fib_count(&self, n: u32) {
        *self.fib_count.write().await = n.max(1);
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

    async fn load_nat_rules(&self, anchor: &str, rules: &[String]) -> Result<(), PfError> {
        tracing::debug!(anchor, count = rules.len(), "mock: load_nat_rules");
        let mut nat_rules = self.nat_rules.write().await;
        nat_rules.insert(anchor.to_string(), rules.to_vec());
        Ok(())
    }

    async fn get_nat_rules(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let nat_rules = self.nat_rules.read().await;
        Ok(nat_rules.get(anchor).cloned().unwrap_or_default())
    }

    async fn flush_nat_rules(&self, anchor: &str) -> Result<(), PfError> {
        tracing::debug!(anchor, "mock: flush_nat_rules");
        let mut nat_rules = self.nat_rules.write().await;
        nat_rules.remove(anchor);
        Ok(())
    }

    async fn load_queues(&self, anchor: &str, queue_defs: &[String]) -> Result<(), PfError> {
        tracing::debug!(anchor, count = queue_defs.len(), "mock: load_queues");
        let mut queues = self.queues.write().await;
        queues.insert(anchor.to_string(), queue_defs.to_vec());
        Ok(())
    }

    async fn get_queues(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let queues = self.queues.read().await;
        Ok(queues.get(anchor).cloned().unwrap_or_default())
    }

    async fn flush_queues(&self, anchor: &str) -> Result<(), PfError> {
        tracing::debug!(anchor, "mock: flush_queues");
        let mut queues = self.queues.write().await;
        queues.remove(anchor);
        Ok(())
    }

    async fn set_interface_fib(&self, iface: &str, fib: u32) -> Result<(), PfError> {
        tracing::debug!(iface, fib, "mock: set_interface_fib");
        let fib_count = *self.fib_count.read().await;
        if fib >= fib_count {
            return Err(PfError::Other(format!(
                "fib {fib} out of range (net.fibs={fib_count})"
            )));
        }
        self.iface_fibs
            .write()
            .await
            .insert(iface.to_string(), fib);
        Ok(())
    }

    async fn get_interface_fib(&self, iface: &str) -> Result<u32, PfError> {
        Ok(self
            .iface_fibs
            .read()
            .await
            .get(iface)
            .copied()
            .unwrap_or(0))
    }

    async fn list_fibs(&self) -> Result<u32, PfError> {
        Ok(*self.fib_count.read().await)
    }

    async fn kill_states_on_iface(&self, iface: &str) -> Result<u64, PfError> {
        tracing::debug!(iface, "mock: kill_states_on_iface");
        let mut states = self.states.write().await;
        let before = states.len();
        states.retain(|s| s.iface.as_deref() != Some(iface));
        Ok((before - states.len()) as u64)
    }

    async fn kill_states_for_label(&self, label: &str) -> Result<u64, PfError> {
        tracing::debug!(label, "mock: kill_states_for_label");
        Ok(0)
    }
}
