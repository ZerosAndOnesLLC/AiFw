use aifw_common::{NatRule, QueueConfig, RateLimitRule, Rule};
use aifw_conntrack::{ConnectionTracker, ConntrackStats};
use aifw_core::{Database, NatEngine, RuleEngine, ShapingEngine};
use aifw_pf::{PfBackend, PfState, PfStats};
use std::sync::Arc;

use aifw_core::audit::AuditEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Rules,
    Nat,
    Connections,
    Logs,
}

impl Tab {
    pub const ALL: [Tab; 5] = [
        Tab::Dashboard,
        Tab::Rules,
        Tab::Nat,
        Tab::Connections,
        Tab::Logs,
    ];

    pub fn title(&self) -> &'static str {
        match self {
            Tab::Dashboard => "Dashboard",
            Tab::Rules => "Rules",
            Tab::Nat => "NAT",
            Tab::Connections => "Connections",
            Tab::Logs => "Logs",
        }
    }

    pub fn next(&self) -> Tab {
        match self {
            Tab::Dashboard => Tab::Rules,
            Tab::Rules => Tab::Nat,
            Tab::Nat => Tab::Connections,
            Tab::Connections => Tab::Logs,
            Tab::Logs => Tab::Dashboard,
        }
    }

    pub fn prev(&self) -> Tab {
        match self {
            Tab::Dashboard => Tab::Logs,
            Tab::Rules => Tab::Dashboard,
            Tab::Nat => Tab::Rules,
            Tab::Connections => Tab::Nat,
            Tab::Logs => Tab::Connections,
        }
    }
}

pub struct App {
    pub tab: Tab,
    pub running: bool,
    pub pf: Arc<dyn PfBackend>,
    pub rule_engine: Arc<RuleEngine>,
    pub nat_engine: Arc<NatEngine>,
    pub shaping_engine: Arc<ShapingEngine>,
    pub conntrack: Arc<ConnectionTracker>,

    // Cached data
    pub pf_stats: PfStats,
    pub rules: Vec<Rule>,
    pub nat_rules: Vec<NatRule>,
    pub connections: Vec<PfState>,
    pub conntrack_stats: ConntrackStats,
    pub top_talkers: Vec<(std::net::IpAddr, u64)>,
    pub audit_entries: Vec<AuditEntry>,
    pub queues: Vec<QueueConfig>,
    pub rate_limits: Vec<RateLimitRule>,

    // Selection state
    pub rules_selected: usize,
    pub nat_selected: usize,
    pub conn_selected: usize,
    pub log_selected: usize,
}

impl App {
    pub async fn new(db_path: &std::path::Path) -> anyhow::Result<Self> {
        let db = Database::new(db_path).await?;
        let pf: Arc<dyn PfBackend> = Arc::from(aifw_pf::create_backend());
        Self::with_backend(db, pf).await
    }

    /// Build the app on an existing database + pf backend (tests use an
    /// in-memory DB and the mock backend).
    pub async fn with_backend(db: Database, pf: Arc<dyn PfBackend>) -> anyhow::Result<Self> {
        let pool = db.pool().clone();

        let rule_engine = Arc::new(RuleEngine::new(pool.clone(), pf.clone()));
        // "aifw-nat" — must match the API/daemon anchor (#531).
        let nat_engine = Arc::new(NatEngine::new(pool.clone(), pf.clone()));
        nat_engine.migrate().await?;
        let shaping_engine = Arc::new(ShapingEngine::new(pool.clone(), pf.clone()));
        shaping_engine.migrate().await?;
        let conntrack = Arc::new(ConnectionTracker::new(pf.clone()));

        let mut app = Self {
            tab: Tab::Dashboard,
            running: true,
            pf,
            rule_engine,
            nat_engine,
            shaping_engine,
            conntrack,
            pf_stats: PfStats::default(),
            rules: Vec::new(),
            nat_rules: Vec::new(),
            connections: Vec::new(),
            conntrack_stats: ConntrackStats::default(),
            top_talkers: Vec::new(),
            audit_entries: Vec::new(),
            queues: Vec::new(),
            rate_limits: Vec::new(),
            rules_selected: 0,
            nat_selected: 0,
            conn_selected: 0,
            log_selected: 0,
        };

        app.refresh().await;
        Ok(app)
    }

    pub async fn refresh(&mut self) {
        if let Ok(stats) = self.pf.get_stats().await {
            self.pf_stats = stats;
        }
        if let Ok(rules) = self.rule_engine.list().await {
            self.rules = rules;
        }
        if let Ok(nat) = self.nat_engine.list().await {
            self.nat_rules = nat;
        }
        let _ = self.conntrack.refresh().await;
        self.connections = self.conntrack.get_connections().await.to_vec();
        self.conntrack_stats = self.conntrack.stats().await;
        self.top_talkers = self.conntrack.top_talkers(10).await;
        if let Ok(entries) = self.rule_engine.audit().list(100).await {
            self.audit_entries = entries;
        }
        if let Ok(q) = self.shaping_engine.list_queues().await {
            self.queues = q;
        }
        if let Ok(r) = self.shaping_engine.list_rate_limits().await {
            self.rate_limits = r;
        }
    }

    pub async fn delete_selected_rule(&mut self) {
        if let Some(rule) = self.rules.get(self.rules_selected) {
            let id = rule.id;
            if self.rule_engine.delete(id).await.is_ok() {
                self.refresh().await;
                if self.rules_selected > 0 && self.rules_selected >= self.rules.len() {
                    self.rules_selected = self.rules.len().saturating_sub(1);
                }
            }
        }
    }

    pub async fn delete_selected_nat(&mut self) {
        if let Some(rule) = self.nat_rules.get(self.nat_selected) {
            let id = rule.id;
            if self.nat_engine.delete(id).await.is_ok() {
                self.refresh().await;
                if self.nat_selected > 0 && self.nat_selected >= self.nat_rules.len() {
                    self.nat_selected = self.nat_rules.len().saturating_sub(1);
                }
            }
        }
    }

    pub fn select_up(&mut self) {
        match self.tab {
            Tab::Rules => {
                self.rules_selected = self.rules_selected.saturating_sub(1);
            }
            Tab::Nat => {
                self.nat_selected = self.nat_selected.saturating_sub(1);
            }
            Tab::Connections => {
                self.conn_selected = self.conn_selected.saturating_sub(1);
            }
            Tab::Logs => {
                self.log_selected = self.log_selected.saturating_sub(1);
            }
            _ => {}
        }
    }

    pub fn select_down(&mut self) {
        match self.tab {
            Tab::Rules if !self.rules.is_empty() => {
                self.rules_selected = (self.rules_selected + 1).min(self.rules.len() - 1);
            }
            Tab::Nat if !self.nat_rules.is_empty() => {
                self.nat_selected = (self.nat_selected + 1).min(self.nat_rules.len() - 1);
            }
            Tab::Connections if !self.connections.is_empty() => {
                self.conn_selected = (self.conn_selected + 1).min(self.connections.len() - 1);
            }
            Tab::Logs if !self.audit_entries.is_empty() => {
                self.log_selected = (self.log_selected + 1).min(self.audit_entries.len() - 1);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::{Action, Address, Direction, Protocol, RuleMatch};

    async fn app() -> App {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        App::with_backend(db, pf).await.unwrap()
    }

    fn rule(port: u16) -> Rule {
        Rule::new(
            Action::Pass,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(aifw_common::PortRange {
                    start: port,
                    end: port,
                }),
            },
        )
    }

    #[test]
    fn tabs_cycle_in_both_directions() {
        let mut t = Tab::Dashboard;
        for expected in Tab::ALL.iter().skip(1) {
            t = t.next();
            assert_eq!(t.title(), expected.title());
        }
        assert_eq!(t.next().title(), Tab::Dashboard.title(), "wraps forward");
        let mut t = Tab::Dashboard;
        assert_eq!(t.prev().title(), Tab::Logs.title(), "wraps backward");
        for _ in 0..Tab::ALL.len() {
            t = t.prev();
        }
        assert_eq!(t.title(), Tab::Dashboard.title(), "full backward cycle");
        // Every title is distinct — the tab bar relies on it.
        let mut titles: Vec<&str> = Tab::ALL.iter().map(Tab::title).collect();
        titles.sort();
        titles.dedup();
        assert_eq!(titles.len(), Tab::ALL.len());
    }

    #[tokio::test]
    async fn fresh_app_starts_on_dashboard_with_empty_caches() {
        let a = app().await;
        assert!(a.running);
        assert_eq!(a.tab.title(), "Dashboard");
        assert!(a.rules.is_empty() && a.nat_rules.is_empty() && a.connections.is_empty());
        assert_eq!(a.rules_selected, 0);
    }

    #[tokio::test]
    async fn selection_is_clamped_per_tab_and_no_op_on_empty_lists() {
        let mut a = app().await;
        a.tab = Tab::Rules;
        // Empty list: down does nothing, up saturates at 0.
        a.select_down();
        a.select_up();
        assert_eq!(a.rules_selected, 0);

        a.rule_engine.add(rule(22)).await.unwrap();
        a.rule_engine.add(rule(80)).await.unwrap();
        a.rule_engine.add(rule(443)).await.unwrap();
        a.refresh().await;
        assert_eq!(a.rules.len(), 3);
        for _ in 0..10 {
            a.select_down();
        }
        assert_eq!(a.rules_selected, 2, "clamped to last row");
        a.select_up();
        assert_eq!(a.rules_selected, 1);
        // Selection state is per tab — moving on Rules must not touch NAT.
        assert_eq!(a.nat_selected, 0);
        a.tab = Tab::Dashboard;
        a.select_down();
        assert_eq!(a.rules_selected, 1, "dashboard has no selection");
    }

    #[tokio::test]
    async fn delete_selected_rule_removes_it_and_keeps_selection_in_range() {
        let mut a = app().await;
        a.rule_engine.add(rule(22)).await.unwrap();
        a.rule_engine.add(rule(80)).await.unwrap();
        a.refresh().await;
        a.tab = Tab::Rules;
        a.select_down();
        assert_eq!(a.rules_selected, 1);
        a.delete_selected_rule().await;
        assert_eq!(a.rules.len(), 1);
        assert!(
            a.rules_selected < a.rules.len(),
            "selection stays in range after delete"
        );
        a.delete_selected_rule().await;
        assert!(a.rules.is_empty());
        // Deleting with nothing selected is a no-op, not a panic.
        a.delete_selected_rule().await;
    }
}
