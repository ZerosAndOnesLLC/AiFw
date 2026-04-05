use std::sync::Arc;

use aifw_common::ids::{IdsAction, IdsAlert, IdsMode};
use aifw_pf::PfBackend;
use tracing::{info, warn};

use crate::config::RuntimeConfig;

/// The IDS block table in pf
const IDS_BLOCK_TABLE: &str = "aifw-ids-block";

/// Verdict from the action engine
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Pass the packet (no action)
    Pass,
    /// Alert only (IDS mode or alert action)
    Alert,
    /// Drop the packet (IPS mode + drop action)
    Drop,
    /// Reject the packet — send RST/ICMP unreachable (IPS mode + reject action)
    Reject,
}

/// The action engine determines what happens after a detection match.
/// In IDS mode, all verdicts become alerts. In IPS mode, drops are enforced via pf.
pub struct ActionEngine {
    pf: Arc<dyn PfBackend>,
    config: Arc<RuntimeConfig>,
}

impl ActionEngine {
    pub fn new(pf: Arc<dyn PfBackend>, config: Arc<RuntimeConfig>) -> Self {
        Self { pf, config }
    }

    /// Determine the verdict for an alert based on mode and rule action.
    pub fn verdict(&self, alert: &IdsAlert) -> Verdict {
        let mode = self.config.config().mode;

        match mode {
            IdsMode::Ids => {
                // IDS mode: everything is an alert
                Verdict::Alert
            }
            IdsMode::Ips => {
                // IPS mode: enforce the rule action
                match alert.action {
                    IdsAction::Pass => Verdict::Pass,
                    IdsAction::Alert => Verdict::Alert,
                    IdsAction::Drop => Verdict::Drop,
                    IdsAction::Reject => Verdict::Reject,
                }
            }
            IdsMode::Disabled => Verdict::Pass,
        }
    }

    /// Execute the verdict — add to pf block table if needed.
    pub async fn execute(&self, alert: &IdsAlert, verdict: &Verdict) {
        match verdict {
            Verdict::Drop | Verdict::Reject => {
                info!(
                    src = %alert.src_ip,
                    sig = %alert.signature_msg,
                    action = %if *verdict == Verdict::Drop { "drop" } else { "reject" },
                    "IPS blocking source"
                );

                if let Err(e) = self
                    .pf
                    .add_table_entry(IDS_BLOCK_TABLE, alert.src_ip)
                    .await
                {
                    warn!("failed to add {} to IDS block table: {e}", alert.src_ip);
                }
            }
            _ => {}
        }
    }

    /// Remove an IP from the IDS block table.
    pub async fn unblock(&self, ip: std::net::IpAddr) {
        if let Err(e) = self.pf.remove_table_entry(IDS_BLOCK_TABLE, ip).await {
            warn!("failed to remove {ip} from IDS block table: {e}");
        }
    }

    /// Flush the IDS block table.
    pub async fn flush_blocks(&self) {
        if let Err(e) = self.pf.flush_table(IDS_BLOCK_TABLE).await {
            warn!("failed to flush IDS block table: {e}");
        }
    }
}

impl std::fmt::Debug for ActionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActionEngine").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::ids::{IdsSeverity, RuleSource};

    fn test_alert(action: IdsAction) -> IdsAlert {
        IdsAlert::new(
            "Test alert".into(),
            IdsSeverity::HIGH,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "tcp",
            action,
            RuleSource::Custom,
        )
    }

    #[tokio::test]
    async fn test_verdict_ids_mode() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();

        let config = Arc::new(RuntimeConfig::load(&pool).await.unwrap());

        // Set IDS mode
        let mut cfg = config.config();
        cfg.mode = IdsMode::Ids;
        config.update(cfg);

        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = ActionEngine::new(pf, config);

        // In IDS mode, everything becomes Alert
        assert_eq!(engine.verdict(&test_alert(IdsAction::Drop)), Verdict::Alert);
        assert_eq!(engine.verdict(&test_alert(IdsAction::Reject)), Verdict::Alert);
        assert_eq!(engine.verdict(&test_alert(IdsAction::Alert)), Verdict::Alert);
    }

    #[tokio::test]
    async fn test_verdict_ips_mode() {
        let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
        crate::IdsEngine::migrate(&pool).await.unwrap();

        let config = Arc::new(RuntimeConfig::load(&pool).await.unwrap());

        let mut cfg = config.config();
        cfg.mode = IdsMode::Ips;
        config.update(cfg);

        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = ActionEngine::new(pf, config);

        assert_eq!(engine.verdict(&test_alert(IdsAction::Drop)), Verdict::Drop);
        assert_eq!(engine.verdict(&test_alert(IdsAction::Reject)), Verdict::Reject);
        assert_eq!(engine.verdict(&test_alert(IdsAction::Alert)), Verdict::Alert);
        assert_eq!(engine.verdict(&test_alert(IdsAction::Pass)), Verdict::Pass);
    }
}
