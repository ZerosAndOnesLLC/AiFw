//! Implements `IpcHandler` by delegating to an `IdsEngine`.

use aifw_ids::IdsEngine;
use aifw_ids_ipc::proto::{
    AlertSummary, IdsStats, IpcRequest, IpcResponse, RuleSummary, RulesetSummary,
};
use aifw_ids_ipc::server::IpcHandler;
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Instant;

pub struct EngineHandler {
    engine: Arc<IdsEngine>,
    started_at: Instant,
}

impl EngineHandler {
    pub fn new(engine: Arc<IdsEngine>) -> Self {
        Self {
            engine,
            started_at: Instant::now(),
        }
    }
}

#[async_trait]
impl IpcHandler for EngineHandler {
    async fn handle(&self, req: IpcRequest) -> IpcResponse {
        match req {
            IpcRequest::GetConfig => match self.engine.load_config().await {
                Ok(c) => IpcResponse::Config(c),
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::SetConfig { config } => match self.engine.save_config(&config).await {
                Ok(()) => IpcResponse::Ok,
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::Reload => {
                let mgr = aifw_ids::rules::manager::RulesetManager::new(self.engine.pool().clone());
                match mgr.compile_rules(self.engine.rule_db()).await {
                    Ok(_) => IpcResponse::Ok,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetStats => {
                let cfg = self.engine.load_config().await.ok();
                let mode = cfg
                    .as_ref()
                    .map(|c| format!("{:?}", c.mode).to_lowercase())
                    .unwrap_or_else(|| "unknown".into());
                let rules_loaded = self.engine.rule_db().rule_count() as u32;
                let flow_count = self
                    .engine
                    .flow_table()
                    .map(|t| t.len() as u64)
                    .unwrap_or(0);
                let flow_reassembly_bytes = self
                    .engine
                    .flow_table()
                    .map(|t| t.reassembly_bytes() as u64)
                    .unwrap_or(0);
                let engine_stats = self.engine.stats();
                IpcResponse::Stats(IdsStats {
                    mode,
                    running: self.engine.is_running(),
                    rules_loaded,
                    flow_count,
                    flow_reassembly_bytes,
                    packets_inspected: engine_stats.packets_inspected,
                    alerts_total: engine_stats.alerts_total,
                    drops_total: engine_stats.drops_total,
                    packets_per_sec: engine_stats.packets_per_sec,
                    bytes_per_sec: engine_stats.bytes_per_sec,
                    uptime_secs: self.started_at.elapsed().as_secs(),
                })
            }
            IpcRequest::ListRulesets => {
                match aifw_ids::rules::manager::RulesetManager::new(self.engine.pool().clone())
                    .list_rulesets()
                    .await
                {
                    Ok(rs) => IpcResponse::Rulesets(
                        rs.into_iter()
                            .map(|r| RulesetSummary {
                                id: r.id.to_string(),
                                name: r.name,
                                enabled: r.enabled,
                                rule_count: r.rule_count,
                            })
                            .collect(),
                    ),
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::GetRule { id } => match self.engine.get_rule(&id).await {
                Ok(Some(r)) => IpcResponse::Rule(Some(RuleSummary {
                    id: r.id,
                    sid: r.sid,
                    msg: r.msg,
                    action: r.action,
                    enabled: r.enabled,
                    raw: r.raw,
                })),
                Ok(None) => IpcResponse::Rule(None),
                Err(e) => IpcResponse::Error(e.to_string()),
            },
            IpcRequest::SetRule { id, enabled } => {
                match self.engine.set_rule_enabled(&id, enabled).await {
                    Ok(()) => IpcResponse::Ok,
                    Err(e) => IpcResponse::Error(e.to_string()),
                }
            }
            IpcRequest::TailAlerts { count } => {
                let alerts = match self.engine.alert_buffer() {
                    Some(buf) => buf.tail(count as usize).await,
                    None => Vec::new(),
                };
                IpcResponse::Alerts(
                    alerts
                        .into_iter()
                        .map(|a| AlertSummary {
                            id: a.id.to_string(),
                            timestamp: a.timestamp,
                            sid: a.signature_id.unwrap_or(0),
                            msg: a.signature_msg,
                            src_ip: a.src_ip.to_string(),
                            dst_ip: a.dst_ip.to_string(),
                            src_port: a.src_port,
                            dst_port: a.dst_port,
                            protocol: a.protocol,
                            severity: a.severity.0,
                        })
                        .collect(),
                )
            }
        }
    }
}
