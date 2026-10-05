//! Row-cursor bridges: tail an append-only table and dispatch each new row
//! as a hook event. Used for tables written by other processes or crates
//! that can't call the plugin manager directly — audit_log (aifw-core
//! engines), ids_alerts (aifw-ids), multiwan_gateway_events (the daemon's
//! gateway probes).

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use aifw_plugins::{HookEvent, HookEventData, HookPoint};

use crate::AppState;

/// Rows dispatched per poll; a backlog drains over successive polls.
const BATCH: i64 = 500;

/// A table tailed into a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Source {
    /// audit_log → `LogEvent`
    Audit,
    /// ids_alerts → `IdsAlert`
    Ids,
    /// multiwan_gateway_events → `GatewayEvent`
    Gateway,
}

impl Source {
    pub(crate) fn hook(self) -> HookPoint {
        match self {
            Source::Audit => HookPoint::LogEvent,
            Source::Ids => HookPoint::IdsAlert,
            Source::Gateway => HookPoint::GatewayEvent,
        }
    }

    fn every(self) -> Duration {
        match self {
            Source::Audit | Source::Ids | Source::Gateway => Duration::from_secs(5),
        }
    }

    fn tail_sql(self) -> &'static str {
        match self {
            Source::Audit => "SELECT COALESCE(MAX(rowid), 0) FROM audit_log",
            Source::Ids => "SELECT COALESCE(MAX(rowid), 0) FROM ids_alerts",
            Source::Gateway => "SELECT COALESCE(MAX(id), 0) FROM multiwan_gateway_events",
        }
    }
}

/// Per-source state carried between polls.
#[derive(Default)]
pub(crate) struct Tail {
    cursor: i64,
    /// Gateway: last state dispatched per gateway. The API and the daemon
    /// both probe (and log) gateways the API touched, so one transition
    /// can appear twice.
    last_gateway_state: HashMap<String, String>,
}

impl Tail {
    /// Position the cursor at the current end of the table.
    pub(crate) async fn seek_end(&mut self, state: &AppState, src: Source) {
        self.cursor = max_id(state, src).await.unwrap_or(0);
        self.last_gateway_state.clear();
    }

    /// Dispatch rows written since the last poll.
    pub(crate) async fn poll(&mut self, state: &AppState, src: Source) {
        // The table shrank (purge / retention) — rowids may be reused from
        // a lower value, so re-anchor rather than wait to catch up.
        if let Some(max) = max_id(state, src).await
            && max < self.cursor
        {
            self.cursor = max;
        }
        let events = match src {
            Source::Audit => self.audit_rows(state).await,
            Source::Ids => self.ids_rows(state).await,
            Source::Gateway => self.gateway_rows(state).await,
        };
        match events {
            Ok(events) => {
                for e in events {
                    state.plugin_manager.dispatch(e).await;
                }
            }
            Err(e) => tracing::warn!(source = ?src, error = %e, "plugins: tail query failed"),
        }
    }

    async fn audit_rows(&mut self, state: &AppState) -> Result<Vec<HookEvent>, sqlx::Error> {
        let rows: Vec<(i64, String, String, String)> = sqlx::query_as(
            "SELECT rowid, action, details, source FROM audit_log \
             WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2",
        )
        .bind(self.cursor)
        .bind(BATCH)
        .fetch_all(&state.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(rowid, action, details, source)| {
                self.cursor = rowid;
                HookEvent {
                    hook: HookPoint::LogEvent,
                    data: HookEventData::Log {
                        action,
                        details,
                        source,
                    },
                }
            })
            .collect())
    }

    async fn ids_rows(&mut self, state: &AppState) -> Result<Vec<HookEvent>, sqlx::Error> {
        type Row = (
            i64,
            String,
            String,
            Option<i64>,
            String,
            i64,
            String,
            Option<i64>,
            String,
            Option<i64>,
            String,
            String,
            String,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT rowid, id, timestamp, signature_id, signature_msg, severity, \
             src_ip, src_port, dst_ip, dst_port, protocol, action, rule_source \
             FROM ids_alerts WHERE rowid > ?1 ORDER BY rowid ASC LIMIT ?2",
        )
        .bind(self.cursor)
        .bind(BATCH)
        .fetch_all(&state.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (rowid, id, ts, sid, msg, sev, src, sport, dst, dport, proto, action, rsrc) in rows {
            self.cursor = rowid;
            let (Ok(src_ip), Ok(dst_ip)) = (src.parse::<IpAddr>(), dst.parse::<IpAddr>()) else {
                tracing::debug!(alert = %id, "plugins: skipping IDS alert with unparseable address");
                continue;
            };
            out.push(HookEvent {
                hook: HookPoint::IdsAlert,
                data: HookEventData::IdsAlertEvent {
                    alert_id: id,
                    timestamp: ts,
                    signature_id: sid.and_then(|s| u32::try_from(s).ok()),
                    signature_msg: msg,
                    severity: u8::try_from(sev).unwrap_or(u8::MAX),
                    src_ip,
                    dst_ip,
                    src_port: sport.and_then(|p| u16::try_from(p).ok()),
                    dst_port: dport.and_then(|p| u16::try_from(p).ok()),
                    protocol: proto,
                    action,
                    rule_source: rsrc,
                },
            });
        }
        Ok(out)
    }

    async fn gateway_rows(&mut self, state: &AppState) -> Result<Vec<HookEvent>, sqlx::Error> {
        type Row = (
            i64,
            String,
            String,
            String,
            Option<String>,
            String,
            Option<String>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT e.id, e.gateway_id, COALESCE(g.name, e.gateway_id), \
             COALESCE(g.interface, ''), e.from_state, e.to_state, e.reason \
             FROM multiwan_gateway_events e \
             LEFT JOIN multiwan_gateways g ON g.id = e.gateway_id \
             WHERE e.id > ?1 ORDER BY e.id ASC LIMIT ?2",
        )
        .bind(self.cursor)
        .bind(BATCH)
        .fetch_all(&state.pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for (id, gw_id, name, iface, from, to, reason) in rows {
            self.cursor = id;
            if self.last_gateway_state.get(&gw_id) == Some(&to) {
                continue;
            }
            self.last_gateway_state.insert(gw_id.clone(), to.clone());
            out.push(HookEvent {
                hook: HookPoint::GatewayEvent,
                data: HookEventData::Gateway {
                    gateway_id: gw_id,
                    gateway_name: name,
                    interface: iface,
                    from_state: from,
                    to_state: to,
                    reason,
                },
            });
        }
        Ok(out)
    }
}

async fn max_id(state: &AppState, src: Source) -> Option<i64> {
    match sqlx::query_scalar(src.tail_sql())
        .fetch_one(&state.pool)
        .await
    {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::debug!(source = ?src, error = %e, "plugins: tail position unavailable");
            None
        }
    }
}

/// Run the tail for `src` forever. Idle (one atomic load per tick) while no
/// running plugin subscribes; on becoming active it seeks to the end so a
/// newly enabled plugin never receives a historical backlog.
pub(crate) fn spawn(state: AppState, src: Source) {
    tokio::spawn(async move {
        let mut tail = Tail::default();
        let mut active = false;
        let mut tick = tokio::time::interval(src.every());
        loop {
            tick.tick().await;
            if !state.plugin_manager.wants(src.hook()) {
                active = false;
                continue;
            }
            if !active {
                tail.seek_end(&state, src).await;
                active = true;
                continue;
            }
            tail.poll(&state, src).await;
        }
    });
}
