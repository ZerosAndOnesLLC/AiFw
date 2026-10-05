//! Turning hook events into human-readable notifications.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::hooks::{HookEvent, HookEventData};

/// How urgent a notification is; drives ntfy priority, Discord colour, …
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Needs attention now
    Critical,
    /// Degraded / suspicious
    Warning,
    /// Informational
    Info,
    /// A problem cleared
    Resolved,
}

/// Which category of event produced the notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// IDS alert
    IdsAlert,
    /// Gateway health change
    Gateway,
    /// VPN up/down
    Vpn,
    /// Audit-log configuration change
    Config,
    /// Operator-triggered test
    Test,
}

/// One notification, independent of channel.
#[derive(Debug, Clone, Serialize)]
pub struct Notification {
    /// Event category
    pub kind: Kind,
    /// Urgency
    pub level: Level,
    /// One-line summary
    pub title: String,
    /// Detail text
    pub body: String,
    /// Key/value context (rendered as fields where the channel supports it)
    pub fields: Vec<(String, String)>,
    /// When the event happened
    pub at: DateTime<Utc>,
    /// Same key within the dedupe window → sent once
    #[serde(skip)]
    pub dedupe_key: String,
}

/// Which events the operator wants.
#[derive(Debug, Clone)]
pub struct Filter {
    /// Send IDS alerts
    pub ids: bool,
    /// Only IDS alerts at or above this severity (1 = critical … 4 = low)
    pub ids_max_severity: u8,
    /// Send gateway changes
    pub gateway: bool,
    /// Send VPN changes
    pub vpn: bool,
    /// Send configuration changes
    pub config: bool,
    /// Audit actions that count as configuration changes
    pub config_actions: Vec<String>,
}

fn severity_name(sev: u8) -> &'static str {
    match sev {
        1 => "critical",
        2 => "high",
        3 => "medium",
        _ => "low",
    }
}

/// Classify a hook event. `None` = the operator doesn't want it.
pub fn classify(event: &HookEvent, f: &Filter) -> Option<Notification> {
    let now = Utc::now();
    match &event.data {
        HookEventData::IdsAlertEvent {
            alert_id,
            signature_id,
            signature_msg,
            severity,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            action,
            ..
        } => {
            if !f.ids || *severity > f.ids_max_severity {
                return None;
            }
            let ep = |ip: &std::net::IpAddr, port: &Option<u16>| match port {
                Some(p) => format!("{ip}:{p}"),
                None => ip.to_string(),
            };
            Some(Notification {
                kind: Kind::IdsAlert,
                level: if *severity <= 1 {
                    Level::Critical
                } else {
                    Level::Warning
                },
                title: format!("IDS {} alert: {signature_msg}", severity_name(*severity)),
                body: format!(
                    "{} → {} ({}), IDS action: {action}",
                    ep(src_ip, src_port),
                    ep(dst_ip, dst_port),
                    protocol.to_uppercase()
                ),
                fields: vec![
                    ("Severity".into(), severity_name(*severity).into()),
                    (
                        "Signature".into(),
                        signature_id.map_or_else(|| "—".into(), |s| s.to_string()),
                    ),
                    ("Source".into(), ep(src_ip, src_port)),
                    ("Destination".into(), ep(dst_ip, dst_port)),
                    ("Alert".into(), alert_id.clone()),
                ],
                at: now,
                dedupe_key: format!("ids:{}:{src_ip}", signature_id.unwrap_or(0)),
            })
        }
        HookEventData::Gateway {
            gateway_id,
            gateway_name,
            interface,
            from_state,
            to_state,
            reason,
        } => {
            if !f.gateway {
                return None;
            }
            let from = from_state.as_deref().unwrap_or("unknown");
            let (level, what) = match to_state.as_str() {
                "down" => (Level::Critical, "is DOWN"),
                "warning" => (Level::Warning, "is degraded"),
                // Boot-time unknown → up is not news.
                "up" if from == "unknown" => return None,
                "up" => (Level::Resolved, "is back up"),
                _ => return None,
            };
            let mut fields = vec![
                ("Interface".into(), interface.clone()),
                ("Change".into(), format!("{from} → {to_state}")),
            ];
            if let Some(r) = reason {
                fields.push(("Reason".into(), r.clone()));
            }
            Some(Notification {
                kind: Kind::Gateway,
                level,
                title: format!("Gateway {gateway_name} {what}"),
                body: reason
                    .clone()
                    .unwrap_or_else(|| format!("State changed from {from} to {to_state}.")),
                fields,
                at: now,
                dedupe_key: format!("gw:{gateway_id}:{to_state}"),
            })
        }
        HookEventData::Vpn {
            kind,
            tunnel_name,
            peer,
            action,
            detail,
        } => {
            if !f.vpn {
                return None;
            }
            let label = if kind == "ipsec" {
                "IPsec"
            } else {
                "WireGuard"
            };
            let subject = match peer {
                Some(p) => format!("{label} peer {p} on {tunnel_name}"),
                None => format!("{label} tunnel {tunnel_name}"),
            };
            let up = action == "up";
            Some(Notification {
                kind: Kind::Vpn,
                level: if up { Level::Resolved } else { Level::Warning },
                title: format!("{subject} is {}", if up { "up" } else { "down" }),
                body: detail.clone().unwrap_or_default(),
                fields: vec![("Tunnel".into(), tunnel_name.clone())],
                at: now,
                dedupe_key: format!(
                    "vpn:{tunnel_name}:{}:{action}",
                    peer.as_deref().unwrap_or("")
                ),
            })
        }
        HookEventData::Log {
            action,
            details,
            source,
        } => {
            // Our own settings changes are audited with source "plugins";
            // notifying about them would be noise (and could loop).
            if !f.config || source == "plugins" || !f.config_actions.iter().any(|a| a == action) {
                return None;
            }
            Some(Notification {
                kind: Kind::Config,
                level: Level::Info,
                title: format!("Configuration change: {}", action.replace('_', " ")),
                body: details.clone(),
                fields: vec![("Source".into(), source.clone())],
                at: now,
                dedupe_key: format!("audit:{action}:{details}"),
            })
        }
        HookEventData::Rule { .. } | HookEventData::Api { .. } | HookEventData::Tick { .. } => None,
    }
}

/// The notification sent by the "Send test" action.
pub fn test_notification() -> Notification {
    Notification {
        kind: Kind::Test,
        level: Level::Info,
        title: "AiFw test notification".into(),
        body: "If you can read this, AiFw can reach this channel.".into(),
        fields: Vec::new(),
        at: Utc::now(),
        dedupe_key: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookPoint;

    fn filter() -> Filter {
        Filter {
            ids: true,
            ids_max_severity: 2,
            gateway: true,
            vpn: true,
            config: true,
            config_actions: vec!["rules_applied".into()],
        }
    }

    fn ids(sev: u8) -> HookEvent {
        HookEvent {
            hook: HookPoint::IdsAlert,
            data: HookEventData::IdsAlertEvent {
                alert_id: "a1".into(),
                timestamp: "t".into(),
                signature_id: Some(2001),
                signature_msg: "ET SCAN nmap".into(),
                severity: sev,
                src_ip: "203.0.113.9".parse().unwrap(),
                dst_ip: "10.0.0.1".parse().unwrap(),
                src_port: Some(4444),
                dst_port: Some(22),
                protocol: "tcp".into(),
                action: "alert".into(),
                rule_source: "suricata".into(),
            },
        }
    }

    fn gw(from: Option<&str>, to: &str) -> HookEvent {
        HookEvent {
            hook: HookPoint::GatewayEvent,
            data: HookEventData::Gateway {
                gateway_id: "g".into(),
                gateway_name: "WAN1".into(),
                interface: "igb0".into(),
                from_state: from.map(str::to_string),
                to_state: to.into(),
                reason: Some("loss 40% > 20%".into()),
            },
        }
    }

    #[test]
    fn ids_severity_threshold() {
        let n = classify(&ids(1), &filter()).unwrap();
        assert_eq!(n.level, Level::Critical);
        assert!(n.title.contains("ET SCAN nmap"));
        assert!(n.body.contains("203.0.113.9:4444 → 10.0.0.1:22 (TCP)"));
        assert!(classify(&ids(2), &filter()).is_some());
        assert!(classify(&ids(3), &filter()).is_none());
        let off = Filter {
            ids: false,
            ..filter()
        };
        assert!(classify(&ids(1), &off).is_none());
    }

    #[test]
    fn gateway_transitions() {
        let down = classify(&gw(Some("up"), "down"), &filter()).unwrap();
        assert_eq!(down.level, Level::Critical);
        assert_eq!(down.title, "Gateway WAN1 is DOWN");
        let back = classify(&gw(Some("down"), "up"), &filter()).unwrap();
        assert_eq!(back.level, Level::Resolved);
        assert!(classify(&gw(Some("unknown"), "up"), &filter()).is_none());
        assert!(classify(&gw(None, "up"), &filter()).is_none());
    }

    #[test]
    fn config_changes_filtered_by_action_and_source() {
        let ev = |action: &str, source: &str| HookEvent {
            hook: HookPoint::LogEvent,
            data: HookEventData::Log {
                action: action.into(),
                details: "x".into(),
                source: source.into(),
            },
        };
        assert!(classify(&ev("rules_applied", "engine"), &filter()).is_some());
        assert!(classify(&ev("rule_added", "engine"), &filter()).is_none());
        assert!(classify(&ev("rules_applied", "plugins"), &filter()).is_none());
    }

    #[test]
    fn vpn_events() {
        let ev = HookEvent {
            hook: HookPoint::VpnEvent,
            data: HookEventData::Vpn {
                kind: "wireguard".into(),
                tunnel_name: "road".into(),
                peer: Some("laptop".into()),
                action: "down".into(),
                detail: Some("last handshake 400s ago".into()),
            },
        };
        let n = classify(&ev, &filter()).unwrap();
        assert_eq!(n.title, "WireGuard peer laptop on road is down");
        assert_eq!(n.level, Level::Warning);
    }
}
