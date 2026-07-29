//! Syslog alert sink — forwards IDS alerts through the process-wide
//! remote-syslog pipeline (`aifw_common::syslog`).
//!
//! The sink is a thin adapter over a [`SyslogHandle`]: transport, format,
//! target, and reconnect handling all live in the shared client. It is
//! registered unconditionally at engine construction and self-gates on the
//! `ids_enabled` category toggle per emit, so config changes take effect
//! without rebuilding the pipeline.

use aifw_common::ids::IdsAlert;
use aifw_common::syslog::{Category, SyslogHandle};

use super::AlertOutput;
use crate::Result;

/// Forwards IDS alerts to the configured remote syslog server.
pub struct SyslogAlertOutput {
    handle: SyslogHandle,
}

impl SyslogAlertOutput {
    /// Wrap a handle from the process's `SyslogManager`.
    pub fn new(handle: SyslogHandle) -> Self {
        Self { handle }
    }

    fn severity_to_syslog(severity: u8) -> u8 {
        match severity {
            1 => 1, // Critical → Alert
            2 => 2, // High → Critical
            3 => 4, // Medium → Warning
            _ => 6, // Info → Informational
        }
    }

    fn format_alert(alert: &IdsAlert) -> String {
        format!(
            "IDS Alert: [{action}] {sig} src={src}:{sport} dst={dst}:{dport} proto={proto} severity={sev}",
            action = alert.action,
            sig = alert.signature_msg,
            src = alert.src_ip,
            sport = alert.src_port.unwrap_or(0),
            dst = alert.dst_ip,
            dport = alert.dst_port.unwrap_or(0),
            proto = alert.protocol,
            sev = alert.severity.label(),
        )
    }
}

#[async_trait::async_trait]
impl AlertOutput for SyslogAlertOutput {
    async fn emit(&self, alert: &IdsAlert) -> Result<()> {
        // O(1) gate; the message is only built when forwarding is on.
        if !self.handle.enabled_for(Category::Ids) {
            return Ok(());
        }
        self.handle.enqueue(
            Category::Ids,
            Self::severity_to_syslog(alert.severity.0),
            "aifw-ids",
            Self::format_alert(alert),
        );
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        Ok(()) // delivery is owned by the shared writer task
    }

    fn name(&self) -> &str {
        "syslog"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};
    use aifw_common::syslog::{SyslogConfig, SyslogManager, Transport};
    use std::time::Duration;

    fn alert() -> IdsAlert {
        let mut a = IdsAlert::new(
            "ET SCAN test signature".into(),
            IdsSeverity(2),
            "203.0.113.7".parse().expect("valid test IP"),
            "10.0.0.5".parse().expect("valid test IP"),
            "tcp",
            IdsAction::Alert,
            RuleSource::Custom,
        );
        a.src_port = Some(4444);
        a.dst_port = Some(22);
        a
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(SyslogAlertOutput::severity_to_syslog(1), 1);
        assert_eq!(SyslogAlertOutput::severity_to_syslog(2), 2);
        assert_eq!(SyslogAlertOutput::severity_to_syslog(3), 4);
        assert_eq!(SyslogAlertOutput::severity_to_syslog(4), 6);
    }

    #[tokio::test]
    async fn emits_alert_to_udp_server() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        let mgr = SyslogManager::start();
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            transport: Transport::Udp,
            ids_enabled: true,
            ..Default::default()
        });

        let out = SyslogAlertOutput::new(mgr.handle());
        out.emit(&alert()).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), server.recv_from(&mut buf))
            .await
            .expect("alert should be forwarded")
            .unwrap();
        let got = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(got.contains("aifw-ids"), "got: {got}");
        assert!(got.contains("ET SCAN test signature"), "got: {got}");
        assert!(got.contains("src=203.0.113.7:4444"), "got: {got}");
        assert!(got.contains("dst=10.0.0.5:22"), "got: {got}");
    }

    #[tokio::test]
    async fn disabled_category_sends_nothing() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();

        let mgr = SyslogManager::start();
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            transport: Transport::Udp,
            ids_enabled: false, // category off
            ..Default::default()
        });

        let out = SyslogAlertOutput::new(mgr.handle());
        out.emit(&alert()).await.unwrap();

        let mut buf = [0u8; 256];
        let r = tokio::time::timeout(Duration::from_millis(300), server.recv_from(&mut buf)).await;
        assert!(r.is_err(), "gated alert must not be forwarded");
    }
}
