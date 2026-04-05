use std::net::UdpSocket;

use aifw_common::ids::IdsAlert;

use super::AlertOutput;
use crate::Result;

/// Syslog alert output — sends alerts to a remote syslog server via UDP.
pub struct SyslogOutput {
    target: String,
    socket: Option<UdpSocket>,
    facility: u8,
}

impl SyslogOutput {
    pub fn new(target: String) -> Self {
        let socket = UdpSocket::bind("0.0.0.0:0").ok();
        Self {
            target,
            socket,
            facility: 4, // LOG_AUTH
        }
    }

    pub fn with_facility(mut self, facility: u8) -> Self {
        self.facility = facility;
        self
    }

    fn severity_to_syslog(severity: u8) -> u8 {
        match severity {
            1 => 1,     // Critical → Alert
            2 => 2,     // High → Critical
            3 => 4,     // Medium → Warning
            _ => 6,     // Info → Informational
        }
    }
}

#[async_trait::async_trait]
impl AlertOutput for SyslogOutput {
    async fn emit(&self, alert: &IdsAlert) -> Result<()> {
        let socket = match &self.socket {
            Some(s) => s,
            None => return Ok(()),
        };

        let syslog_severity = Self::severity_to_syslog(alert.severity.0);
        let priority = (self.facility as u16) * 8 + syslog_severity as u16;

        // RFC 5424 format
        let msg = format!(
            "<{priority}>1 {timestamp} aifw aifw-ids - - - IDS Alert: [{action}] {sig} src={src}:{sport} dst={dst}:{dport} proto={proto} severity={sev}",
            priority = priority,
            timestamp = alert.timestamp.to_rfc3339(),
            action = alert.action,
            sig = alert.signature_msg,
            src = alert.src_ip,
            sport = alert.src_port.unwrap_or(0),
            dst = alert.dst_ip,
            dport = alert.dst_port.unwrap_or(0),
            proto = alert.protocol,
            sev = alert.severity.label(),
        );

        let _ = socket.send_to(msg.as_bytes(), &self.target);

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        Ok(()) // UDP is fire-and-forget
    }

    fn name(&self) -> &str {
        "syslog"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_mapping() {
        assert_eq!(SyslogOutput::severity_to_syslog(1), 1);
        assert_eq!(SyslogOutput::severity_to_syslog(2), 2);
        assert_eq!(SyslogOutput::severity_to_syslog(3), 4);
        assert_eq!(SyslogOutput::severity_to_syslog(4), 6);
    }
}
