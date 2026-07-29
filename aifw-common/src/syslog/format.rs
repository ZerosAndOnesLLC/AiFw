//! RFC 3164 (BSD) and RFC 5424 syslog message rendering.

use chrono::{DateTime, Utc};

use super::config::{SyslogConfig, SyslogFormat};

/// Maximum rendered message length in bytes; longer payloads are truncated at
/// a char boundary. Matches common syslog receiver limits.
const MAX_MSG_BYTES: usize = 2048;

/// One message to forward, before syslog framing is applied.
#[derive(Debug, Clone)]
pub struct SyslogRecord {
    /// Syslog severity 0-7 (0=emerg … 7=debug)
    pub severity: u8,
    /// APP-NAME / TAG field (e.g. `aifw-pf`, `aifw-api`)
    pub app_name: &'static str,
    /// Event time
    pub timestamp: DateTime<Utc>,
    /// Free-form message body
    pub msg: String,
}

/// PRI value: `facility * 8 + severity` (RFC 5424 §6.2.1).
pub fn priority(facility: u8, severity: u8) -> u8 {
    facility.min(23) * 8 + severity.min(7)
}

/// Render a record in the configured format. `hostname` is the already
/// resolved HOSTNAME field value (override applied by the caller).
pub fn format_message(cfg: &SyslogConfig, hostname: &str, rec: &SyslogRecord) -> String {
    let pri = priority(cfg.facility, rec.severity);
    let msg = truncate_msg(&rec.msg);
    let pid = std::process::id();
    match cfg.format {
        SyslogFormat::Rfc3164 => {
            // <PRI>MMM dd HH:MM:SS HOSTNAME TAG[pid]: MSG  (day is space-padded)
            let ts = rec.timestamp.format("%b %e %H:%M:%S");
            format!("<{pri}>{ts} {hostname} {}[{pid}]: {msg}", rec.app_name)
        }
        SyslogFormat::Rfc5424 => {
            // <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
            let ts = rec.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ");
            format!("<{pri}>1 {ts} {hostname} {} {pid} - - {msg}", rec.app_name)
        }
    }
}

/// Truncate at [`MAX_MSG_BYTES`] without splitting a UTF-8 char.
fn truncate_msg(msg: &str) -> &str {
    if msg.len() <= MAX_MSG_BYTES {
        return msg;
    }
    let mut end = MAX_MSG_BYTES;
    while !msg.is_char_boundary(end) {
        end -= 1;
    }
    &msg[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn rec(msg: &str) -> SyslogRecord {
        SyslogRecord {
            severity: 6,
            app_name: "aifw-test",
            timestamp: Utc.with_ymd_and_hms(2026, 7, 5, 8, 9, 10).unwrap(),
            msg: msg.into(),
        }
    }

    #[test]
    fn pri_calculation() {
        assert_eq!(priority(16, 6), 134); // local0.info
        assert_eq!(priority(4, 1), 33); // auth.alert
        assert_eq!(priority(0, 0), 0);
        assert_eq!(priority(99, 99), 23 * 8 + 7); // clamped
    }

    #[test]
    fn rfc3164_shape() {
        let cfg = SyslogConfig::default(); // rfc3164, facility 16
        let out = format_message(&cfg, "fw", &rec("hello world"));
        let pid = std::process::id();
        // Day 5 must be space-padded per RFC 3164
        assert_eq!(
            out,
            format!("<134>Jul  5 08:09:10 fw aifw-test[{pid}]: hello world")
        );
    }

    #[test]
    fn rfc5424_shape() {
        let cfg = SyslogConfig {
            format: SyslogFormat::Rfc5424,
            facility: 4,
            ..Default::default()
        };
        let out = format_message(&cfg, "fw1", &rec("hi"));
        let pid = std::process::id();
        assert_eq!(
            out,
            format!("<38>1 2026-07-05T08:09:10.000000Z fw1 aifw-test {pid} - - hi")
        );
    }

    #[test]
    fn truncation_at_char_boundary() {
        // 2047 ASCII bytes + one 3-byte char straddling the 2048 limit
        let msg = "a".repeat(2047) + "€€";
        let out = format_message(&SyslogConfig::default(), "h", &rec(&msg));
        assert!(out.len() < msg.len() + 64);
        assert!(out.ends_with('a')); // the € straddling the cut is dropped whole
        let long = "b".repeat(4096);
        let out2 = format_message(&SyslogConfig::default(), "h", &rec(&long));
        assert!(out2.contains(&"b".repeat(2048)));
        assert!(!out2.contains(&"b".repeat(2049)));
    }
}
