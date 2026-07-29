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

/// Neutralize control characters so a message body can never break syslog
/// framing (CWE-117 log forging): an embedded newline would otherwise split
/// into extra receiver records with attacker-chosen PRI/timestamp/hostname
/// under RFC 6587 LF framing. `\n`/`\r` become visible escapes (multi-line
/// stderr stays readable), every other C0 control char and DEL becomes a
/// space. Returns a borrowed str when nothing needed changing (hot path).
fn sanitize_msg(msg: &str) -> std::borrow::Cow<'_, str> {
    if !msg
        .bytes()
        .any(|b| b.is_ascii_control() && b != b'\t' || b == 0x7f)
    {
        return std::borrow::Cow::Borrowed(msg);
    }
    let mut out = String::with_capacity(msg.len() + 8);
    for c in msg.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push(c),
            c if c.is_ascii_control() || c == '\u{7f}' => out.push(' '),
            c => out.push(c),
        }
    }
    std::borrow::Cow::Owned(out)
}

/// Sanitize a HOSTNAME field value: syslog headers are space-delimited, so
/// whitespace or control chars here would corrupt every message's framing.
fn sanitize_hostname(hostname: &str) -> std::borrow::Cow<'_, str> {
    if !hostname
        .chars()
        .any(|c| c.is_whitespace() || c.is_ascii_control())
    {
        return std::borrow::Cow::Borrowed(hostname);
    }
    std::borrow::Cow::Owned(
        hostname
            .chars()
            .map(|c| {
                if c.is_whitespace() || c.is_ascii_control() {
                    '-'
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// Render a record in the configured format. `hostname` is the already
/// resolved HOSTNAME field value (override applied by the caller).
pub fn format_message(cfg: &SyslogConfig, hostname: &str, rec: &SyslogRecord) -> String {
    let pri = priority(cfg.facility, rec.severity);
    let sanitized = sanitize_msg(&rec.msg);
    let msg = truncate_msg(&sanitized);
    let hostname = sanitize_hostname(hostname);
    let pid = std::process::id();
    match cfg.format {
        SyslogFormat::Rfc3164 => {
            // <PRI>MMM dd HH:MM:SS HOSTNAME TAG[pid]: MSG  (day is
            // space-padded). RFC 3164 timestamps carry no zone and are
            // local time by convention — receivers on non-UTC boxes would
            // otherwise record events offset by the TZ delta.
            let ts = rec
                .timestamp
                .with_timezone(&chrono::Local)
                .format("%b %e %H:%M:%S");
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
        // RFC 3164 timestamps are local time; recompute the expectation the
        // same way so the test passes in any TZ. Day is space-padded.
        let ts = rec("x")
            .timestamp
            .with_timezone(&chrono::Local)
            .format("%b %e %H:%M:%S");
        assert_eq!(out, format!("<134>{ts} fw aifw-test[{pid}]: hello world"));
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
    fn newlines_cannot_forge_records() {
        let cfg = SyslogConfig::default();
        let forged = "legit\n<0>Jan  1 00:00:00 evil sshd[1]: fake root login\r\nmore";
        let out = format_message(&cfg, "fw", &rec(forged));
        assert!(!out.contains('\n'), "no raw LF may survive: {out:?}");
        assert!(!out.contains('\r'), "no raw CR may survive: {out:?}");
        assert!(out.contains("legit\\n<0>"), "escaped form kept: {out}");
        // Other control chars become spaces; tab survives.
        let out2 = format_message(&cfg, "fw", &rec("a\x1b[31mred\x07b\tc"));
        assert!(!out2.bytes().any(|b| b.is_ascii_control() && b != b'\t'));
        assert!(out2.contains("a [31mred b\tc"), "got: {out2}");
    }

    #[test]
    fn hostname_field_is_sanitized() {
        let cfg = SyslogConfig::default();
        let out = format_message(&cfg, "bad host\nname", &rec("m"));
        assert!(!out.contains('\n'));
        assert!(out.contains("bad-host-name"), "got: {out}");
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
