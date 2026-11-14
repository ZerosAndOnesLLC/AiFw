//! Small argument parsers shared by commands.

use super::exit::CliError;

/// Parse a duration: `300`, `90s`, `5m`, `2h`, `1d` → seconds.
pub fn duration_secs(s: &str) -> Result<u64, CliError> {
    let s = s.trim();
    let (num, mult) = match s.char_indices().last() {
        Some((i, 's')) => (&s[..i], 1),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 'h')) => (&s[..i], 3600),
        Some((i, 'd')) => (&s[..i], 86_400),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n > 0)
        .ok_or_else(|| CliError::Usage(format!("invalid duration '{s}' (e.g. 300, 90s, 5m, 1h)")))
}

/// Normalize a user-typed API URL: default to https, drop trailing `/`.
pub fn api_url(s: &str) -> Result<String, CliError> {
    let s = s.trim();
    let with_scheme = if s.contains("://") {
        s.to_string()
    } else {
        format!("https://{s}")
    };
    let with_scheme = with_scheme.trim_end_matches('/').to_string();
    let u = url::Url::parse(&with_scheme)
        .map_err(|e| CliError::Usage(format!("invalid URL '{s}': {e}")))?;
    if !matches!(u.scheme(), "http" | "https") || u.host_str().is_none() {
        return Err(CliError::Usage(format!(
            "invalid URL '{s}': need http(s)://host[:port]"
        )));
    }
    Ok(with_scheme)
}

/// Format a SHA-256 hex fingerprint as colon-separated upper-case pairs.
pub fn fingerprint_display(fp: &str) -> String {
    fp.as_bytes()
        .chunks(2)
        .map(|c| String::from_utf8_lossy(c).to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":")
}

/// Accept `ab12…` or `AB:12:…`; must be 64 hex digits.
pub fn fingerprint(s: &str) -> Result<String, CliError> {
    let fp: String = s
        .chars()
        .filter(|c| *c != ':')
        .collect::<String>()
        .to_ascii_lowercase();
    if fp.len() == 64 && fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(fp)
    } else {
        Err(CliError::Usage(format!(
            "invalid fingerprint '{s}': expected 64 hex digits (SHA-256)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration_secs("300").unwrap(), 300);
        assert_eq!(duration_secs("90s").unwrap(), 90);
        assert_eq!(duration_secs("5m").unwrap(), 300);
        assert_eq!(duration_secs("2h").unwrap(), 7200);
        assert_eq!(duration_secs("1d").unwrap(), 86_400);
        for bad in ["", "0", "-1", "5x", "m", "1.5m"] {
            assert!(duration_secs(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn urls() {
        assert_eq!(api_url("10.0.0.1:8080").unwrap(), "https://10.0.0.1:8080");
        assert_eq!(api_url("http://fw/").unwrap(), "http://fw");
        assert!(api_url("ftp://x").is_err());
        assert!(api_url("https://").is_err());
    }

    #[test]
    fn fingerprints() {
        let fp = "ab".repeat(32);
        let shown = fingerprint_display(&fp);
        assert!(shown.starts_with("AB:AB:"));
        assert_eq!(fingerprint(&shown).unwrap(), fp);
        assert!(fingerprint("abcd").is_err());
        assert!(fingerprint(&"zz".repeat(32)).is_err());
    }
}
