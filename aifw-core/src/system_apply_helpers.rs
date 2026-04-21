//! Pure helpers for system_apply — string-in/string-out so they
//! unit-test on any host OS.

/// Replace (or insert) a block of content between
/// `# BEGIN <marker>` and `# END <marker>` lines.
///
/// Markers are only recognised when they appear at the start of a line
/// (byte offset 0, or immediately after `\n`). Trailing whitespace on
/// the marker line is tolerated. Marker text that appears mid-line (e.g.
/// inside a comment or string literal) is ignored.
///
/// If a well-formed BEGIN/END pair exists, the block between them is
/// replaced. Otherwise a new block is appended at the end. In the
/// pathological case where END appears before BEGIN (corrupted file),
/// no valid pair is found and the new block is appended.
/// `new_block` should end with a trailing newline if it contains lines.
pub fn replace_managed_block(content: &str, marker: &str, new_block: &str) -> String {
    let begin_line = format!("# BEGIN {}", marker);
    let end_line = format!("# END {}", marker);

    // Collect lines; keep track of whether content had a trailing newline.
    // `str::lines()` strips the final newline, so we detect it separately.
    let lines: Vec<&str> = content.lines().collect();

    // Find the first line that is exactly the begin marker (trimming only
    // trailing whitespace so leading spaces would disqualify it).
    let begin_idx = lines.iter().position(|l| l.trim_end() == begin_line);

    // Find the first end marker that comes *after* the begin marker.
    let end_idx = begin_idx.and_then(|b| {
        lines[b + 1..]
            .iter()
            .position(|l| l.trim_end() == end_line)
            .map(|rel| b + 1 + rel)
    });

    match (begin_idx, end_idx) {
        (Some(b), Some(e)) => {
            // Rebuild: everything before BEGIN (exclusive), the managed block,
            // then everything after END (exclusive).
            let mut out = String::with_capacity(content.len() + new_block.len());
            for line in &lines[..b] {
                out.push_str(line);
                out.push('\n');
            }
            out.push_str(&begin_line);
            out.push('\n');
            out.push_str(new_block);
            if !new_block.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&end_line);
            out.push('\n');
            for line in &lines[e + 1..] {
                out.push_str(line);
                out.push('\n');
            }
            out
        }
        _ => {
            // No valid pair — append a new managed block.
            let mut out = String::with_capacity(
                content.len() + new_block.len() + begin_line.len() + end_line.len() + 8,
            );
            out.push_str(content);
            if !content.is_empty() && !content.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&begin_line);
            out.push('\n');
            out.push_str(new_block);
            if !new_block.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&end_line);
            out.push('\n');
            out
        }
    }
}

pub fn validate_hostname(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Err("hostname must not be empty".into());
    }
    if s.len() > 63 {
        return Err("hostname must be ≤ 63 characters (RFC 1123)".into());
    }
    let bytes = s.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() {
        return Err("hostname must start with a letter or digit".into());
    }
    for &b in bytes {
        if !(b.is_ascii_alphanumeric() || b == b'-') {
            return Err(format!(
                "hostname contains invalid character: {:?}",
                b as char
            ));
        }
    }
    Ok(())
}

pub fn validate_domain(s: &str) -> Result<(), String> {
    if s.is_empty() {
        return Ok(());
    }
    if s.starts_with('.') || s.ends_with('.') {
        return Err("domain must not start or end with a dot".into());
    }
    for b in s.bytes() {
        if !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
            return Err(format!(
                "domain contains invalid character: {:?}",
                b as char
            ));
        }
    }
    Ok(())
}

pub fn validate_ssh_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("ssh port must be 1–65535".into());
    }
    Ok(())
}

pub fn validate_baud(baud: u32) -> Result<(), String> {
    match baud {
        9600 | 19200 | 38400 | 57600 | 115200 => Ok(()),
        _ => Err("baud must be one of 9600, 19200, 38400, 57600, 115200".into()),
    }
}
