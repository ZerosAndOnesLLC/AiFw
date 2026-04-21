//! Shared bounded log tail used by every "Logs" page in the UI.
//!
//! Earlier versions did `sudo cat <full file>` then filtered in Rust on
//! every poll. On a busy box `/var/log/messages` (the fallback for
//! several services) is multiple MB; the resulting 10–15 s wait before
//! the first line appeared was the worst UX in the whole product.
//!
//! What this module does:
//!  1. Probe each candidate path with `test -r` so we never spam stderr
//!     trying to read a file that doesn't exist on this appliance.
//!  2. `tail -n N` the first readable file (bounded read; on FreeBSD
//!     this seeks back from EOF in O(N) bytes).
//!  3. Optional `grep -i <needle>` BEFORE the bytes hit user space, so
//!     filter cost scales with matches not file size.
//!  4. Cap the response at the requested line count, newest-first.
//!
//! The full pipeline runs under `/bin/sh -c` so we can `|` between
//! tail/grep/tail without writing a JSON-encoded ProcessBuilder graph.
//! Inputs that flow into the shell (paths, needle) are all
//! caller-controlled in the API layer — paths are constants in the
//! handlers, needles are constrained to alphanumerics + `-_` here.

use tokio::process::Command;

/// Read the last `tail_lines` lines from the first existing path in
/// `paths`, optionally filter case-insensitively for `needle`, and
/// return up to `take` lines newest-first.
pub async fn tail_filtered(
    paths: &[&str],
    needle: Option<&str>,
    tail_lines: usize,
    take: usize,
) -> Vec<String> {
    for path in paths {
        // Existence + readability via sudo `test -r`. We never `tail` a
        // missing file; that just adds a sudo invocation per poll.
        let exists = Command::new("/usr/local/bin/sudo")
            .args(["/usr/bin/test", "-r", path])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if !exists {
            continue;
        }

        let pipeline = match needle {
            Some(n) => {
                let safe = sanitize_needle(n);
                if safe.is_empty() {
                    format!(
                        "/usr/local/bin/sudo /usr/bin/tail -n {tail_lines} '{path}' | /usr/bin/tail -n {take}"
                    )
                } else {
                    format!(
                        "/usr/local/bin/sudo /usr/bin/tail -n {tail_lines} '{path}' | /usr/bin/grep -iF -- '{safe}' | /usr/bin/tail -n {take}"
                    )
                }
            }
            None => format!(
                "/usr/local/bin/sudo /usr/bin/tail -n {tail_lines} '{path}' | /usr/bin/tail -n {take}"
            ),
        };

        let out = Command::new("/bin/sh")
            .args(["-c", &pipeline])
            .output()
            .await;
        if let Ok(out) = out
            && !out.stdout.is_empty()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<String> = text.lines().rev().map(String::from).collect();
            if !lines.is_empty() {
                return lines;
            }
        }
    }
    Vec::new()
}

/// Strip anything that isn't an obvious word character. Keeps grep happy
/// (no regex metacharacters even though we use `-F`) and prevents shell
/// quote escaping. Lossy on user-provided search terms with punctuation,
/// but the Logs UI is a free-text filter — this is the safe default.
fn sanitize_needle(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_' || *c == '.' || *c == ' ')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_drops_dangerous_chars() {
        assert_eq!(sanitize_needle("rdns'`;rm -rf"), "rdnsrm -rf");
        assert_eq!(sanitize_needle("ERROR.404"), "ERROR.404");
        assert_eq!(sanitize_needle("auth_failed"), "auth_failed");
    }
}
