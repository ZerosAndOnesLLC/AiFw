//! Shared bounded log tail used by every "Logs" page in the UI.
//!
//! Earlier versions did `sudo cat <full file>` then filtered in Rust on
//! every poll. On a busy box `/var/log/messages` (the fallback for
//! several services) is multiple MB; the resulting 10–15 s wait before
//! the first line appeared was the worst UX in the whole product. The
//! next iteration shelled out to `/bin/sh -c "tail | grep | tail"` —
//! bounded, but three forks per poll on pages that refresh every 5–10 s
//! (PERF-L8 #400).
//!
//! What this module does now, fully in-process:
//!  1. Probe each candidate path with `fs::metadata` so we skip files
//!     that don't exist on this appliance.
//!  2. Read the first readable file *backwards* from EOF in 64 KiB
//!     chunks on the blocking pool — cost scales with the lines
//!     actually needed, never with file size.
//!  3. Examine at most `tail_lines` lines (the old `tail -n N` bound),
//!     applying the optional case-insensitive substring filter as lines
//!     are discovered, and stop as soon as `take` matches are found.
//!  4. Return the matches newest-first.
//!
//! No sudo and no shell: each service's rc.d script is responsible for
//! making its log group-readable by `aifw` (see rdns's rc.d script for
//! the pattern — 0640 root:aifw). System logs like /var/log/messages
//! are world-readable. With no shell in the path, the needle no longer
//! needs sanitizing — it's matched as a literal substring.

use std::io::{Read, Seek, SeekFrom};

/// Chunk size for the backwards scan. Large enough that a typical logs
/// page (a few hundred ~200-byte lines) is served in one read.
const CHUNK: usize = 64 * 1024;

/// Read up to the last `tail_lines` lines from the first existing path
/// in `paths`, optionally filter case-insensitively for `needle`, and
/// return up to `take` lines newest-first.
pub async fn tail_filtered(
    paths: &[&str],
    needle: Option<&str>,
    tail_lines: usize,
    take: usize,
) -> Vec<String> {
    // Case-insensitive fixed-string match, same as the old `grep -iF`.
    let needle_lc = needle
        .map(str::to_lowercase)
        .filter(|n| !n.trim().is_empty());

    for path in paths {
        if tokio::fs::metadata(path).await.is_err() {
            continue;
        }
        let path = path.to_string();
        let needle_lc = needle_lc.clone();
        // The backwards scan is plain seek+read std I/O — run it on the
        // blocking pool so a slow disk never stalls a runtime worker.
        let lines = tokio::task::spawn_blocking(move || {
            reverse_tail(&path, needle_lc.as_deref(), tail_lines, take).unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        if !lines.is_empty() {
            return lines;
        }
    }
    Vec::new()
}

/// Scan `path` backwards from EOF, newest line first. Examines at most
/// `tail_lines` lines and returns the first `take` that contain
/// `needle_lc` (case-insensitively; `None` matches everything).
fn reverse_tail(
    path: &str,
    needle_lc: Option<&str>,
    tail_lines: usize,
    take: usize,
) -> std::io::Result<Vec<String>> {
    let mut file = std::fs::File::open(path)?;
    let mut pos = file.seek(SeekFrom::End(0))?;

    let mut out: Vec<String> = Vec::new();
    let mut examined = 0usize;
    // Bytes of the (not yet complete) line spanning a chunk boundary —
    // the head of the chunk we just processed, waiting for the rest.
    let mut carry: Vec<u8> = Vec::new();
    // The bytes after the file's final newline form the last line.
    let mut at_eof = true;

    let push_line = |raw: &[u8], out: &mut Vec<String>, examined: &mut usize| -> bool {
        *examined += 1;
        let line = String::from_utf8_lossy(raw);
        let line = line.strip_suffix('\r').unwrap_or(&line);
        let matches = match needle_lc {
            Some(n) => line.to_lowercase().contains(n),
            None => true,
        };
        if matches {
            out.push(line.to_string());
        }
        out.len() >= take || *examined >= tail_lines
    };

    while pos > 0 {
        let read_size = CHUNK.min(pos as usize);
        pos -= read_size as u64;
        file.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; read_size];
        file.read_exact(&mut buf)?;
        buf.extend_from_slice(&carry);

        // Walk the chunk backwards, emitting each complete line. The
        // bytes before the first newline belong to a line that starts in
        // an earlier chunk — they become the next iteration's carry.
        let mut end = buf.len();
        let mut done = false;
        while let Some(nl) = buf[..end].iter().rposition(|&b| b == b'\n') {
            let raw = &buf[nl + 1..end];
            // Skip the empty pseudo-line after the file's final newline.
            if !(at_eof && raw.is_empty()) && push_line(raw, &mut out, &mut examined) {
                done = true;
            }
            at_eof = false;
            end = nl;
            if done {
                break;
            }
        }
        if done {
            return Ok(out);
        }
        carry = buf[..end].to_vec();
    }

    // Whatever is left is the first line of the file.
    if !carry.is_empty() {
        push_line(&carry, &mut out, &mut examined);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(name: &str, contents: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join("aifw-log-tail-tests");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(name);
        std::fs::write(&path, contents).unwrap();
        path
    }

    #[tokio::test]
    async fn tails_newest_first() {
        let path = write_temp("basic.log", "one\ntwo\nthree\n");
        let lines = tail_filtered(&[path.to_str().unwrap()], None, 100, 100).await;
        assert_eq!(lines, vec!["three", "two", "one"]);
    }

    #[tokio::test]
    async fn respects_take_and_tail_bounds() {
        let path = write_temp("bounds.log", "a\nb\nc\nd\ne\n");
        let lines = tail_filtered(&[path.to_str().unwrap()], None, 100, 2).await;
        assert_eq!(lines, vec!["e", "d"]);
        // tail_lines bounds how far back the scan looks at all.
        let lines = tail_filtered(&[path.to_str().unwrap()], Some("a"), 2, 10).await;
        assert!(lines.is_empty(), "'a' is outside the last 2 lines");
    }

    #[tokio::test]
    async fn filters_case_insensitively() {
        let path = write_temp(
            "filter.log",
            "ok line\nERROR: bad\nok again\nerror: worse\n",
        );
        let lines = tail_filtered(&[path.to_str().unwrap()], Some("Error"), 100, 100).await;
        assert_eq!(lines, vec!["error: worse", "ERROR: bad"]);
    }

    #[tokio::test]
    async fn handles_missing_trailing_newline_and_crlf() {
        let path = write_temp("edges.log", "first\r\nsecond\r\nlast-no-newline");
        let lines = tail_filtered(&[path.to_str().unwrap()], None, 100, 100).await;
        assert_eq!(lines, vec!["last-no-newline", "second", "first"]);
    }

    #[tokio::test]
    async fn spans_chunk_boundaries() {
        // Lines large enough that the backwards scan must stitch a line
        // across the 64 KiB chunk boundary.
        let big_a = format!("A{}", "x".repeat(CHUNK));
        let big_b = format!("B{}", "y".repeat(CHUNK / 2));
        let path = write_temp("chunks.log", &format!("{big_a}\n{big_b}\nend\n"));
        let lines = tail_filtered(&[path.to_str().unwrap()], None, 100, 100).await;
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "end");
        assert_eq!(lines[1], big_b);
        assert_eq!(lines[2], big_a);
    }

    #[tokio::test]
    async fn skips_missing_paths() {
        let path = write_temp("fallback.log", "found\n");
        let lines = tail_filtered(
            &["/nonexistent/never.log", path.to_str().unwrap()],
            None,
            100,
            100,
        )
        .await;
        assert_eq!(lines, vec!["found"]);
    }
}
