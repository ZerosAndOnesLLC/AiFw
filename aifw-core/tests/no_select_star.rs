//! Regression guard for #348 (PERF-H4).
//!
//! `SELECT *` in sqlx queries is banned across `aifw-core/src/`. It has
//! triggered a sqlx-sqlite column-count panic on shutdown (#273, the reason
//! `RULE_COLUMNS` exists in `db.rs`), and it silently breaks `FromRow`
//! consumers when an `ALTER TABLE ... ADD COLUMN` migration lands. Explicit
//! column lists also let the SQLite optimizer skip unused TEXT columns.
//!
//! Every table select must name its columns explicitly (mirror the
//! `*_COLUMNS` consts). If this test fails, replace the offending
//! `SELECT *` with `SELECT {TABLE_COLUMNS} FROM ...`.

use std::path::Path;

fn scan(dir: &Path, offenders: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan(&path, offenders);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for (lineno, line) in contents.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            // Only flag actual query text, not prose in comments/docs.
            let is_comment = line.trim_start().starts_with("//");
            if !is_comment && (lower.contains("select * from") || lower.contains("select *\n")) {
                offenders.push(format!("{}:{}", path.display(), lineno + 1));
            }
        }
    }
}

#[test]
fn no_select_star_in_source() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "SELECT * is banned in aifw-core/src/ (#348); use explicit column lists. Offenders:\n{}",
        offenders.join("\n")
    );
}
