//! The `aifw` command-line client.
//!
//! A library so the API's integration tests can drive real commands
//! against an in-process server (`aifw_cli::run` with buffered stdio).

pub mod app;
pub mod cli;
pub mod commands;

pub use app::run;
pub use cli::{Env, Io};

#[cfg(test)]
mod guard_tests {
    /// Only `commands/local/` (break-glass, root on the appliance) may open
    /// the database or drive pf directly; everything else goes through the
    /// API so validation, audit, versioning and HA sync apply.
    #[test]
    fn only_local_touches_the_database_or_pf() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let local = root.join("commands").join("local");
        let mut hits = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    if p != local {
                        stack.push(p);
                    }
                    continue;
                }
                if p.extension().is_none_or(|x| x != "rs") || p.ends_with("lib.rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&p).unwrap();
                for (i, line) in text.lines().enumerate() {
                    let t = line.trim_start();
                    if t.starts_with("//") {
                        continue;
                    }
                    for bad in [
                        "Database::new",
                        "create_backend",
                        "SqlitePool",
                        "aifw_core::updater",
                    ] {
                        if t.contains(bad) {
                            hits.push(format!(
                                "{}:{}: {t}",
                                p.strip_prefix(&root).unwrap().display(),
                                i + 1
                            ));
                        }
                    }
                }
            }
        }
        assert!(
            hits.is_empty(),
            "direct DB/pf access outside commands/local — go through the API:\n{}",
            hits.join("\n")
        );
    }
}
