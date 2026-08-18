//! Idempotent schema helpers for engine `migrate()` functions (#193).
//!
//! SQLite has no `ALTER TABLE … ADD COLUMN IF NOT EXISTS`, so engines used to
//! run the `ALTER` blind and swallow *every* error (`let _ =` / `.ok()`), which
//! also hid real failures (locked DB, disk full, typo in the DDL). These
//! helpers probe `pragma_table_info` first and only then alter, so the only
//! errors left are real ones — and those propagate.
//!
//! Versioning of new schema lives in `aifw-core/migrations/` (sqlx tracks
//! applied versions in `_sqlx_migrations`); these helpers exist for the
//! historical inline `CREATE TABLE IF NOT EXISTS` engines that still add
//! columns to tables they created themselves.

use sqlx::SqlitePool;

/// All helpers return the raw `sqlx::Error` so they slot into engines that
/// use either `CoreError` or `aifw_common::AifwError` (both convert from it).
type Result<T> = std::result::Result<T, sqlx::Error>;

/// True when `table` has a column named `column`.
pub async fn column_exists(pool: &SqlitePool, table: &str, column: &str) -> Result<bool> {
    let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM pragma_table_info('{}') WHERE name = ?1",
        table.replace('\'', "''")
    )))
    .bind(column)
    .fetch_one(pool)
    .await?;
    Ok(n > 0)
}

/// `ALTER TABLE <table> ADD COLUMN <column> <definition>` unless the column
/// already exists. Returns `true` when the column was added. Errors other
/// than "already there" propagate. `table`/`column`/`definition` are
/// compile-time DDL fragments, never user input.
pub async fn add_column_if_missing(
    pool: &SqlitePool,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<bool> {
    if column_exists(pool, table, column).await? {
        return Ok(false);
    }
    match sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE {table} ADD COLUMN {column} {definition}"
    )))
    .execute(pool)
    .await
    {
        Ok(_) => Ok(true),
        // Two processes migrating the same DB can race between probe and
        // ALTER; the loser sees "duplicate column", which is fine.
        Err(e) if e.to_string().contains("duplicate column") => Ok(false),
        Err(e) => Err(e),
    }
}

/// `ALTER TABLE <table> DROP COLUMN <column>` if present (SQLite ≥ 3.35).
/// Returns `true` when dropped.
pub async fn drop_column_if_present(pool: &SqlitePool, table: &str, column: &str) -> Result<bool> {
    if !column_exists(pool, table, column).await? {
        return Ok(false);
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "ALTER TABLE {table} DROP COLUMN {column}"
    )))
    .execute(pool)
    .await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_and_drop_are_idempotent_and_report_changes() {
        let db = crate::db::Database::new_in_memory().await.unwrap();
        let pool = db.pool();
        sqlx::query("CREATE TABLE t (id TEXT PRIMARY KEY)")
            .execute(pool)
            .await
            .unwrap();
        assert!(!column_exists(pool, "t", "extra").await.unwrap());
        assert!(
            add_column_if_missing(pool, "t", "extra", "TEXT NOT NULL DEFAULT 'x'")
                .await
                .unwrap()
        );
        assert!(
            !add_column_if_missing(pool, "t", "extra", "TEXT")
                .await
                .unwrap(),
            "second call is a no-op"
        );
        assert!(column_exists(pool, "t", "extra").await.unwrap());
        // The column is really there and its default applies.
        sqlx::query("INSERT INTO t (id) VALUES ('a')")
            .execute(pool)
            .await
            .unwrap();
        let v: String = sqlx::query_scalar("SELECT extra FROM t WHERE id = 'a'")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(v, "x");
        assert!(drop_column_if_present(pool, "t", "extra").await.unwrap());
        assert!(!drop_column_if_present(pool, "t", "extra").await.unwrap());
        // Real errors are not swallowed: bad DDL surfaces.
        assert!(
            add_column_if_missing(pool, "t", "bad", "NOTATYPE (((")
                .await
                .is_err()
        );
        // Missing table: probe says absent, ALTER fails loudly.
        assert!(
            add_column_if_missing(pool, "nope", "c", "TEXT")
                .await
                .is_err()
        );
    }

    /// Discipline gate (#193): every inline schema change goes through the
    /// helpers above (or a versioned file in `aifw-core/migrations/`), so no
    /// engine can reintroduce a blind, error-swallowing `ALTER TABLE`.
    #[test]
    fn no_raw_alter_table_in_engine_sources() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            if let Ok(rd) = std::fs::read_dir(dir) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.is_dir() {
                        if p.file_name()
                            .is_some_and(|n| n == "target" || n == "node_modules")
                        {
                            continue;
                        }
                        walk(&p, out);
                    } else if p.extension().is_some_and(|x| x == "rs") {
                        out.push(p);
                    }
                }
            }
        }
        let mut files = Vec::new();
        for crate_dir in [
            "aifw-core",
            "aifw-api",
            "aifw-common",
            "aifw-daemon",
            "aifw-setup",
            "aifw-cli",
        ] {
            walk(&root.join(crate_dir).join("src"), &mut files);
        }
        let this = std::path::Path::new(file!()).file_name().unwrap();
        let mut hits = Vec::new();
        for f in files {
            if f.file_name() == Some(this) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            for (i, line) in text.lines().enumerate() {
                let t = line.trim_start();
                if t.starts_with("//") {
                    continue;
                }
                if t.contains("ALTER TABLE") && t.contains("ADD COLUMN") {
                    hits.push(format!(
                        "{}:{}: {t}",
                        f.strip_prefix(&root).unwrap().display(),
                        i + 1
                    ));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "raw ALTER TABLE … ADD COLUMN outside aifw_core::schema — use \
             schema::add_column_if_missing (or a versioned migration):\n{}",
            hits.join("\n")
        );
    }
}
