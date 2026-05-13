//! Versioned schema migrations via `sqlx::migrate!` (QUAL-C6).
//!
//! Background: the audit caught that aifw-core / aifw-api carried ~20
//! engine-local `migrate()` functions, each running its own
//! `CREATE TABLE IF NOT EXISTS` + ad-hoc `ALTER TABLE ADD COLUMN`
//! sequence. There was no schema-version tracking, no rollback story, no
//! ordering guarantee between engines. A renamed column required a hand
//! patch on every deployed appliance.
//!
//! This module wires `sqlx::migrate!()` to the workspace
//! `aifw-core/migrations/` directory. sqlx automatically creates a
//! `_sqlx_migrations` table and tracks which versions have been applied.
//! On a fresh DB, every numbered file runs in order; on an existing DB,
//! only unapplied versions run.
//!
//! New schema changes going forward MUST go in a numbered file in
//! `aifw-core/migrations/` (`NNNN_name.sql`). The historical engine-side
//! `CREATE TABLE IF NOT EXISTS` pattern is deprecated; engine migrate()
//! functions will be folded into versioned migrations as engines change.

use sqlx::SqlitePool;
use sqlx::migrate::Migrator;

/// Embedded migrator pointing at `aifw-core/migrations/`. The macro
/// resolves the path at compile time and embeds each file in the binary,
/// so no on-disk migrations directory is required at runtime.
pub static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

/// Run all pending versioned migrations. Idempotent: already-applied
/// versions are skipped. Errors propagate as `CoreError::Database`.
pub async fn run(pool: &SqlitePool) -> crate::Result<()> {
    MIGRATOR
        .run(pool)
        .await
        .map_err(|e| crate::CoreError::Database(format!("sqlx migrate: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn baseline_runs_on_fresh_db() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        run(&pool).await.unwrap();
        // _sqlx_migrations table should now exist with version 1 applied.
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM _sqlx_migrations")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert!(row.0 >= 1, "expected at least one migration recorded");
    }

    #[tokio::test]
    async fn baseline_is_idempotent() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        run(&pool).await.unwrap();
        // Second call must be a no-op.
        run(&pool).await.unwrap();
    }
}
