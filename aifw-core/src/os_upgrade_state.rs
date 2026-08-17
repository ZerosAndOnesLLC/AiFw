//! Persistent record of an in-flight FreeBSD release upgrade (#613).
//!
//! The API drives the upgrade and owns the writes; this module is the
//! read side, shared with the CLI so that every AiFw install path can
//! stand down while a release upgrade is running (#646) — the same way
//! patch-level `freebsd-update` calls already do (#633).

use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// `update_config` key under which the record is stored.
pub const OS_UPGRADE_KEY: &str = "os_upgrade_state";

/// State of an OS release upgrade, stored in `update_config` so it survives
/// the reboot in the middle of the flow.
///
/// Phases: `fetching` (freebsd-update -r X upgrade) → `installing`
/// (kernel install) → `reboot_required` → `finalizing` (post-reboot
/// userland install passes) → `done`, or `failed` with the reason in
/// `detail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsUpgradeState {
    /// Target release, e.g. `15.1`.
    pub target: String,
    /// Current phase (see the type docs for the sequence).
    pub phase: String,
    /// Human-readable progress or failure detail.
    pub detail: String,
    /// RFC 3339 timestamp when the upgrade was started.
    pub started_at: String,
    /// RFC 3339 timestamp of the last phase change.
    pub updated_at: String,
}

impl OsUpgradeState {
    /// True while this record owns freebsd-update's state directory —
    /// from fetch through the post-reboot finalize.
    pub fn is_in_flight(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "fetching" | "installing" | "reboot_required" | "finalizing"
        )
    }
}

/// Load the current record, if any. A missing table, missing row, or
/// unparseable value all read as "no upgrade recorded".
pub async fn load(pool: &SqlitePool) -> Option<OsUpgradeState> {
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM update_config WHERE key = ?1")
        .bind(OS_UPGRADE_KEY)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()?;
    serde_json::from_str(&row.0).ok()
}

/// True while a release upgrade is in flight (see
/// [`OsUpgradeState::is_in_flight`]). AiFw installs and patch-level
/// freebsd-update operations must not run in this window: an install's
/// service restart can interrupt the finalize passes (#646), and a routine
/// fetch destroys the staged release (#633).
pub async fn in_flight(pool: &SqlitePool) -> bool {
    load(pool).await.map(|s| s.is_in_flight()).unwrap_or(false)
}

/// Operator-facing explanation used by every AiFw install path that stands
/// down for an in-flight upgrade.
pub fn blocked_message(state: &OsUpgradeState) -> String {
    format!(
        "A FreeBSD {} upgrade is in progress ({}). AiFw updates are paused until it \
         completes — check System → Updates → Operating system, then install the AiFw update.",
        state.target, state.phase
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(phase: &str) -> OsUpgradeState {
        OsUpgradeState {
            target: "15.1".into(),
            phase: phase.into(),
            detail: String::new(),
            started_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn in_flight_phases() {
        for p in ["fetching", "installing", "reboot_required", "finalizing"] {
            assert!(state(p).is_in_flight(), "{p} should be in flight");
        }
        for p in ["done", "failed", "", "bogus"] {
            assert!(!state(p).is_in_flight(), "{p} should not be in flight");
        }
    }

    #[tokio::test]
    async fn load_tolerates_missing_table_and_row() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        assert!(load(&pool).await.is_none());
        assert!(!in_flight(&pool).await);

        sqlx::query("CREATE TABLE update_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        assert!(load(&pool).await.is_none());

        let json = serde_json::to_string(&state("finalizing")).unwrap();
        sqlx::query("INSERT INTO update_config (key, value) VALUES (?1, ?2)")
            .bind(OS_UPGRADE_KEY)
            .bind(json)
            .execute(&pool)
            .await
            .unwrap();
        assert!(in_flight(&pool).await);

        sqlx::query("UPDATE update_config SET value = 'not json' WHERE key = ?1")
            .bind(OS_UPGRADE_KEY)
            .execute(&pool)
            .await
            .unwrap();
        assert!(!in_flight(&pool).await);
    }
}
