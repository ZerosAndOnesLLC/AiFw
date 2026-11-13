//! Shared parsers and engine constructors used by several command groups.

use aifw_core::{Database, NatEngine, RuleEngine};
use std::path::Path;
use std::sync::Arc;

pub(super) async fn create_engine(db_path: &Path) -> anyhow::Result<RuleEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    Ok(RuleEngine::new(db.pool().clone(), pf))
}

pub(super) async fn create_nat_engine(db_path: &Path) -> anyhow::Result<NatEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    // "aifw-nat" — must match the API/daemon anchor; NAT loads replace every
    // rule class in their anchor since #531.
    Ok(NatEngine::new(db.pool().clone(), pf))
}
