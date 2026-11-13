//! `aifw interfaces` — network interfaces (via the API).

use crate::cli::{Ctx, col, wide};

pub async fn run(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client.get("/interfaces").await?;
    ctx.list(
        &v,
        &[
            col("INTERFACE", "/name"),
            col("IPV4", "/ipv4"),
            col("MAC", "/mac"),
            col("STATUS", "/status"),
            col("ROLE", "/role"),
            wide("IPV6", "/ipv6"),
        ],
    )
}
