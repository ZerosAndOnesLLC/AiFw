//! `aifw status` and `aifw reload` through the API.

use std::time::Duration;

use crate::cli::Ctx;

pub async fn status(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client.get("/status").await.map_err(|e| {
        let hint = matches!(e, aifw_client::ClientError::Unreachable { .. })
            .then_some(" (on the appliance, `aifw local status` works without the API)")
            .unwrap_or_default();
        anyhow::Error::new(e).context(format!("fetching status{hint}"))
    })?;
    ctx.detail(
        &v,
        &[
            ("pf running", "/pf_running"),
            ("pf states", "/pf_states"),
            ("pf rules", "/pf_rules"),
            ("AiFw rules", "/aifw_rules"),
            ("Active rules", "/aifw_active_rules"),
            ("NAT rules", "/nat_rules"),
            ("Packets in", "/packets_in"),
            ("Packets out", "/packets_out"),
            ("Bytes in", "/bytes_in"),
            ("Bytes out", "/bytes_out"),
        ],
    )
}

/// Load staged filter/NAT changes and re-apply queues — what `aifw reload`
/// has always meant.
pub async fn reload(ctx: &mut Ctx) -> anyhow::Result<()> {
    super::staging::apply(ctx).await?;
    let client = ctx.client()?;
    let timeout = ctx.slow_timeout(Duration::from_secs(120));
    client
        .request_with_timeout(reqwest::Method::POST, "/shaper/apply", None, timeout)
        .await?;
    if !ctx.format().is_structured() {
        ctx.io.println("Queues re-applied.");
    }
    Ok(())
}
