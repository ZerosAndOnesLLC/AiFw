//! `aifw api-keys …` — your API keys (for scripts and other machines).

use clap::Subcommand;
use serde_json::json;

use crate::cli::body::Fields;
use crate::cli::{Ctx, col, wide};

#[derive(Debug, Subcommand)]
pub enum ApiKeysCmd {
    /// List your keys (--all: everyone's, needs users:read)
    #[command(visible_alias = "ls")]
    List {
        #[arg(long)]
        all: bool,
    },
    /// Create a key; the secret is printed once
    Create {
        #[arg(long)]
        name: String,
        /// Narrow the key to a role (id), e.g. builtin-viewer
        #[arg(long)]
        role: Option<String>,
        /// Lifetime in days (default: never expires)
        #[arg(long)]
        expires_days: Option<u32>,
        /// Mint for another user (id; needs users:write)
        #[arg(long)]
        user: Option<String>,
    },
    /// Revoke a key (id)
    #[command(visible_alias = "rm")]
    Revoke {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn run(ctx: &mut Ctx, cmd: ApiKeysCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        ApiKeysCmd::List { all } => {
            let v = client
                .get(if all {
                    "/auth/api-keys?all=true"
                } else {
                    "/auth/api-keys"
                })
                .await?;
            ctx.list_mapped(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("PREFIX", "/prefix"),
                    col("USER", "/username"),
                    col("ROLE", "/_role"),
                    col("EXPIRES", "/_expires"),
                    col("LAST USED", "/last_used_at"),
                    wide("CREATED", "/created_at"),
                ],
                |k| {
                    let mut r = k.clone();
                    r["_role"] = json!(k["role_name"].as_str().unwrap_or("(account)"));
                    r["_expires"] = json!(if k["expired"] == json!(true) {
                        "EXPIRED".to_string()
                    } else {
                        k["expires_at"].as_str().unwrap_or("never").to_string()
                    });
                    r
                },
            )
        }
        ApiKeysCmd::Create {
            name,
            role,
            expires_days,
            user,
        } => {
            let body = Fields::new()
                .set("name", name)
                .opt("role_id", role)
                .opt("expires_in_days", expires_days)
                .opt("user_id", user)
                .into_value();
            let v = client.post("/auth/api-keys", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            // The secret goes to stdout alone so `KEY=$(aifw api-keys create …)` works.
            ctx.io.println(v["key"].as_str().unwrap_or_default());
            ctx.io.eprintln(&format!(
                "Created key {} ({}…). Store it now — it won't be shown again.",
                v["name"].as_str().unwrap_or("?"),
                v["prefix"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        ApiKeysCmd::Revoke { id, yes } => {
            ctx.confirm(
                &format!("Revoke API key {id}? Anything using it stops working."),
                yes,
            )?;
            let v = client.delete(&format!("/auth/api-keys/{id}")).await?;
            ctx.message(&v, &format!("Revoked {id}"))
        }
    }
}
