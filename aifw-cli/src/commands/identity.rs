//! `aifw roles …`, `aifw totp …`, `aifw audit` via the API.

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::body::Fields;
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, prompt, wide};

#[derive(Debug, Subcommand)]
pub enum RolesCmd {
    #[command(visible_alias = "ls")]
    List,
    /// Show a role (id or name) and its permissions
    Show { role: String },
    /// Every permission a role can grant
    Permissions,
    /// Create a role
    Add {
        #[arg(long)]
        name: String,
        /// Comma-separated permissions, e.g. rules:read,nat:read
        #[arg(long)]
        permissions: String,
        #[arg(long)]
        description: Option<String>,
    },
    /// Change a custom role (built-ins: description only)
    Edit {
        role: String,
        #[arg(long)]
        name: Option<String>,
        /// Replace the permission set
        #[arg(long)]
        permissions: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    #[command(visible_alias = "rm")]
    Remove {
        role: String,
        #[arg(short, long)]
        yes: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum TotpCmd {
    /// Start enrolment: prints the secret, an otpauth:// URI and recovery codes
    Setup,
    /// Finish enrolment with a code from your authenticator
    Verify { code: String },
    /// Turn 2FA off (needs a current code)
    Disable { code: Option<String> },
}

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

async fn find_role(client: &aifw_client::Client, key: &str) -> anyhow::Result<Value> {
    let v = client.get("/auth/roles").await?;
    crate::cli::output::rows(&v)
        .into_iter()
        .find(|r| r["id"] == json!(key) || r["name"] == json!(key))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("role {key}")).into())
}

pub async fn roles(ctx: &mut Ctx, cmd: RolesCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        RolesCmd::List => {
            let v = client.get("/auth/roles").await?;
            ctx.list_mapped(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("BUILT-IN", "/builtin"),
                    col("PERMISSIONS", "/_n"),
                    wide("DESCRIPTION", "/description"),
                ],
                |r| {
                    let mut x = r.clone();
                    x["_n"] = json!(r["permissions"].as_array().map_or(0, Vec::len));
                    x
                },
            )
        }
        RolesCmd::Show { role } => {
            let r = find_role(&client, &role).await?;
            ctx.detail(
                &r,
                &[
                    ("ID", "/id"),
                    ("Name", "/name"),
                    ("Built-in", "/builtin"),
                    ("Description", "/description"),
                    ("Permissions", "/permissions"),
                ],
            )
        }
        RolesCmd::Permissions => {
            let v = client.get("/auth/permissions").await?;
            ctx.list(
                &v,
                &[
                    col("PERMISSION", "/key"),
                    col("CATEGORY", "/category"),
                    col("ACTION", "/action"),
                ],
            )
        }
        RolesCmd::Add {
            name,
            permissions,
            description,
        } => {
            let v = client
                .post("/auth/roles", &json!({ "name": name, "permissions": csv(&permissions), "description": description }))
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Created role {} with {} permission(s)",
                v["id"].as_str().unwrap_or("?"),
                v["permissions"].as_array().map_or(0, Vec::len)
            ));
            Ok(())
        }
        RolesCmd::Edit {
            role,
            name,
            permissions,
            description,
        } => {
            let r = find_role(&client, &role).await?;
            let body = Fields::new()
                .opt("name", name)
                .opt("permissions", permissions.as_deref().map(csv))
                .opt("description", description);
            if body.is_empty() {
                return Err(CliError::Usage("nothing to change".into()).into());
            }
            let v = client
                .put(
                    &format!("/auth/roles/{}", r["id"].as_str().unwrap_or_default()),
                    &body.into_value(),
                )
                .await?;
            ctx.message(&v, "Role updated")
        }
        RolesCmd::Remove { role, yes } => {
            let r = find_role(&client, &role).await?;
            ctx.confirm(
                &format!("Delete role {}?", r["name"].as_str().unwrap_or(&role)),
                yes,
            )?;
            let v = client
                .delete(&format!(
                    "/auth/roles/{}",
                    r["id"].as_str().unwrap_or_default()
                ))
                .await?;
            ctx.message(&v, "Role deleted")
        }
    }
}

pub async fn totp(ctx: &mut Ctx, cmd: TotpCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        TotpCmd::Setup => {
            let v = client.post_empty("/auth/totp/setup").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let codes: Vec<String> = v["recovery_codes"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect();
            ctx.io.println(&format!(
                "Secret:   {}\nURI:      {}\nRecovery codes (store them safely):\n  {}\nFinish with: aifw totp verify <code>",
                v["secret"].as_str().unwrap_or("?"),
                v["provisioning_uri"].as_str().unwrap_or("?"),
                codes.join("\n  ")
            ));
            Ok(())
        }
        TotpCmd::Verify { code } => {
            let v = client
                .post("/auth/totp/verify", &json!({ "code": code }))
                .await?;
            ctx.message(&v, "TOTP enabled")
        }
        TotpCmd::Disable { code } => {
            let code = match code {
                Some(c) => c,
                None => {
                    let no_input = ctx.g.no_input;
                    prompt::line(&mut ctx.io, "Current TOTP code: ", no_input, "TOTP code")?
                }
            };
            let v = client
                .post("/auth/totp/disable", &json!({ "code": code }))
                .await?;
            ctx.message(&v, "TOTP disabled")
        }
    }
}

/// `aifw audit` — user/account audit trail.
pub async fn audit(ctx: &mut Ctx) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let v = client.get("/auth/audit").await?;
    ctx.list(
        &v,
        &[
            col("TIME", "/created_at"),
            col("ACTION", "/action"),
            col("ACTOR", "/actor_id"),
            col("USER", "/user_id"),
            col("DETAILS", "/details"),
            wide("IP", "/ip_addr"),
        ],
    )
}
