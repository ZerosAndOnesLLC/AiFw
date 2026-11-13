//! `aifw users …` — local user accounts (via the API).

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, Format, col, prompt, wide};

#[derive(Debug, Subcommand)]
pub enum UsersCmd {
    /// List users
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Show a user (id or username)
    Show { user: String },
    /// Add a user
    Add {
        #[arg(long)]
        username: String,
        /// Password (prompted when omitted; prefer --password-stdin in scripts)
        #[arg(long)]
        password: Option<String>,
        /// Read the password from stdin
        #[arg(long, conflicts_with = "password")]
        password_stdin: bool,
        /// admin, operator, viewer, or a custom role name
        #[arg(long, default_value = "admin")]
        role: String,
    },
    /// Delete a user (id or username)
    #[command(visible_alias = "rm")]
    Remove {
        user: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Disable a user (blocks login and their API keys)
    Disable { user: String },
    /// Enable a user
    Enable { user: String },
    /// Change a user's role
    SetRole { user: String, role: String },
    /// Set a user's password
    Passwd {
        user: String,
        #[arg(long)]
        password_stdin: bool,
    },
}

const COLS: &[crate::cli::output::Col] = &[
    col("ID", "/id"),
    col("USERNAME", "/username"),
    col("ROLE", "/role"),
    col("2FA", "/totp_enabled"),
    col("ENABLED", "/enabled"),
    col("PROVIDER", "/auth_provider"),
    wide("CREATED", "/created_at"),
];

/// Resolve an id or username to the user object.
async fn find(client: &aifw_client::Client, user: &str) -> anyhow::Result<Value> {
    let all = client.get("/auth/users").await?;
    crate::cli::output::rows(&all)
        .into_iter()
        .find(|u| u["id"] == json!(user) || u["username"] == json!(user))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("user {user}")).into())
}

fn read_password(ctx: &mut Ctx, flag: Option<String>, stdin: bool) -> anyhow::Result<String> {
    if let Some(p) = flag {
        return Ok(p);
    }
    let no_input = ctx.g.no_input;
    if stdin {
        let p = prompt::read_line_raw(&mut ctx.io)?
            .trim_end_matches(['\r', '\n'])
            .to_string();
        if p.is_empty() {
            return Err(CliError::Usage("no password on stdin".into()).into());
        }
        return Ok(p);
    }
    let p = prompt::secret(&mut ctx.io, "Password: ", no_input, "password")?;
    let again = prompt::secret(&mut ctx.io, "Repeat password: ", no_input, "password")?;
    if p != again {
        return Err(CliError::Usage("passwords do not match".into()).into());
    }
    Ok(p)
}

pub async fn run(ctx: &mut Ctx, cmd: UsersCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        UsersCmd::List { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/auth/users").await?;
            ctx.list(&v, COLS)
        }
        UsersCmd::Show { user } => {
            let u = find(&client, &user).await?;
            ctx.detail(
                &u,
                &[
                    ("ID", "/id"),
                    ("Username", "/username"),
                    ("Role", "/role"),
                    ("Role ID", "/role_id"),
                    ("2FA", "/totp_enabled"),
                    ("Enabled", "/enabled"),
                    ("Provider", "/auth_provider"),
                    ("Created", "/created_at"),
                ],
            )
        }
        UsersCmd::Add {
            username,
            password,
            password_stdin,
            role,
        } => {
            let password = read_password(ctx, password, password_stdin)?;
            let v = client
                .post(
                    "/auth/users",
                    &json!({ "username": username, "password": password, "role": role }),
                )
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added user {username} ({})",
                crate::cli::output::item(&v)["id"].as_str().unwrap_or("?")
            ));
            Ok(())
        }
        UsersCmd::Remove { user, yes } => {
            let u = find(&client, &user).await?;
            let name = u["username"].as_str().unwrap_or(&user).to_string();
            ctx.confirm(&format!("Delete user {name} and their API keys?"), yes)?;
            let v = client
                .delete(&format!(
                    "/auth/users/{}",
                    u["id"].as_str().unwrap_or_default()
                ))
                .await?;
            ctx.message(&v, &format!("Removed user {name}"))
        }
        UsersCmd::Disable { user } => {
            update(ctx, &client, &user, json!({ "enabled": false }), "disabled").await
        }
        UsersCmd::Enable { user } => {
            update(ctx, &client, &user, json!({ "enabled": true }), "enabled").await
        }
        UsersCmd::SetRole { user, role } => {
            update(ctx, &client, &user, json!({ "role": role }), "role updated").await
        }
        UsersCmd::Passwd {
            user,
            password_stdin,
        } => {
            let password = read_password(ctx, None, password_stdin)?;
            update(
                ctx,
                &client,
                &user,
                json!({ "password": password }),
                "password changed",
            )
            .await
        }
    }
}

async fn update(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    user: &str,
    body: Value,
    what: &str,
) -> anyhow::Result<()> {
    let u = find(client, user).await?;
    let name = u["username"].as_str().unwrap_or(user).to_string();
    let v = client
        .put(
            &format!("/auth/users/{}", u["id"].as_str().unwrap_or_default()),
            &body,
        )
        .await?;
    if ctx.format().is_structured() {
        return ctx.raw(&v);
    }
    ctx.io.println(&format!("User {name}: {what}"));
    Ok(())
}
