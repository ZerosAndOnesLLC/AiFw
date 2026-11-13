//! Generic CRUD over an API collection whose objects are edited as JSON/YAML
//! (`-f file`, or `-f -` for stdin). Used where flags per field would add
//! little: reverse-proxy collections, resolver hosts, ACME providers, …

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::cli::output::Col;
use crate::cli::{Ctx, Format};

/// A collection endpoint and how to show it.
pub struct Resource {
    /// List/create path; items live at `{path}/{id}`.
    pub path: String,
    /// Human name ("host override").
    pub what: &'static str,
    pub cols: Vec<Col>,
}

/// A collection command: a verb (default `list`), plus the legacy `--json`.
#[derive(Debug, Args)]
pub struct Coll {
    #[command(subcommand)]
    pub action: Option<Crud>,
    #[arg(long, hide = true)]
    pub json: bool,
}

/// The same verbs for every collection. Objects are JSON/YAML in the API's
/// shape (see `list -o json` for examples).
#[derive(Debug, Subcommand)]
pub enum Crud {
    /// List
    #[command(visible_alias = "ls")]
    List,
    /// Show one (by id or name)
    Show { id: String },
    /// Create from a JSON/YAML file (- for stdin)
    Add {
        #[arg(short = 'f', long = "file")]
        file: String,
    },
    /// Update from a JSON/YAML file, merged onto the current object
    Edit {
        id: String,
        #[arg(short = 'f', long = "file")]
        file: String,
    },
    /// Enable
    Enable { id: String },
    /// Disable
    Disable { id: String },
    /// Delete
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
    },
}

/// Fields the server owns; never sent back on update.
const READ_ONLY: &[&str] = &["id", "created_at", "updated_at"];

fn id_of(v: &Value) -> String {
    match &v["id"] {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Find an item by id or name.
pub async fn find(client: &aifw_client::Client, r: &Resource, key: &str) -> anyhow::Result<Value> {
    let all = client.get(&r.path).await?;
    crate::cli::output::rows(&all)
        .into_iter()
        .find(|x| id_of(x) == key || x["name"] == json!(key))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("{} {key}", r.what)).into())
}

/// The current object, minus server-owned fields, as an update body.
pub fn update_body(current: &Value) -> Value {
    let mut b = current.clone();
    if let Some(o) = b.as_object_mut() {
        for k in READ_ONLY {
            o.remove(*k);
        }
    }
    b
}

pub async fn coll(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    r: &Resource,
    c: Coll,
) -> anyhow::Result<()> {
    if c.json {
        ctx.force_format(Format::Json);
    }
    crud(ctx, client, r, c.action.unwrap_or(Crud::List)).await
}

pub async fn crud(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    r: &Resource,
    cmd: Crud,
) -> anyhow::Result<()> {
    match cmd {
        Crud::List => {
            let v = client.get(&r.path).await?;
            ctx.list(&v, &r.cols)
        }
        Crud::Show { id } => {
            let v = find(client, r, &id).await?;
            ctx.raw(&v)
        }
        Crud::Add { file } => {
            let body = crate::cli::body::read(&mut ctx.io, &file)?;
            let v = client.post(&r.path, &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            let created = crate::cli::output::item(&v);
            match created.get("id") {
                Some(_) => ctx
                    .io
                    .println(&format!("Created {} {}", r.what, id_of(created))),
                None => ctx.message(&v, &format!("Created {}", r.what))?,
            }
            Ok(())
        }
        Crud::Edit { id, file } => {
            let cur = find(client, r, &id).await?;
            let mut body = update_body(&cur);
            let patch = crate::cli::body::read(&mut ctx.io, &file)?;
            crate::cli::body::merge(&mut body, &patch);
            let v = client
                .put(&format!("{}/{}", r.path, id_of(&cur)), &body)
                .await?;
            ctx.message(&v, &format!("Updated {} {id}", r.what))
        }
        Crud::Enable { id } => set_enabled(ctx, client, r, &id, true).await,
        Crud::Disable { id } => set_enabled(ctx, client, r, &id, false).await,
        Crud::Remove { id, yes } => {
            let cur = find(client, r, &id).await?;
            let label = cur["name"]
                .as_str()
                .map_or_else(|| id.clone(), str::to_string);
            ctx.confirm(&format!("Delete {} {label}?", r.what), yes)?;
            let v = client
                .delete(&format!("{}/{}", r.path, id_of(&cur)))
                .await?;
            ctx.message(&v, &format!("Deleted {} {label}", r.what))
        }
    }
}

async fn set_enabled(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    r: &Resource,
    id: &str,
    on: bool,
) -> anyhow::Result<()> {
    let cur = find(client, r, id).await?;
    let mut body = update_body(&cur);
    body["enabled"] = json!(on);
    let v = client
        .put(&format!("{}/{}", r.path, id_of(&cur)), &body)
        .await?;
    ctx.message(
        &v,
        &format!(
            "{} {id} {}",
            r.what,
            if on { "enabled" } else { "disabled" }
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_body_drops_server_fields() {
        let b = update_body(
            &json!({"id": 3, "name": "x", "created_at": "t", "updated_at": "t", "enabled": true}),
        );
        assert_eq!(b, json!({"name": "x", "enabled": true}));
        assert_eq!(id_of(&json!({"id": 3})), "3");
        assert_eq!(id_of(&json!({"id": "abc"})), "abc");
    }
}
