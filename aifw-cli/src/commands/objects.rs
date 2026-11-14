//! `aifw aliases …`, `aifw schedules …`, `aifw vlans …` via the API.
//! Their PUTs replace the whole object, so edits send the current object
//! merged with the flags. Alias and VLAN changes are staged (`aifw apply`).

use clap::Subcommand;
use serde_json::{Value, json};

use crate::cli::body::{self, Fields};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col, wide};

fn csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(str::to_string)
        .collect()
}

async fn find(
    client: &aifw_client::Client,
    path: &str,
    key: &str,
    what: &str,
) -> anyhow::Result<Value> {
    let all = client.get(path).await?;
    crate::cli::output::rows(&all)
        .into_iter()
        .find(|x| id_str(x) == key || x["name"] == json!(key))
        .cloned()
        .ok_or_else(|| aifw_client::ClientError::NotFound(format!("{what} {key}")).into())
}

fn id_str(v: &Value) -> String {
    v["id"]
        .as_str()
        .map_or_else(|| v["id"].to_string(), str::to_string)
}

// ---------------------------------------------------------------- aliases

#[derive(Debug, Subcommand)]
pub enum AliasCmd {
    #[command(visible_alias = "ls")]
    List,
    /// Show an alias (id or name)
    Show { alias: String },
    /// Add an alias (use it in rules as <name>)
    Add {
        #[arg(long)]
        name: String,
        /// host, network, port, url_table
        #[arg(long = "type", value_name = "TYPE")]
        alias_type: String,
        /// Comma-separated entries (addresses, CIDRs, ports or URLs)
        #[arg(long)]
        entries: String,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        disabled: bool,
        #[arg(long)]
        apply: bool,
    },
    /// Change an alias
    Edit {
        alias: String,
        #[arg(long)]
        name: Option<String>,
        /// Replace all entries
        #[arg(long)]
        entries: Option<String>,
        /// Add entries
        #[arg(long = "add", value_name = "ENTRY")]
        add: Vec<String>,
        /// Remove entries
        #[arg(long = "del", value_name = "ENTRY")]
        del: Vec<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        apply: bool,
    },
    #[command(visible_alias = "rm")]
    Remove {
        alias: String,
        #[arg(short, long)]
        yes: bool,
        #[arg(long)]
        apply: bool,
    },
}

fn alias_request(a: &Value) -> Value {
    json!({
        "name": a["name"], "alias_type": a["alias_type"], "entries": a["entries"],
        "description": a["description"], "enabled": a["enabled"],
    })
}

pub async fn aliases(ctx: &mut Ctx, cmd: AliasCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        AliasCmd::List => {
            let v = client.get("/aliases").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("TYPE", "/alias_type"),
                    col("ENTRIES", "/entries"),
                    col("ENABLED", "/enabled"),
                    wide("DESCRIPTION", "/description"),
                ],
            )
        }
        AliasCmd::Show { alias } => {
            let a = find(&client, "/aliases", &alias, "alias").await?;
            ctx.detail(
                &a,
                &[
                    ("ID", "/id"),
                    ("Name", "/name"),
                    ("Type", "/alias_type"),
                    ("Entries", "/entries"),
                    ("Enabled", "/enabled"),
                    ("Description", "/description"),
                ],
            )
        }
        AliasCmd::Add {
            name,
            alias_type,
            entries,
            description,
            disabled,
            apply,
        } => {
            let body = Fields::new()
                .set("name", name)
                .set("alias_type", alias_type)
                .set("entries", csv(&entries))
                .opt("description", description)
                .set("enabled", !disabled)
                .into_value();
            let v = client.post("/aliases", &body).await?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                ctx.io.println(&format!(
                    "Added alias {}",
                    id_str(crate::cli::output::item(&v))
                ));
            }
            super::rules::after_write(ctx, apply).await
        }
        AliasCmd::Edit {
            alias,
            name,
            entries,
            add,
            del,
            description,
            enabled,
            apply,
        } => {
            let cur = find(&client, "/aliases", &alias, "alias").await?;
            let mut body = alias_request(&cur);
            let mut list: Vec<String> = match &entries {
                Some(e) => csv(e),
                None => body["entries"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect(),
            };
            for a in &add {
                if !list.contains(a) {
                    list.push(a.clone());
                }
            }
            list.retain(|x| !del.contains(x));
            let flags = Fields::new()
                .opt("name", name)
                .opt("description", description)
                .opt("enabled", enabled);
            if flags.is_empty() && entries.is_none() && add.is_empty() && del.is_empty() {
                return Err(CliError::Usage("nothing to change".into()).into());
            }
            body::merge(&mut body, &flags.into_value());
            body["entries"] = json!(list);
            let v = client
                .put(&format!("/aliases/{}", id_str(&cur)), &body)
                .await?;
            ctx.message(&v, &format!("Updated alias {alias}"))?;
            super::rules::after_write(ctx, apply).await
        }
        AliasCmd::Remove { alias, yes, apply } => {
            let cur = find(&client, "/aliases", &alias, "alias").await?;
            ctx.confirm(
                &format!("Delete alias {}?", cur["name"].as_str().unwrap_or(&alias)),
                yes,
            )?;
            let v = client.delete(&format!("/aliases/{}", id_str(&cur))).await?;
            ctx.message(&v, "Alias deleted")?;
            super::rules::after_write(ctx, apply).await
        }
    }
}

// -------------------------------------------------------------- schedules

#[derive(Debug, Subcommand)]
pub enum ScheduleCmd {
    #[command(visible_alias = "ls")]
    List,
    /// Add a schedule (attach it to rules with `aifw rules edit --schedule`)
    Add {
        #[arg(long)]
        name: String,
        /// Time ranges, e.g. 08:00-17:00,19:00-21:00
        #[arg(long)]
        times: String,
        /// Days, e.g. mon,tue,wed (default: every day)
        #[arg(long)]
        days: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// Change a schedule
    Edit {
        schedule: String,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        times: Option<String>,
        #[arg(long)]
        days: Option<String>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
    },
    #[command(visible_alias = "rm")]
    Remove {
        schedule: String,
        #[arg(short, long)]
        yes: bool,
    },
}

pub async fn schedules(ctx: &mut Ctx, cmd: ScheduleCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        ScheduleCmd::List => {
            let v = client.get("/schedules").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("TIMES", "/time_ranges"),
                    col("DAYS", "/days_of_week"),
                    col("ENABLED", "/enabled"),
                    wide("DESCRIPTION", "/description"),
                ],
            )
        }
        ScheduleCmd::Add {
            name,
            times,
            days,
            description,
        } => {
            let body = Fields::new()
                .set("name", name)
                .set("time_ranges", times)
                .opt("days_of_week", days)
                .opt("description", description)
                .into_value();
            let v = client.post("/schedules", &body).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "Added schedule {}",
                id_str(crate::cli::output::item(&v))
            ));
            Ok(())
        }
        ScheduleCmd::Edit {
            schedule,
            name,
            times,
            days,
            description,
            enabled,
        } => {
            let cur = find(&client, "/schedules", &schedule, "schedule").await?;
            let base = json!({
                "name": cur["name"], "description": cur["description"], "time_ranges": cur["time_ranges"],
                "days_of_week": cur["days_of_week"], "enabled": cur["enabled"],
            });
            let flags = Fields::new()
                .opt("name", name)
                .opt("time_ranges", times)
                .opt("days_of_week", days)
                .opt("description", description)
                .opt("enabled", enabled);
            let body = body::for_update(&mut ctx.io, base, None, flags)?;
            let v = client
                .put(&format!("/schedules/{}", id_str(&cur)), &body)
                .await?;
            ctx.message(&v, &format!("Updated schedule {schedule}"))
        }
        ScheduleCmd::Remove { schedule, yes } => {
            let cur = find(&client, "/schedules", &schedule, "schedule").await?;
            ctx.confirm(
                &format!(
                    "Delete schedule {} (rules using it lose it)?",
                    cur["name"].as_str().unwrap_or(&schedule)
                ),
                yes,
            )?;
            let v = client
                .delete(&format!("/schedules/{}", id_str(&cur)))
                .await?;
            ctx.message(&v, "Schedule deleted")
        }
    }
}

// ------------------------------------------------------------------ vlans

#[derive(Debug, Subcommand)]
pub enum VlanCmd {
    #[command(visible_alias = "ls")]
    List,
    /// Add a VLAN interface
    Add {
        /// VLAN tag (1-4094)
        #[arg(long)]
        vlan_id: u16,
        /// Parent interface, e.g. em1
        #[arg(long)]
        parent: String,
        /// dhcp, static, none
        #[arg(long)]
        ipv4_mode: Option<String>,
        /// CIDR, required with --ipv4-mode static
        #[arg(long)]
        ipv4_address: Option<String>,
        #[arg(long)]
        ipv6_address: Option<String>,
        #[arg(long)]
        mtu: Option<u16>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        apply: bool,
    },
    /// Change a VLAN
    Edit {
        id: String,
        #[arg(long)]
        ipv4_mode: Option<String>,
        #[arg(long)]
        ipv4_address: Option<String>,
        #[arg(long)]
        ipv6_address: Option<String>,
        #[arg(long)]
        mtu: Option<u16>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        enabled: Option<bool>,
        #[arg(long)]
        apply: bool,
    },
    #[command(visible_alias = "rm")]
    Remove {
        id: String,
        #[arg(short, long)]
        yes: bool,
        #[arg(long)]
        apply: bool,
    },
}

pub async fn vlans(ctx: &mut Ctx, cmd: VlanCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        VlanCmd::List => {
            let v = client.get("/vlans").await?;
            ctx.list(
                &v,
                &[
                    col("ID", "/id"),
                    col("VLAN", "/vlan_id"),
                    col("PARENT", "/parent"),
                    col("IPV4", "/ipv4_mode"),
                    col("ADDRESS", "/ipv4_address"),
                    col("MTU", "/mtu"),
                    col("ENABLED", "/enabled"),
                    wide("IPV6", "/ipv6_address"),
                    wide("DESCRIPTION", "/description"),
                ],
            )
        }
        VlanCmd::Add {
            vlan_id,
            parent,
            ipv4_mode,
            ipv4_address,
            ipv6_address,
            mtu,
            description,
            apply,
        } => {
            let body = Fields::new()
                .set("vlan_id", vlan_id)
                .set("parent", parent)
                .opt("ipv4_mode", ipv4_mode)
                .opt("ipv4_address", ipv4_address)
                .opt("ipv6_address", ipv6_address)
                .opt("mtu", mtu)
                .opt("description", description)
                .into_value();
            let v = client.post("/vlans", &body).await?;
            if ctx.format().is_structured() {
                ctx.raw(&v)?;
            } else {
                ctx.io.println(&format!(
                    "Added VLAN {}",
                    id_str(crate::cli::output::item(&v))
                ));
            }
            super::rules::after_write(ctx, apply).await
        }
        VlanCmd::Edit {
            id,
            ipv4_mode,
            ipv4_address,
            ipv6_address,
            mtu,
            description,
            enabled,
            apply,
        } => {
            let cur = find(&client, "/vlans", &id, "VLAN").await?;
            let base = json!({
                "vlan_id": cur["vlan_id"], "parent": cur["parent"], "ipv4_mode": cur["ipv4_mode"],
                "ipv4_address": cur["ipv4_address"], "ipv6_address": cur["ipv6_address"], "mtu": cur["mtu"],
                "enabled": cur["enabled"], "description": cur["description"],
            });
            let flags = Fields::new()
                .opt("ipv4_mode", ipv4_mode)
                .opt("ipv4_address", ipv4_address)
                .opt("ipv6_address", ipv6_address)
                .opt("mtu", mtu)
                .opt("description", description)
                .opt("enabled", enabled);
            let body = body::for_update(&mut ctx.io, base, None, flags)?;
            let v = client
                .put(&format!("/vlans/{}", id_str(&cur)), &body)
                .await?;
            ctx.message(&v, &format!("Updated VLAN {id}"))?;
            super::rules::after_write(ctx, apply).await
        }
        VlanCmd::Remove { id, yes, apply } => {
            ctx.confirm(&format!("Delete VLAN {id}?"), yes)?;
            let v = client.delete(&format!("/vlans/{id}")).await?;
            ctx.message(&v, "VLAN deleted")?;
            super::rules::after_write(ctx, apply).await
        }
    }
}
