//! `aifw plugins …` — built-in plugins (threat feeds, notifier, …) via the
//! API. Setting types come from the plugin's schema as served by the
//! appliance, so the CLI parses `key=value` the way that version expects.

use aifw_plugins::schema::{FieldKind, ListItem, SettingField};
use clap::Subcommand;
use serde_json::{Map, Value, json};

use crate::cli::exit::CliError;
use crate::cli::{Ctx, Format, col, prompt};

#[derive(Debug, Subcommand)]
pub enum PluginsCmd {
    /// List plugins with their state
    #[command(visible_alias = "ls")]
    List {
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Show a plugin's settings and actions
    Show {
        name: String,
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Enable a plugin
    Enable { name: String },
    /// Disable a plugin
    Disable { name: String },
    /// Change settings: key=value pairs, --secret key=value, --secret-stdin key, --unset key
    #[command(after_help = "\
EXAMPLES:
    # Refresh threat feeds every 6 hours from two lists
    aifw plugins set threat-feeds refresh_hours=6 feeds=spamhaus-drop,feodo

    # Never block an upstream partner's network
    aifw plugins set threat-feeds allowlist=198.51.100.0/24

    # Send notifications to an ntfy topic (secrets go through --secret)
    aifw plugins set notifier --secret ntfy_url=https://ntfy.sh/my-topic

    # Read a secret from stdin so it stays out of shell history and ps
    printf '%s' \"$TOKEN\" | aifw plugins set notifier --secret-stdin ntfy_token

    # Back to the default
    aifw plugins set threat-feeds --unset refresh_hours")]
    Set {
        name: String,
        values: Vec<String>,
        #[arg(long = "secret", value_name = "KEY=VALUE")]
        secrets: Vec<String>,
        #[arg(long = "secret-stdin", value_name = "KEY")]
        secret_stdin: Option<String>,
        #[arg(long = "unset", value_name = "KEY")]
        unset: Vec<String>,
    },
    /// Reset a plugin to defaults (and disable it)
    Reset {
        name: String,
        #[arg(short, long)]
        yes: bool,
    },
    /// Runtime state, counters and live status (all plugins by default)
    Status {
        name: Option<String>,
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Recent log entries
    Logs {
        name: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value = "info", value_parser = ["info", "warn", "error"])]
        level: String,
        #[arg(long, hide = true)]
        json: bool,
    },
    /// Run a plugin action
    #[command(after_help = "\
EXAMPLES:
    aifw plugins run threat-feeds refresh
    aifw plugins run threat-feeds lookup ip=203.0.113.9
    aifw plugins run notifier test channel=ntfy")]
    Run {
        name: String,
        action: String,
        args: Vec<String>,
        #[arg(long, hide = true)]
        json: bool,
    },
}

fn kind_label(f: &SettingField) -> String {
    let opts = |o: &[aifw_plugins::schema::SelectOption]| {
        o.iter()
            .map(|o| o.value.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    match &f.kind {
        FieldKind::Bool => "bool".into(),
        FieldKind::Integer { min, max } => format!("integer {min}-{max}"),
        FieldKind::Text { .. } => "text".into(),
        FieldKind::Url { https_only: true } => "https url".into(),
        FieldKind::Url { .. } => "url".into(),
        FieldKind::Select { options } => format!("one of: {}", opts(options)),
        FieldKind::MultiSelect { options } => format!("comma list of: {}", opts(options)),
        FieldKind::List { item, max_items } => format!(
            "comma list of {} (max {max_items})",
            match item {
                ListItem::Cidr => "IPs/CIDRs",
                ListItem::Url => "URLs",
                ListItem::Text => "values",
            }
        ),
    }
}

fn show_value(v: &Value) -> String {
    match v {
        Value::Null => "-".into(),
        Value::String(s) if s.is_empty() => "-".into(),
        Value::String(s) => s.clone(),
        Value::Array(a) if a.is_empty() => "(none)".into(),
        Value::Array(a) => a
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| x.to_string())
            })
            .collect::<Vec<_>>()
            .join(", "),
        Value::Bool(b) => if *b { "yes" } else { "no" }.into(),
        other => other.to_string(),
    }
}

/// Indented key/value rendering of an arbitrary JSON object (action
/// results, live status).
fn render_object(v: &Value, indent: usize, out: &mut Vec<String>) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                match v {
                    Value::Object(_) => {
                        out.push(format!("{pad}{k}:"));
                        render_object(v, indent + 2, out);
                    }
                    Value::Array(a) if a.iter().any(Value::is_object) => {
                        out.push(format!("{pad}{k}:"));
                        for item in a {
                            if item.is_object() {
                                out.push(format!("{pad}  -"));
                                render_object(item, indent + 4, out);
                            } else {
                                out.push(format!("{pad}  - {}", show_value(item)));
                            }
                        }
                    }
                    other => out.push(format!("{pad}{k}: {}", show_value(other))),
                }
            }
        }
        other => out.push(format!("{pad}{}", show_value(other))),
    }
}

/// Parse `raw` into the JSON shape `field` expects. Range/option checks
/// are the server's job.
pub fn parse_value(field: &SettingField, raw: &str) -> Result<Value, CliError> {
    let raw = raw.trim();
    Ok(match &field.kind {
        FieldKind::Bool => match raw.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Value::Bool(true),
            "false" | "no" | "off" | "0" => Value::Bool(false),
            _ => {
                return Err(CliError::Usage(format!(
                    "{}: expected true/false, got '{raw}'",
                    field.key
                )));
            }
        },
        FieldKind::Integer { .. } => Value::from(raw.parse::<i64>().map_err(|_| {
            CliError::Usage(format!(
                "{}: expected a whole number, got '{raw}'",
                field.key
            ))
        })?),
        FieldKind::MultiSelect { .. } | FieldKind::List { .. } => Value::Array(
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(Value::from)
                .collect(),
        ),
        _ => Value::String(raw.to_string()),
    })
}

fn split_kv(arg: &str) -> Result<(&str, &str), CliError> {
    arg.split_once('=')
        .ok_or_else(|| CliError::Usage(format!("expected key=value, got '{arg}'")))
}

fn state_line(p: &Value) -> String {
    let state = p["state"].as_str().unwrap_or("?");
    match p["last_error"].as_str() {
        Some(e) if state == "error" => format!("error: {e}"),
        _ => state.to_string(),
    }
}

fn schema_of(detail: &Value, ptr: &str) -> Vec<SettingField> {
    detail
        .pointer(ptr)
        .cloned()
        .and_then(|s| serde_json::from_value(s).ok())
        .unwrap_or_default()
}

pub async fn run(ctx: &mut Ctx, cmd: PluginsCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        PluginsCmd::List { json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client.get("/plugins").await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.list_mapped(
                &json!({ "data": v["plugins"] }),
                &[
                    col("NAME", "/name"),
                    col("TITLE", "/title"),
                    col("ENABLED", "/enabled"),
                    col("STATE", "/_state"),
                    col("DESCRIPTION", "/description"),
                ],
                |p| {
                    let mut r = p.clone();
                    r["_state"] = json!(state_line(p));
                    r
                },
            )
        }
        PluginsCmd::Show { name, json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let d = client.get(&format!("/plugins/{name}")).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&d);
            }
            show(ctx, &name, &d);
            Ok(())
        }
        PluginsCmd::Enable { name } => set_enabled(ctx, &client, &name, true).await,
        PluginsCmd::Disable { name } => set_enabled(ctx, &client, &name, false).await,
        PluginsCmd::Set {
            name,
            values,
            secrets,
            secret_stdin,
            unset,
        } => {
            if values.is_empty() && secrets.is_empty() && secret_stdin.is_none() && unset.is_empty()
            {
                return Err(CliError::Usage(
                    "nothing to change — pass key=value pairs, --secret key=value, --secret-stdin key or --unset key".into(),
                )
                .into());
            }
            let d = client.get(&format!("/plugins/{name}")).await?;
            let schema = schema_of(&d, "/schema");
            let field = |key: &str| {
                schema.iter().find(|f| f.key == key).ok_or_else(|| {
                    CliError::Usage(format!(
                        "'{name}' has no setting '{key}' — see `aifw plugins show {name}`"
                    ))
                })
            };
            let mut vals = Map::new();
            let mut secs = Map::new();
            for arg in &values {
                let (k, raw) = split_kv(arg)?;
                let f = field(k)?;
                if f.secret {
                    return Err(CliError::Usage(format!(
                        "'{k}' is a secret — use --secret {k}=… or --secret-stdin {k}"
                    ))
                    .into());
                }
                vals.insert(k.to_string(), parse_value(f, raw)?);
            }
            for arg in &secrets {
                let (k, raw) = split_kv(arg)?;
                if !field(k)?.secret {
                    return Err(CliError::Usage(format!(
                        "'{k}' is not a secret — pass it as {k}=…"
                    ))
                    .into());
                }
                secs.insert(k.to_string(), json!(raw.trim()));
            }
            if let Some(k) = &secret_stdin {
                if !field(k)?.secret {
                    return Err(CliError::Usage(format!(
                        "'{k}' is not a secret — pass it as {k}=…"
                    ))
                    .into());
                }
                let s = prompt::read_line_raw(&mut ctx.io)?.trim().to_string();
                if s.is_empty() {
                    return Err(
                        CliError::Usage(format!("--secret-stdin {k}: nothing on stdin")).into(),
                    );
                }
                secs.insert(k.clone(), json!(s));
            }
            for k in &unset {
                let target = if field(k)?.secret {
                    &mut secs
                } else {
                    &mut vals
                };
                target.insert(k.clone(), Value::Null);
            }
            let v = client
                .patch(
                    &format!("/plugins/{name}/settings"),
                    &json!({ "values": vals, "secrets": secs }),
                )
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "{} settings saved.",
                v["title"].as_str().unwrap_or(&name)
            ));
            Ok(())
        }
        PluginsCmd::Reset { name, yes } => {
            ctx.confirm(&format!("Reset {name} to defaults and disable it?"), yes)?;
            let v = client.post_empty(&format!("/plugins/{name}/reset")).await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            ctx.io.println(&format!(
                "{} reset to defaults and disabled.",
                v["title"].as_str().unwrap_or(&name)
            ));
            Ok(())
        }
        PluginsCmd::Status { name, json } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let names: Vec<String> = match name {
                Some(n) => vec![n],
                None => client.get("/plugins").await?["plugins"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|p| p["name"].as_str().map(str::to_string))
                    .collect(),
            };
            let mut out = Vec::new();
            for n in &names {
                let summary = client.get(&format!("/plugins/{n}")).await?;
                let status = if summary["state"] == "running" {
                    client
                        .get(&format!("/plugins/{n}/status"))
                        .await
                        .unwrap_or(Value::Null)
                } else {
                    Value::Null
                };
                out.push(json!({ "plugin": summary, "status": status }));
            }
            if ctx.format().is_structured() {
                return ctx.raw(&Value::Array(out));
            }
            let mut lines = Vec::new();
            for (i, e) in out.iter().enumerate() {
                let s = &e["plugin"];
                if i > 0 {
                    lines.push(String::new());
                }
                lines.push(format!(
                    "{} ({}): {}",
                    s["title"].as_str().unwrap_or("?"),
                    s["name"].as_str().unwrap_or("?"),
                    state_line(s)
                ));
                if let Some(at) = s["started_at"].as_str() {
                    lines.push(format!("  Started: {at}"));
                }
                let st = &s["stats"];
                lines.push(format!(
                    "  Events: {}  actions: {}  errors: {}  timeouts: {}  panics: {}",
                    st["events"], st["actions"], st["errors"], st["timeouts"], st["panics"]
                ));
                if let Some(rules) = s["rules"].as_array().filter(|r| !r.is_empty()) {
                    lines.push("  pf rules:".into());
                    lines.extend(rules.iter().map(|r| format!("    {}", show_value(r))));
                }
                if !e["status"].is_null() {
                    lines.push("  Live status:".into());
                    render_object(&e["status"], 4, &mut lines);
                }
            }
            ctx.io.println(&lines.join("\n"));
            Ok(())
        }
        PluginsCmd::Logs {
            name,
            limit,
            level,
            json,
        } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let v = client
                .get(&format!(
                    "/plugins/{name}/logs?limit={}&level={level}",
                    limit.clamp(1, 500)
                ))
                .await?;
            let entries = v["entries"].as_array().cloned().unwrap_or_default();
            if ctx.format().is_structured() {
                return ctx.raw(&Value::Array(entries));
            }
            if entries.is_empty() {
                ctx.io.eprintln("No entries.");
            }
            for e in entries.iter().rev() {
                ctx.io.println(&format!(
                    "{}  {:<5} {}",
                    e["ts"].as_str().unwrap_or("-"),
                    e["level"].as_str().unwrap_or("-"),
                    e["message"].as_str().unwrap_or("")
                ));
            }
            Ok(())
        }
        PluginsCmd::Run {
            name,
            action,
            args,
            json,
        } => {
            if json {
                ctx.force_format(Format::Json);
            }
            let d = client.get(&format!("/plugins/{name}")).await?;
            let actions = d["actions"].as_array().cloned().unwrap_or_default();
            let info = actions
                .iter()
                .find(|a| a["id"] == json!(action))
                .ok_or_else(|| {
                    let known: Vec<&str> =
                        actions.iter().filter_map(|a| a["id"].as_str()).collect();
                    CliError::Usage(format!(
                        "'{name}' has no action '{action}' (available: {})",
                        known.join(", ")
                    ))
                })?;
            let arg_schema: Vec<SettingField> =
                serde_json::from_value(info["args"].clone()).unwrap_or_default();
            let mut body = Map::new();
            for arg in &args {
                let (k, raw) = split_kv(arg)?;
                let f = arg_schema.iter().find(|f| f.key == k).ok_or_else(|| {
                    CliError::Usage(format!("action '{action}' has no argument '{k}'"))
                })?;
                body.insert(k.to_string(), parse_value(f, raw)?);
            }
            let label = info["label"].as_str().unwrap_or(&action).to_string();
            // Actions may run up to the server's 120 s limit.
            let v = client
                .request_with_timeout(
                    reqwest::Method::POST,
                    &format!("/plugins/{name}/actions/{action}"),
                    Some(&Value::Object(body)),
                    ctx.slow_timeout(std::time::Duration::from_secs(150)),
                )
                .await?;
            if ctx.format().is_structured() {
                return ctx.raw(&v["result"]);
            }
            let mut lines = vec![format!("{label} finished.")];
            render_object(&v["result"], 2, &mut lines);
            ctx.io.println(&lines.join("\n"));
            Ok(())
        }
    }
}

fn show(ctx: &mut Ctx, name: &str, d: &Value) {
    let schema = schema_of(d, "/schema");
    let mut lines = vec![
        format!(
            "{} ({}) v{}",
            d["title"].as_str().unwrap_or(name),
            name,
            d["version"].as_str().unwrap_or("?")
        ),
        format!("  {}", d["description"].as_str().unwrap_or("")),
        format!(
            "  Enabled: {}  State: {}",
            if d["enabled"] == true { "yes" } else { "no" },
            state_line(d)
        ),
    ];
    let secrets_set: Vec<&str> = d["secrets_set"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut group: Option<String> = None;
    for f in &schema {
        let g = f.group.clone().unwrap_or_else(|| "Settings".into());
        if group.as_deref() != Some(g.as_str()) {
            lines.push(format!("\n  [{g}]"));
            group = Some(g);
        }
        let value = if f.secret {
            if secrets_set.contains(&f.key.as_str()) {
                "(set)".into()
            } else {
                "(not set)".into()
            }
        } else {
            let v = show_value(d["effective"].get(&f.key).unwrap_or(&Value::Null));
            if d["values"].get(&f.key).is_some() {
                v
            } else {
                format!("{v}  (default)")
            }
        };
        lines.push(format!("  {:<28} {}", f.key, value));
        lines.push(format!("  {:<28} {} — {}", "", f.label, kind_label(f)));
    }
    if let Some(actions) = d["actions"].as_array().filter(|a| !a.is_empty()) {
        lines.push(format!(
            "\n  Actions (aifw plugins run {name} <action> [key=value…]):"
        ));
        for a in actions {
            let args: Vec<String> = a["args"]
                .as_array()
                .map(|x| {
                    x.iter()
                        .filter_map(|f| f["key"].as_str())
                        .map(|k| format!("{k}=…"))
                        .collect()
                })
                .unwrap_or_default();
            lines.push(format!(
                "    {:<10} {} {}",
                a["id"].as_str().unwrap_or("?"),
                a["description"].as_str().unwrap_or(""),
                args.join(" ")
            ));
        }
    }
    ctx.io.println(&lines.join("\n"));
}

async fn set_enabled(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    name: &str,
    on: bool,
) -> anyhow::Result<()> {
    let v = client
        .put(
            &format!("/plugins/{name}/enabled"),
            &json!({ "enabled": on }),
        )
        .await?;
    if ctx.format().is_structured() {
        return ctx.raw(&v);
    }
    ctx.io.println(&format!(
        "{} {} ({}).",
        v["title"].as_str().unwrap_or(name),
        if on { "enabled" } else { "disabled" },
        state_line(&v)
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn field(kind: Value) -> SettingField {
        serde_json::from_value(json!({
            "key": "k", "label": "K", "kind": kind, "secret": false, "default": null
        }))
        .unwrap()
    }

    #[test]
    fn values_parse_by_kind() {
        assert_eq!(
            parse_value(&field(json!({"type":"bool"})), "on").unwrap(),
            json!(true)
        );
        assert!(parse_value(&field(json!({"type":"bool"})), "maybe").is_err());
        assert_eq!(
            parse_value(&field(json!({"type":"integer","min":1,"max":9})), " 6 ").unwrap(),
            json!(6)
        );
        assert!(parse_value(&field(json!({"type":"integer","min":1,"max":9})), "six").is_err());
        assert_eq!(
            parse_value(
                &field(json!({"type":"list","item":"cidr","max_items":5})),
                "10.0.0.0/8, ,192.0.2.1"
            )
            .unwrap(),
            json!(["10.0.0.0/8", "192.0.2.1"])
        );
        assert!(split_kv("novalue").is_err());
    }

    #[test]
    fn nested_rendering() {
        let mut out = Vec::new();
        render_object(
            &json!({"a": 1, "b": {"c": [1, 2]}, "d": [{"e": true}]}),
            0,
            &mut out,
        );
        assert_eq!(
            out,
            vec!["a: 1", "b:", "  c: 1, 2", "d:", "  -", "    e: yes"]
        );
    }
}
