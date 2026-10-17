//! `aifw plugins …` — view and configure built-in plugins.
//!
//! Configuration (`enable`, `disable`, `set`, `reset`) is written to the
//! same `plugin_config` table the API uses, through the same schema
//! validation, so it works whether or not aifw-api is running; the API
//! applies it within ~10 seconds. Runtime views (`status`, `logs`, `run`)
//! come from the API, which owns the running plugins; they need a token
//! (`AIFW_TOKEN`, or `/var/db/aifw/cli.token`).

use std::path::Path;
use std::time::Duration;

use aifw_core::Database;
use aifw_plugins::schema::{FieldKind, ListItem, SettingField, effective};
use aifw_plugins::store::{PluginStore, StoredConfig};
use aifw_plugins::{Plugin, SettingsPatch, registry};
use serde_json::{Map, Value, json};

use super::cluster::{AIFW_API_BASE, read_api_token};

const APPLY_NOTE: &str = "The running aifw-api applies the change within ~10 seconds.";
/// How long `enable` / `disable` wait for the API to report the new state.
const APPLY_WAIT: Duration = Duration::from_secs(15);

async fn open_store(db_path: &Path) -> anyhow::Result<PluginStore> {
    let db = Database::new(db_path).await?;
    let store = PluginStore::new(db.pool().clone());
    store.migrate().await?;
    Ok(store)
}

fn find(name: &str) -> anyhow::Result<std::sync::Arc<dyn Plugin>> {
    registry::find(name).ok_or_else(|| {
        let known: Vec<String> = registry::builtins().iter().map(|p| p.info().name).collect();
        anyhow::anyhow!("unknown plugin '{name}' (available: {})", known.join(", "))
    })
}

// ---- API access -------------------------------------------------------------

/// Why the API could not be asked; the caller decides how loud to be.
pub(super) enum ApiUnavailable {
    /// Connection refused / timed out: aifw-api is not running here.
    Down,
    /// 401/403: no (usable) token.
    Unauthorized,
    /// Anything else, with the server's message.
    Other(String),
}

impl std::fmt::Display for ApiUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiUnavailable::Down => write!(f, "aifw-api is not reachable at {AIFW_API_BASE}"),
            ApiUnavailable::Unauthorized => write!(
                f,
                "the API refused the request: set AIFW_TOKEN to an API key with read access \
                 to this resource (and write access for commands that change it)"
            ),
            ApiUnavailable::Other(m) => f.write_str(m),
        }
    }
}

pub(super) async fn api(
    method: reqwest::Method,
    path: &str,
    body: Option<&Value>,
) -> Result<Value, ApiUnavailable> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(130))
        .connect_timeout(Duration::from_secs(2))
        .build()
        .map_err(|e| ApiUnavailable::Other(e.to_string()))?;
    let mut req = client.request(method, format!("{AIFW_API_BASE}{path}"));
    let token = read_api_token();
    if !token.is_empty() {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = req.send().await.map_err(|e| {
        if e.is_connect() || e.is_timeout() {
            ApiUnavailable::Down
        } else {
            ApiUnavailable::Other(e.without_url().to_string())
        }
    })?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(ApiUnavailable::Unauthorized);
    }
    let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !status.is_success() {
        let msg = value["message"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(ApiUnavailable::Other(msg));
    }
    Ok(value)
}

fn plugin_path(name: &str, rest: &str) -> String {
    format!("/api/v1/plugins/{name}{rest}")
}

// ---- formatting ---------------------------------------------------------------

fn kind_label(f: &SettingField) -> String {
    match &f.kind {
        FieldKind::Bool => "bool".into(),
        FieldKind::Integer { min, max } => format!("integer {min}-{max}"),
        FieldKind::Text { .. } => "text".into(),
        FieldKind::Url { https_only: true } => "https url".into(),
        FieldKind::Url { .. } => "url".into(),
        FieldKind::Select { options } => format!(
            "one of: {}",
            options
                .iter()
                .map(|o| o.value.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
        FieldKind::MultiSelect { options } => format!(
            "comma list of: {}",
            options
                .iter()
                .map(|o| o.value.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ),
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

/// One line per key of a JSON object, nested objects and object lists
/// indented, for action results and live status.
fn print_object(v: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                match v {
                    Value::Object(_) => {
                        println!("{pad}{k}:");
                        print_object(v, indent + 2);
                    }
                    Value::Array(a) if a.iter().any(Value::is_object) => {
                        println!("{pad}{k}:");
                        for item in a {
                            if item.is_object() {
                                println!("{pad}  -");
                                print_object(item, indent + 4);
                            } else {
                                println!("{pad}  - {}", show_value(item));
                            }
                        }
                    }
                    other => println!("{pad}{k}: {}", show_value(other)),
                }
            }
        }
        other => println!("{pad}{}", show_value(other)),
    }
}

/// Parse `raw` into the JSON shape `field` expects. Validation proper
/// (ranges, allowed values) happens in the shared schema check.
fn parse_value(field: &SettingField, raw: &str) -> anyhow::Result<Value> {
    let raw = raw.trim();
    Ok(match &field.kind {
        FieldKind::Bool => match raw.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Value::Bool(true),
            "false" | "no" | "off" | "0" => Value::Bool(false),
            _ => anyhow::bail!("{}: expected true/false, got '{raw}'", field.key),
        },
        FieldKind::Integer { .. } => {
            Value::from(raw.parse::<i64>().map_err(|_| {
                anyhow::anyhow!("{}: expected a whole number, got '{raw}'", field.key)
            })?)
        }
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

fn split_kv(arg: &str) -> anyhow::Result<(&str, &str)> {
    arg.split_once('=')
        .ok_or_else(|| anyhow::anyhow!("expected key=value, got '{arg}'"))
}

fn state_line(p: &Value) -> String {
    let state = p["state"].as_str().unwrap_or("?");
    match p["last_error"].as_str() {
        Some(e) if state == "error" => format!("error: {e}"),
        _ => state.to_string(),
    }
}

// ---- commands -----------------------------------------------------------------

pub async fn plugins_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let store = open_store(db_path).await?;
    // Runtime state comes from the API when it can be asked.
    let live = api(reqwest::Method::GET, "/api/v1/plugins", None).await;
    let state_of = |name: &str| -> Option<String> {
        live.as_ref().ok().and_then(|v| {
            v["plugins"]
                .as_array()?
                .iter()
                .find(|p| p["name"] == name)
                .map(state_line)
        })
    };
    let mut rows = Vec::new();
    for p in registry::builtins() {
        let info = p.info();
        let cfg = store.load(&info.name).await?;
        let state = state_of(&info.name);
        rows.push((info, cfg.enabled, state));
    }
    if json {
        let out: Vec<Value> = rows
            .iter()
            .map(|(i, enabled, state)| {
                json!({"name": i.name, "title": i.title, "version": i.version,
                       "enabled": enabled, "state": state})
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    println!(
        "  {:<16} {:<22} {:<9} {:<10} DESCRIPTION",
        "NAME", "TITLE", "ENABLED", "STATE"
    );
    for (i, enabled, state) in rows {
        println!(
            "  {:<16} {:<22} {:<9} {:<10} {}",
            i.name,
            i.title,
            if enabled { "yes" } else { "no" },
            state.as_deref().unwrap_or("-"),
            i.description
        );
    }
    if let Err(e) = live {
        println!("\nState unavailable: {e}.");
    }
    Ok(())
}

pub async fn plugins_show(db_path: &Path, name: &str, json: bool) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let store = open_store(db_path).await?;
    let cfg = store.load(name).await?;
    let schema = plugin.settings_schema();
    // Secrets are only ever shown as set / not set, so they stay out of the
    // effective map that is printed.
    let eff = effective(&schema, &cfg.values, &Map::new()).into_map();
    let info = plugin.info();
    let secrets_set: Vec<&str> = schema
        .iter()
        .filter(|f| f.secret && cfg.secrets.contains_key(&f.key))
        .map(|f| f.key.as_str())
        .collect();

    if json {
        let settings: Map<String, Value> = schema
            .iter()
            .filter(|f| !f.secret)
            .map(|f| {
                (
                    f.key.clone(),
                    eff.get(&f.key).cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
        let actions: Vec<Value> = plugin
            .actions()
            .iter()
            .map(|a| {
                json!({"id": a.id, "label": a.label, "description": a.description,
                       "args": a.args.iter().map(|f| f.key.clone()).collect::<Vec<_>>()})
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "name": info.name,
                "title": info.title,
                "version": info.version,
                "enabled": cfg.enabled,
                "settings": settings,
                "secrets_set": secrets_set,
                "actions": actions,
            }))?
        );
        return Ok(());
    }

    println!("{} ({}) v{}", info.title, info.name, info.version);
    println!("  {}", info.description);
    println!("  Enabled: {}", if cfg.enabled { "yes" } else { "no" });
    let mut group: Option<&str> = None;
    for f in &schema {
        let g = f.group.as_deref().unwrap_or("Settings");
        if group != Some(g) {
            println!("\n  [{g}]");
            group = Some(g);
        }
        let value = if f.secret {
            if cfg.secrets.contains_key(&f.key) {
                "(set)".to_string()
            } else {
                "(not set)".to_string()
            }
        } else {
            let v = show_value(eff.get(&f.key).unwrap_or(&Value::Null));
            if cfg.values.contains_key(&f.key) {
                v
            } else {
                format!("{v}  (default)")
            }
        };
        println!("  {:<28} {}", f.key, value);
        println!("  {:<28} {} — {}", "", f.label, kind_label(f));
    }
    let actions = plugin.actions();
    if !actions.is_empty() {
        println!("\n  Actions (aifw plugins run {name} <action> [key=value…]):");
        for a in actions {
            let args: Vec<String> = a.args.iter().map(|f| format!("{}=…", f.key)).collect();
            println!("    {:<10} {} {}", a.id, a.description, args.join(" "));
        }
    }
    Ok(())
}

async fn save(store: &PluginStore, name: &str, cfg: &StoredConfig) -> anyhow::Result<()> {
    store.save(name, cfg).await?;
    Ok(())
}

/// After a config write, watch the API until it reports the plugin in the
/// wanted state (or an error), then print what happened. Falls back to a
/// hint when the API can't be asked.
async fn report_apply(name: &str, want_enabled: bool) {
    let deadline = tokio::time::Instant::now() + APPLY_WAIT;
    loop {
        match api(reqwest::Method::GET, &plugin_path(name, ""), None).await {
            Ok(p) => {
                let enabled = p["enabled"].as_bool().unwrap_or(!want_enabled);
                let state = p["state"].as_str().unwrap_or("");
                let settled = enabled == want_enabled
                    && (!want_enabled || state == "running" || state == "error");
                if settled {
                    println!("Now {}.", state_line(&p));
                    if state == "error" {
                        println!("See `aifw plugins logs {name}` for details.");
                    }
                    return;
                }
            }
            Err(e @ ApiUnavailable::Down) | Err(e @ ApiUnavailable::Unauthorized) => {
                println!("{APPLY_NOTE} ({e}; check with `aifw plugins status {name}`.)");
                return;
            }
            Err(ApiUnavailable::Other(m)) => {
                println!("{APPLY_NOTE} (could not confirm: {m})");
                return;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            println!("{APPLY_NOTE} (not applied yet; check with `aifw plugins status {name}`.)");
            return;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

pub async fn plugins_enable(db_path: &Path, name: &str, enabled: bool) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let store = open_store(db_path).await?;
    let mut cfg = store.load(name).await?;
    cfg.set_enabled(&*plugin, enabled)?;
    save(&store, name, &cfg).await?;
    println!(
        "{} {}.",
        plugin.info().title,
        if enabled { "enabled" } else { "disabled" }
    );
    report_apply(name, enabled).await;
    Ok(())
}

fn read_stdin_line() -> anyhow::Result<String> {
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let v = line.trim_end_matches(['\r', '\n']).to_string();
    if v.is_empty() {
        anyhow::bail!("--secret-stdin: nothing was read from stdin");
    }
    Ok(v)
}

pub async fn plugins_set(
    db_path: &Path,
    name: &str,
    values: &[String],
    secrets: &[String],
    secret_stdin: Option<&str>,
    unset: &[String],
) -> anyhow::Result<()> {
    if values.is_empty() && secrets.is_empty() && secret_stdin.is_none() && unset.is_empty() {
        anyhow::bail!(
            "nothing to change — pass key=value pairs, --secret key=value, \
             --secret-stdin key or --unset key"
        );
    }
    let plugin = find(name)?;
    let schema = plugin.settings_schema();
    let field = |key: &str| {
        schema.iter().find(|f| f.key == key).ok_or_else(|| {
            anyhow::anyhow!("'{name}' has no setting '{key}' — see `aifw plugins show {name}`")
        })
    };
    let mut patch = SettingsPatch::default();
    for arg in values {
        let (k, raw) = split_kv(arg)?;
        let f = field(k)?;
        if f.secret {
            anyhow::bail!("'{k}' is a secret — use --secret {k}=… or --secret-stdin {k}");
        }
        patch.values.insert(k.to_string(), parse_value(f, raw)?);
    }
    for arg in secrets {
        let (k, raw) = split_kv(arg)?;
        let f = field(k)?;
        if !f.secret {
            anyhow::bail!("'{k}' is not a secret — pass it as {k}=…");
        }
        patch
            .secrets
            .insert(k.to_string(), Value::String(raw.trim().to_string()));
    }
    if let Some(k) = secret_stdin {
        let f = field(k)?;
        if !f.secret {
            anyhow::bail!("'{k}' is not a secret — pass it as {k}=…");
        }
        patch
            .secrets
            .insert(k.to_string(), Value::String(read_stdin_line()?));
    }
    for k in unset {
        let f = field(k)?;
        let target = if f.secret {
            &mut patch.secrets
        } else {
            &mut patch.values
        };
        target.insert(k.clone(), Value::Null);
    }

    let store = open_store(db_path).await?;
    let mut cfg = store.load(name).await?;
    cfg.apply_patch(&*plugin, patch)?;
    save(&store, name, &cfg).await?;
    println!("{} settings saved.", plugin.info().title);
    if cfg.enabled {
        println!("{APPLY_NOTE} Check with `aifw plugins status {name}`.");
    }
    Ok(())
}

pub async fn plugins_reset(db_path: &Path, name: &str) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let store = open_store(db_path).await?;
    store.reset(name).await?;
    println!("{} reset to defaults and disabled.", plugin.info().title);
    report_apply(name, false).await;
    Ok(())
}

pub async fn plugins_status(name: Option<&str>, json: bool) -> anyhow::Result<()> {
    let names: Vec<String> = match name {
        Some(n) => {
            find(n)?;
            vec![n.to_string()]
        }
        None => registry::builtins().iter().map(|p| p.info().name).collect(),
    };
    let mut out = Vec::new();
    for n in &names {
        let summary = api(reqwest::Method::GET, &plugin_path(n, ""), None)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let status = if summary["state"] == "running" {
            api(reqwest::Method::GET, &plugin_path(n, "/status"), None)
                .await
                .unwrap_or(Value::Null)
        } else {
            Value::Null
        };
        out.push((n.clone(), summary, status));
    }
    if json {
        let v: Vec<Value> = out
            .iter()
            .map(|(_, s, st)| json!({"plugin": s, "status": st}))
            .collect();
        println!("{}", serde_json::to_string_pretty(&v)?);
        return Ok(());
    }
    for (i, (n, s, st)) in out.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!(
            "{} ({n}): {}",
            s["title"].as_str().unwrap_or(n),
            state_line(s)
        );
        if let Some(at) = s["started_at"].as_str() {
            println!("  Started: {at}");
        }
        let stats = &s["stats"];
        println!(
            "  Events: {}  actions: {}  errors: {}  timeouts: {}  panics: {}",
            stats["events"], stats["actions"], stats["errors"], stats["timeouts"], stats["panics"]
        );
        if let Some(rules) = s["rules"].as_array().filter(|r| !r.is_empty()) {
            println!("  pf rules:");
            for r in rules {
                println!("    {}", show_value(r));
            }
        }
        if !st.is_null() {
            println!("  Live status:");
            print_object(st, 4);
        }
    }
    Ok(())
}

pub async fn plugins_logs(name: &str, limit: usize, level: &str, json: bool) -> anyhow::Result<()> {
    find(name)?;
    if !matches!(level, "info" | "warn" | "error") {
        anyhow::bail!("--level must be info, warn or error");
    }
    let v = api(
        reqwest::Method::GET,
        &plugin_path(
            name,
            &format!("/logs?limit={}&level={level}", limit.clamp(1, 500)),
        ),
        None,
    )
    .await
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    let entries = v["entries"].as_array().cloned().unwrap_or_default();
    if json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
        return Ok(());
    }
    if entries.is_empty() {
        println!("No entries.");
        return Ok(());
    }
    for e in entries.iter().rev() {
        println!(
            "{}  {:<5} {}",
            e["ts"].as_str().unwrap_or("-"),
            e["level"].as_str().unwrap_or("-"),
            e["message"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

pub async fn plugins_run(
    name: &str,
    action: &str,
    args: &[String],
    json: bool,
) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let info = plugin
        .actions()
        .into_iter()
        .find(|a| a.id == action)
        .ok_or_else(|| {
            let known: Vec<String> = plugin.actions().iter().map(|a| a.id.clone()).collect();
            anyhow::anyhow!(
                "'{name}' has no action '{action}' (available: {})",
                known.join(", ")
            )
        })?;
    let mut body = Map::new();
    for arg in args {
        let (k, raw) = split_kv(arg)?;
        let f = info
            .args
            .iter()
            .find(|f| f.key == k)
            .ok_or_else(|| anyhow::anyhow!("action '{action}' has no argument '{k}'"))?;
        body.insert(k.to_string(), parse_value(f, raw)?);
    }
    let v = api(
        reqwest::Method::POST,
        &plugin_path(name, &format!("/actions/{action}")),
        Some(&Value::Object(body)),
    )
    .await
    .map_err(|e| anyhow::anyhow!("{}: {e}", info.label))?;
    let result = &v["result"];
    if json {
        println!("{}", serde_json::to_string_pretty(result)?);
        return Ok(());
    }
    println!("{} finished.", info.label);
    print_object(result, 2);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Scratch DB in its own directory, removed on drop.
    struct Scratch(std::path::PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            if let Err(e) = std::fs::remove_dir_all(&self.0) {
                eprintln!("scratch cleanup failed: {e}");
            }
        }
    }

    fn db() -> (Scratch, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("aifw-cli-plugins-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("aifw.db");
        (Scratch(dir), path)
    }

    #[tokio::test]
    async fn set_validates_and_persists() {
        let (_dir, path) = db();
        plugins_set(
            &path,
            "threat-feeds",
            &["refresh_hours=6".into(), "feeds=feodo,dshield".into()],
            &[],
            None,
            &[],
        )
        .await
        .unwrap();
        // Out of range is rejected by the shared schema check.
        assert!(
            plugins_set(
                &path,
                "threat-feeds",
                &["refresh_hours=0".into()],
                &[],
                None,
                &[]
            )
            .await
            .is_err()
        );
        // Secrets must go through --secret.
        assert!(
            plugins_set(
                &path,
                "notifier",
                &["ntfy_url=https://ntfy.sh/x".into()],
                &[],
                None,
                &[]
            )
            .await
            .is_err()
        );
        let store = open_store(&path).await.unwrap();
        let cfg = store.load("threat-feeds").await.unwrap();
        assert_eq!(cfg.values["refresh_hours"], 6);
        assert_eq!(cfg.values["feeds"], json!(["feodo", "dshield"]));

        plugins_set(
            &path,
            "threat-feeds",
            &[],
            &[],
            None,
            &["refresh_hours".into()],
        )
        .await
        .unwrap();
        let cfg = store.load("threat-feeds").await.unwrap();
        assert!(!cfg.values.contains_key("refresh_hours"));
    }

    #[tokio::test]
    async fn enable_refuses_unconfigured_notifier() {
        let (_dir, path) = db();
        let err = plugins_enable(&path, "notifier", true).await.unwrap_err();
        assert!(err.to_string().contains("channel"), "{err}");
        plugins_set(
            &path,
            "notifier",
            &[],
            &["ntfy_url=https://ntfy.sh/aifw-cli-test".into()],
            None,
            &[],
        )
        .await
        .unwrap();
        // No API in tests: enable writes the store and prints the hint.
        plugins_enable(&path, "notifier", true).await.unwrap();
        let cfg = open_store(&path)
            .await
            .unwrap()
            .load("notifier")
            .await
            .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.secrets["ntfy_url"], "https://ntfy.sh/aifw-cli-test");
    }

    #[test]
    fn values_parse_by_kind() {
        let schema = find("notifier").unwrap().settings_schema();
        let f = |k: &str| schema.iter().find(|f| f.key == k).unwrap();
        assert_eq!(parse_value(f("notify_ids"), "off").unwrap(), json!(false));
        assert_eq!(parse_value(f("dedupe_minutes"), "15").unwrap(), json!(15));
        assert_eq!(
            parse_value(f("config_actions"), "rules_applied, daemon_stopped").unwrap(),
            json!(["rules_applied", "daemon_stopped"])
        );
        assert!(parse_value(f("notify_ids"), "maybe").is_err());
    }

    #[tokio::test]
    async fn runtime_commands_explain_a_missing_api() {
        // Nothing listens on the loopback API port in tests; the error must
        // say so rather than dump a reqwest message.
        let err = plugins_logs("notifier", 10, "info", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not reachable") || err.contains("refused"),
            "{err}"
        );
        assert!(plugins_run("notifier", "nope", &[], false).await.is_err());
        assert!(plugins_logs("notifier", 10, "loud", false).await.is_err());
    }
}
