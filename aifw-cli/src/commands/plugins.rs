//! `aifw plugins …` — view and configure built-in plugins. Writes go to
//! the same `plugin_config` table the API uses, through the same schema
//! validation; the running aifw-api applies them within ~10 seconds.

use std::path::Path;

use aifw_core::Database;
use aifw_plugins::schema::{FieldKind, ListItem, SettingField, effective};
use aifw_plugins::store::{PluginStore, StoredConfig};
use aifw_plugins::{Plugin, SettingsPatch, registry};
use serde_json::{Map, Value, json};

const APPLY_NOTE: &str = "The running aifw-api applies the change within ~10 seconds.";

async fn open_store(db_path: &Path) -> anyhow::Result<PluginStore> {
    let db = Database::new(db_path).await?;
    let store = PluginStore::new(db.pool().clone());
    store.migrate().await?;
    Ok(store)
}

fn find(name: &str) -> anyhow::Result<Box<dyn Plugin>> {
    registry::instantiate(name).ok_or_else(|| {
        let known: Vec<String> = registry::factories()
            .iter()
            .map(|f| f().info().name)
            .collect();
        anyhow::anyhow!("unknown plugin '{name}' (available: {})", known.join(", "))
    })
}

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
        other => other.to_string(),
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

pub async fn plugins_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let store = open_store(db_path).await?;
    let mut rows = Vec::new();
    for f in registry::factories() {
        let info = f().info();
        let cfg = store.load(&info.name).await?;
        rows.push((info, cfg.enabled));
    }
    if json {
        let out: Vec<Value> = rows
            .iter()
            .map(|(i, enabled)| {
                json!({"name": i.name, "title": i.title, "version": i.version, "enabled": enabled})
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    println!(
        "  {:<16} {:<22} {:<9} DESCRIPTION",
        "NAME", "TITLE", "ENABLED"
    );
    for (i, enabled) in rows {
        println!(
            "  {:<16} {:<22} {:<9} {}",
            i.name,
            i.title,
            if enabled { "yes" } else { "no" },
            i.description
        );
    }
    println!("\nRuntime state and live status are on the Plugins page of the web UI.");
    Ok(())
}

pub async fn plugins_show(db_path: &Path, name: &str, json: bool) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let store = open_store(db_path).await?;
    let cfg = store.load(name).await?;
    let schema = plugin.settings_schema();
    let eff = effective(&schema, &cfg.values, &cfg.secrets).into_map();
    let info = plugin.info();

    if json {
        let settings: Map<String, Value> = schema
            .iter()
            .map(|f| {
                let v = if f.secret {
                    json!({"secret": true, "set": cfg.secrets.contains_key(&f.key)})
                } else {
                    eff.get(&f.key).cloned().unwrap_or(Value::Null)
                };
                (f.key.clone(), v)
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
        println!("\n  Actions (run from the web UI or the API):");
        for a in actions {
            println!("    {:<10} {}", a.id, a.description);
        }
    }
    Ok(())
}

async fn save(store: &PluginStore, name: &str, cfg: &StoredConfig) -> anyhow::Result<()> {
    store.save(name, cfg).await?;
    Ok(())
}

pub async fn plugins_enable(db_path: &Path, name: &str, enabled: bool) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let store = open_store(db_path).await?;
    let mut cfg = store.load(name).await?;
    cfg.set_enabled(&*plugin, enabled)?;
    save(&store, name, &cfg).await?;
    println!(
        "{} {}. {APPLY_NOTE}",
        plugin.info().title,
        if enabled { "enabled" } else { "disabled" }
    );
    Ok(())
}

pub async fn plugins_set(
    db_path: &Path,
    name: &str,
    values: &[String],
    secrets: &[String],
    unset: &[String],
) -> anyhow::Result<()> {
    if values.is_empty() && secrets.is_empty() && unset.is_empty() {
        anyhow::bail!(
            "nothing to change — pass key=value pairs, --secret key=value or --unset key"
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
            anyhow::bail!("'{k}' is a secret — use --secret {k}=…");
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
    println!("{} settings saved. {APPLY_NOTE}", plugin.info().title);
    Ok(())
}

pub async fn plugins_reset(db_path: &Path, name: &str) -> anyhow::Result<()> {
    let plugin = find(name)?;
    let store = open_store(db_path).await?;
    store.reset(name).await?;
    println!(
        "{} reset to defaults and disabled. {APPLY_NOTE}",
        plugin.info().title
    );
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
            &[],
        )
        .await
        .unwrap();
        // Out of range is rejected by the shared schema check.
        assert!(
            plugins_set(&path, "threat-feeds", &["refresh_hours=0".into()], &[], &[])
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
                &[]
            )
            .await
            .is_err()
        );
        let store = open_store(&path).await.unwrap();
        let cfg = store.load("threat-feeds").await.unwrap();
        assert_eq!(cfg.values["refresh_hours"], 6);
        assert_eq!(cfg.values["feeds"], json!(["feodo", "dshield"]));

        plugins_set(&path, "threat-feeds", &[], &[], &["refresh_hours".into()])
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
            &[],
        )
        .await
        .unwrap();
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
}
