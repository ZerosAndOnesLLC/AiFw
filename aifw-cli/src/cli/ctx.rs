//! Per-invocation state handed to every command: global flags, stdio, the
//! config store and on-box paths, plus helpers to build clients and render.

use std::time::Duration;

use aifw_client::Client;
use serde_json::Value;

use super::config::Store;
use super::connect::{self, Target};
use super::global::GlobalArgs;
use super::io::Io;
use super::onbox::OnBox;
use super::output::{self, Col, Format};
use super::prompt;

/// Process-level environment, overridable by tests.
#[derive(Debug, Clone)]
pub struct Env {
    pub config_dir: std::path::PathBuf,
    pub onbox: OnBox,
}

impl Default for Env {
    fn default() -> Self {
        Self {
            config_dir: super::config::default_config_dir(),
            onbox: OnBox::default(),
        }
    }
}

pub struct Ctx {
    pub g: GlobalArgs,
    pub io: Io,
    pub store: Store,
    pub onbox: OnBox,
    /// Output format after applying the context default.
    format: Option<Format>,
}

impl Ctx {
    pub fn new(g: GlobalArgs, io: Io, env: Env) -> Self {
        Self {
            format: g.output,
            store: Store::new(env.config_dir),
            onbox: env.onbox,
            g,
            io,
        }
    }

    pub fn format(&self) -> Format {
        self.format.unwrap_or_default()
    }

    /// Force a format (legacy per-command `--json` flags).
    pub fn force_format(&mut self, f: Format) {
        self.format = Some(f);
    }

    /// Resolve the target for the selected (single) context.
    pub fn target(&mut self) -> anyhow::Result<Target> {
        let names = self.g.context_names();
        if names.len() > 1 {
            return Err(super::exit::CliError::Usage(
                "this command talks to one appliance; pass a single --context".into(),
            )
            .into());
        }
        let t = connect::resolve(
            &self.g,
            &self.store,
            &self.onbox,
            names.first().map(String::as_str),
        )?;
        if self.format.is_none() {
            self.format = t.output.as_deref().and_then(Format::parse);
        }
        Ok(t)
    }

    /// Client for the selected context, with the global `--timeout`.
    pub fn client(&mut self) -> anyhow::Result<Client> {
        let t = self.target()?;
        connect::client(
            &t,
            &self.store,
            self.g.request_timeout.map(Duration::from_secs),
        )
    }

    /// Timeout for slow synchronous endpoints: `--timeout` or `default`.
    pub fn slow_timeout(&self, default: Duration) -> Duration {
        self.g.request_timeout.map_or(default, Duration::from_secs)
    }

    // ---- rendering ----------------------------------------------------

    /// Print a list response: a table of `cols`, or the raw JSON/YAML.
    pub fn list(&mut self, v: &Value, cols: &[Col]) -> anyhow::Result<()> {
        let f = self.format();
        if f.is_structured() {
            return self.raw(v);
        }
        let rows = output::rows(v);
        if rows.is_empty() {
            self.io.eprintln("No results.");
            return Ok(());
        }
        let t = output::table(&rows, cols, f);
        self.io.println(&t);
        Ok(())
    }

    /// The old per-command `--json` output: a bare array of the list's
    /// rows (no `{"data": …}` envelope), optionally reshaped to the keys
    /// the pre-API CLI printed. Scripts doing `jq '.[0]'` keep working.
    pub fn legacy_json(
        &mut self,
        v: &Value,
        map: Option<&dyn Fn(&Value) -> Value>,
    ) -> anyhow::Result<()> {
        let rows: Vec<Value> = output::rows(v)
            .into_iter()
            .map(|r| map.map_or_else(|| r.clone(), |f| f(r)))
            .collect();
        let s = output::structured(&Value::Array(rows), Format::Json)?;
        self.io.println(&s);
        Ok(())
    }

    /// Like [`Self::list`] but each row is reshaped by `f` for the table
    /// (computed columns); json/yaml still get the API's response as-is.
    pub fn list_mapped(
        &mut self,
        v: &Value,
        cols: &[Col],
        f: impl Fn(&Value) -> Value,
    ) -> anyhow::Result<()> {
        if self.format().is_structured() {
            return self.raw(v);
        }
        let mapped: Vec<Value> = output::rows(v).into_iter().map(f).collect();
        self.list(&Value::Array(mapped), cols)
    }

    /// Print one object as `label: value` lines, or the raw JSON/YAML.
    pub fn detail(&mut self, v: &Value, fields: &[(&str, &str)]) -> anyhow::Result<()> {
        if self.format().is_structured() {
            return self.raw(v);
        }
        let d = output::detail(output::item(v), fields);
        self.io.println(&d);
        Ok(())
    }

    /// Print the response's `message` (or `fallback`) for tables; the raw
    /// response for json/yaml.
    pub fn message(&mut self, v: &Value, fallback: &str) -> anyhow::Result<()> {
        if self.format().is_structured() {
            let v = if v.is_null() {
                serde_json::json!({ "message": fallback })
            } else {
                v.clone()
            };
            return self.raw(&v);
        }
        let msg = v
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or(fallback)
            .to_string();
        self.io.println(&msg);
        Ok(())
    }

    /// Like [`Self::message`], for service start/stop/validate endpoints
    /// that answer 200 with a failure message: print it, then fail.
    pub fn service_message(&mut self, v: &Value, fallback: &str) -> anyhow::Result<()> {
        self.message(v, fallback)?;
        let msg = v.get("message").and_then(Value::as_str).unwrap_or_default();
        if message_reports_failure(msg) {
            return Err(super::exit::CliError::CheckFailed(msg.to_string()).into());
        }
        Ok(())
    }

    /// Raw JSON/YAML (json for table formats too — used by `get` commands
    /// whose output has no natural table).
    pub fn raw(&mut self, v: &Value) -> anyhow::Result<()> {
        let f = if self.format() == Format::Yaml {
            Format::Yaml
        } else {
            Format::Json
        };
        let s = output::structured(v, f)?;
        self.io.println(&s);
        Ok(())
    }

    // ---- prompts ------------------------------------------------------

    /// Confirm a destructive action; `yes` is the command's `--yes`.
    pub fn confirm(&mut self, question: &str, yes: bool) -> anyhow::Result<()> {
        let no_input = self.g.no_input;
        prompt::require(&mut self.io, question, yes, no_input, "--yes")
    }
}

/// Service endpoints that answer 200 even when the action failed phrase it
/// as "Failed to …", "<thing> failed: …" or "Configuration invalid: …".
pub fn message_reports_failure(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.starts_with("failed")
        || lower.contains(" failed")
        || lower.starts_with("configuration invalid")
        || lower.starts_with("partial reload")
        || lower.starts_with("unknown backend")
        || lower.contains("unavailable")
}

#[cfg(test)]
mod tests {
    use super::message_reports_failure;

    #[test]
    fn soft_failures() {
        assert!(message_reports_failure("DHCP start failed: exit 1"));
        assert!(message_reports_failure("Failed to run validation: x"));
        assert!(message_reports_failure("Configuration invalid: line 3"));
        assert!(!message_reports_failure("DHCP started"));
        assert!(!message_reports_failure("Configuration valid"));
        assert!(message_reports_failure("config generation failed (2)"));
        assert!(message_reports_failure("database unavailable"));
        assert!(message_reports_failure("Failed to release 10.0.0.9: x"));
        assert!(message_reports_failure("pkg upgrade failed: no network"));
        assert!(!message_reports_failure("Lease 10.0.0.9 released"));
    }
}
