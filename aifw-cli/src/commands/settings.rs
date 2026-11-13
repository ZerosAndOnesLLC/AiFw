//! `aifw settings …` — appliance settings sections, auth policy, OAuth
//! providers and AI providers, via the API.

use clap::Subcommand;
use serde_json::{Map, Value, json};

use super::resource::{Coll, Resource};
use crate::cli::exit::CliError;
use crate::cli::{Ctx, col};

#[derive(Debug, Subcommand)]
pub enum SettingsCmd {
    /// Show a section (tls, valkey, dashboard-history, ids-alerts, pf-tuning, ai, syslog,
    /// log-rotation, or any key/value section such as metrics)
    Get { section: String },
    /// Change a section: key=value pairs and/or -f file (JSON/YAML)
    Set {
        section: String,
        values: Vec<String>,
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Login policy (token lifetimes, 2FA requirement, lockout)
    Auth { values: Vec<String> },
    /// OAuth / SSO login providers
    OauthProviders(Coll),
    /// Public URL used for OAuth callbacks
    OauthUrl { url: Option<String> },
    /// Models an AI provider offers
    AiModels { provider: String },
    /// Check an AI provider's endpoint and key
    AiTest { provider: String },
}

/// `key=value` pairs → JSON; values parse as JSON when they can
/// (numbers, booleans, arrays), else stay strings.
pub fn kv_pairs(pairs: &[String]) -> Result<Map<String, Value>, CliError> {
    let mut m = Map::new();
    for p in pairs {
        let (k, v) = p
            .split_once('=')
            .ok_or_else(|| CliError::Usage(format!("expected key=value, got '{p}'")))?;
        let val = serde_json::from_str::<Value>(v).unwrap_or_else(|_| json!(v));
        m.insert(k.trim().to_string(), val);
    }
    Ok(m)
}

/// Sections whose PUT replaces the whole object: send current + changes.
const FULL_REPLACE: &[&str] = &["syslog", "log-rotation", "pf-tuning"];

pub async fn run(ctx: &mut Ctx, cmd: SettingsCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    match cmd {
        SettingsCmd::Get { section } => {
            ctx.raw(&client.get(&format!("/settings/{section}")).await?)
        }
        SettingsCmd::Set {
            section,
            values,
            file,
        } => {
            let mut body = Value::Object(Map::new());
            if FULL_REPLACE.contains(&section.as_str()) {
                body = client.get(&format!("/settings/{section}")).await?;
                if section == "log-rotation" {
                    body = body["config"].clone();
                }
            }
            if let Some(f) = file {
                let patch = crate::cli::body::read(&mut ctx.io, &f)?;
                crate::cli::body::merge(&mut body, &patch);
            }
            let kv = kv_pairs(&values)?;
            if kv.is_empty() && body.as_object().is_some_and(Map::is_empty) {
                return Err(CliError::Usage(
                    "nothing to change: pass key=value pairs or -f file".into(),
                )
                .into());
            }
            crate::cli::body::merge(&mut body, &Value::Object(kv));
            let v = client.put(&format!("/settings/{section}"), &body).await?;
            ctx.message(&v, &format!("{section} settings saved"))
        }
        SettingsCmd::Auth { values } => {
            if values.is_empty() {
                return ctx.raw(&client.get("/auth/settings").await?);
            }
            let v = client
                .put("/auth/settings", &Value::Object(kv_pairs(&values)?))
                .await?;
            ctx.message(&v, "Auth settings updated")?;
            if !ctx.format().is_structured() {
                ctx.io.eprintln(
                    "Note: `aifw settings auth` shows the running values until the API restarts.",
                );
            }
            Ok(())
        }
        SettingsCmd::OauthProviders(c) => {
            let r = Resource {
                path: "/auth/oauth/providers".into(),
                what: "OAuth provider",
                cols: vec![
                    col("ID", "/id"),
                    col("NAME", "/name"),
                    col("TYPE", "/provider_type"),
                    col("CLIENT ID", "/client_id"),
                    col("ENABLED", "/enabled"),
                ],
            };
            super::resource::coll(ctx, &client, &r, c).await
        }
        SettingsCmd::OauthUrl { url } => {
            let v = match url {
                Some(u) => {
                    client
                        .put("/auth/oauth/settings", &json!({ "public_url": u }))
                        .await?
                }
                None => client.get("/auth/oauth/settings").await?,
            };
            ctx.raw(&v)
        }
        SettingsCmd::AiModels { provider } => {
            let v = client
                .get(&format!("/settings/ai/models?provider={provider}"))
                .await?;
            if let Some(e) = v["error"].as_str() {
                return Err(CliError::CheckFailed(e.to_string()).into());
            }
            if ctx.format().is_structured() {
                return ctx.raw(&v);
            }
            for m in v["models"].as_array().into_iter().flatten() {
                ctx.io.println(m.as_str().unwrap_or_default());
            }
            Ok(())
        }
        SettingsCmd::AiTest { provider } => {
            let v = client
                .post("/settings/ai/test", &json!({ "provider": provider }))
                .await?;
            ctx.raw(&v)?;
            if v["success"] != json!(true) {
                return Err(CliError::CheckFailed(
                    v["error"]
                        .as_str()
                        .unwrap_or("AI provider test failed")
                        .to_string(),
                )
                .into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kv_values_parse_as_json_when_possible() {
        let m = kv_pairs(&[
            "a=1".into(),
            "b=true".into(),
            "c=hello".into(),
            "d=[1,2]".into(),
            "e=".into(),
        ])
        .unwrap();
        assert_eq!(m["a"], json!(1));
        assert_eq!(m["b"], json!(true));
        assert_eq!(m["c"], json!("hello"));
        assert_eq!(m["d"], json!([1, 2]));
        assert_eq!(m["e"], json!(""));
        assert!(kv_pairs(&["nope".into()]).is_err());
    }
}
