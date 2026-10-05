//! Typed plugin settings. A plugin declares its settings as a list of
//! [`SettingField`]s; the store validates every write against that schema,
//! the UI renders a form from it, and the CLI uses it to parse `key=value`.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::net::IpAddr;

use crate::error::{PluginError, Result};

/// One selectable option of a `Select` / `MultiSelect` field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectOption {
    /// Stored value
    pub value: String,
    /// Human-readable label
    pub label: String,
    /// Optional longer description shown next to the option
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
}

impl SelectOption {
    /// Option whose label is shown verbatim.
    pub fn new(value: &str, label: &str) -> Self {
        Self {
            value: value.to_string(),
            label: label.to_string(),
            help: None,
        }
    }

    /// Attach a description to the option.
    pub fn help(mut self, help: &str) -> Self {
        self.help = Some(help.to_string());
        self
    }
}

/// Element type of a `List` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListItem {
    /// IP address or CIDR prefix
    Cidr,
    /// http(s) URL
    Url,
    /// Free text
    Text,
}

/// The value type of a setting, with its constraints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldKind {
    /// true / false
    Bool,
    /// Whole number within `[min, max]`
    Integer {
        /// Inclusive lower bound
        min: i64,
        /// Inclusive upper bound
        max: i64,
    },
    /// Free text up to `max_len` characters
    Text {
        /// Maximum length in characters
        max_len: usize,
    },
    /// http(s) URL
    Url {
        /// Reject plain `http://`
        https_only: bool,
    },
    /// Exactly one of `options`
    Select {
        /// Allowed values
        options: Vec<SelectOption>,
    },
    /// Any subset of `options`
    MultiSelect {
        /// Allowed values
        options: Vec<SelectOption>,
    },
    /// List of items of one type
    List {
        /// Element type
        item: ListItem,
        /// Maximum number of items
        max_items: usize,
    },
}

/// Show a field only when another field has a given value (UI hint only;
/// validation always applies).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VisibleIf {
    /// Key of the controlling field
    pub key: String,
    /// Value the controlling field must have
    pub equals: Value,
}

/// One plugin setting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingField {
    /// Settings key
    pub key: String,
    /// Form label
    pub label: String,
    /// Help text shown under the input
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    /// Value type and constraints
    pub kind: FieldKind,
    /// Value used when the operator hasn't set one (`null` = unset)
    pub default: Value,
    /// Secret values are sealed at rest and never returned by the API.
    pub secret: bool,
    /// Form section the field belongs to
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// UI visibility condition
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_if: Option<VisibleIf>,
}

impl SettingField {
    fn new(key: &str, label: &str, kind: FieldKind, default: Value) -> Self {
        Self {
            key: key.to_string(),
            label: label.to_string(),
            help: None,
            kind,
            default,
            secret: false,
            group: None,
            visible_if: None,
        }
    }

    /// Boolean switch.
    pub fn bool(key: &str, label: &str, default: bool) -> Self {
        Self::new(key, label, FieldKind::Bool, Value::Bool(default))
    }

    /// Integer in `[min, max]`.
    pub fn integer(key: &str, label: &str, min: i64, max: i64, default: i64) -> Self {
        Self::new(
            key,
            label,
            FieldKind::Integer { min, max },
            Value::from(default),
        )
    }

    /// Single-line text, empty by default.
    pub fn text(key: &str, label: &str, max_len: usize) -> Self {
        Self::new(key, label, FieldKind::Text { max_len }, Value::Null)
    }

    /// URL, empty by default.
    pub fn url(key: &str, label: &str, https_only: bool) -> Self {
        Self::new(key, label, FieldKind::Url { https_only }, Value::Null)
    }

    /// One-of select.
    pub fn select(key: &str, label: &str, options: Vec<SelectOption>, default: &str) -> Self {
        Self::new(
            key,
            label,
            FieldKind::Select { options },
            Value::String(default.to_string()),
        )
    }

    /// Any-of select.
    pub fn multi_select(
        key: &str,
        label: &str,
        options: Vec<SelectOption>,
        default: &[&str],
    ) -> Self {
        Self::new(
            key,
            label,
            FieldKind::MultiSelect { options },
            Value::Array(default.iter().map(|s| Value::from(*s)).collect()),
        )
    }

    /// List of items, empty by default.
    pub fn list(key: &str, label: &str, item: ListItem, max_items: usize) -> Self {
        Self::new(
            key,
            label,
            FieldKind::List { item, max_items },
            Value::Array(Vec::new()),
        )
    }

    /// Set help text.
    pub fn help(mut self, help: &str) -> Self {
        self.help = Some(help.to_string());
        self
    }

    /// Mark as secret (sealed at rest, write-only through the API).
    pub fn secret(mut self) -> Self {
        self.secret = true;
        self
    }

    /// Place the field in a form section.
    pub fn group(mut self, group: &str) -> Self {
        self.group = Some(group.to_string());
        self
    }

    /// Only show the field when `key == equals`.
    pub fn visible_if(mut self, key: &str, equals: impl Into<Value>) -> Self {
        self.visible_if = Some(VisibleIf {
            key: key.to_string(),
            equals: equals.into(),
        });
        self
    }
}

/// Effective, validated settings handed to a plugin: every schema key is
/// present (operator value or default), secrets included in plaintext.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PluginSettings(Map<String, Value>);

impl PluginSettings {
    /// Wrap a raw map without validation (tests, internal use).
    pub fn from_map(map: Map<String, Value>) -> Self {
        Self(map)
    }

    /// The underlying map.
    pub fn into_map(self) -> Map<String, Value> {
        self.0
    }

    /// Raw value for `key`.
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }

    /// String value; `None` if unset, empty, or not a string.
    pub fn str(&self, key: &str) -> Option<&str> {
        self.0
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    }

    /// Integer value.
    pub fn i64(&self, key: &str) -> Option<i64> {
        self.0.get(key).and_then(Value::as_i64)
    }

    /// Boolean value (`false` when unset).
    pub fn bool(&self, key: &str) -> bool {
        self.0.get(key).and_then(Value::as_bool).unwrap_or(false)
    }

    /// List of strings (MultiSelect / List fields); empty when unset.
    pub fn strings(&self, key: &str) -> Vec<String> {
        self.0
            .get(key)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn invalid(field: &SettingField, msg: impl std::fmt::Display) -> PluginError {
    PluginError::Validation(format!("{}: {msg}", field.label))
}

/// Parse and check an http(s) URL string.
fn check_url(field: &SettingField, s: &str, https_only: bool) -> Result<()> {
    let lower = s.to_ascii_lowercase();
    let ok_scheme = lower.starts_with("https://") || (!https_only && lower.starts_with("http://"));
    if !ok_scheme {
        return Err(invalid(
            field,
            if https_only {
                "must be an https:// URL"
            } else {
                "must be an http:// or https:// URL"
            },
        ));
    }
    if s.len() > 2048 || s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(field, "is not a valid URL"));
    }
    let host = s
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or(""))
        .unwrap_or("");
    if host.is_empty() {
        return Err(invalid(field, "URL has no host"));
    }
    Ok(())
}

/// Parse an IP address or CIDR prefix (`1.2.3.4`, `10.0.0.0/8`, `2001:db8::/32`).
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let s = s.trim();
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(l) => l.parse::<u8>().ok().filter(|l| *l <= max)?,
        None => max,
    };
    Some((ip, len))
}

fn check_value(field: &SettingField, v: &Value) -> Result<Value> {
    match &field.kind {
        FieldKind::Bool => v
            .as_bool()
            .map(Value::Bool)
            .ok_or_else(|| invalid(field, "must be true or false")),
        FieldKind::Integer { min, max } => {
            let n = v
                .as_i64()
                .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
                .ok_or_else(|| invalid(field, "must be a whole number"))?;
            if n < *min || n > *max {
                return Err(invalid(field, format!("must be between {min} and {max}")));
            }
            Ok(Value::from(n))
        }
        FieldKind::Text { max_len } => {
            let s = v.as_str().ok_or_else(|| invalid(field, "must be text"))?;
            if s.chars().count() > *max_len {
                return Err(invalid(
                    field,
                    format!("must be at most {max_len} characters"),
                ));
            }
            if s.chars().any(|c| c.is_control()) {
                return Err(invalid(field, "must not contain control characters"));
            }
            Ok(Value::String(s.trim().to_string()))
        }
        FieldKind::Url { https_only } => {
            let s = v
                .as_str()
                .ok_or_else(|| invalid(field, "must be a URL"))?
                .trim();
            if !s.is_empty() {
                check_url(field, s, *https_only)?;
            }
            Ok(Value::String(s.to_string()))
        }
        FieldKind::Select { options } => {
            let s = v.as_str().ok_or_else(|| invalid(field, "must be text"))?;
            if !options.iter().any(|o| o.value == s) {
                return Err(invalid(field, format!("'{s}' is not an allowed value")));
            }
            Ok(Value::String(s.to_string()))
        }
        FieldKind::MultiSelect { options } => {
            let arr = v
                .as_array()
                .ok_or_else(|| invalid(field, "must be a list"))?;
            let mut out: Vec<Value> = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item
                    .as_str()
                    .ok_or_else(|| invalid(field, "must be a list of text values"))?;
                if !options.iter().any(|o| o.value == s) {
                    return Err(invalid(field, format!("'{s}' is not an allowed value")));
                }
                if !out.iter().any(|o| o.as_str() == Some(s)) {
                    out.push(Value::from(s));
                }
            }
            Ok(Value::Array(out))
        }
        FieldKind::List { item, max_items } => {
            let arr = v
                .as_array()
                .ok_or_else(|| invalid(field, "must be a list"))?;
            let mut out: Vec<Value> = Vec::with_capacity(arr.len());
            for entry in arr {
                let s = entry
                    .as_str()
                    .ok_or_else(|| invalid(field, "must be a list of text values"))?
                    .trim();
                if s.is_empty() {
                    continue;
                }
                match item {
                    ListItem::Cidr => {
                        if parse_cidr(s).is_none() {
                            return Err(invalid(
                                field,
                                format!("'{s}' is not an IP address or CIDR"),
                            ));
                        }
                    }
                    ListItem::Url => check_url(field, s, false)?,
                    ListItem::Text => {
                        if s.len() > 1024 || s.chars().any(|c| c.is_control()) {
                            return Err(invalid(field, format!("'{s}' is not valid")));
                        }
                    }
                }
                if !out.iter().any(|o| o.as_str() == Some(s)) {
                    out.push(Value::from(s));
                }
            }
            if out.len() > *max_items {
                return Err(invalid(field, format!("at most {max_items} entries")));
            }
            Ok(Value::Array(out))
        }
    }
}

/// Validate operator-supplied `values` (non-secret) and `secrets` against
/// `schema`. Returns the normalized stored forms (only keys the operator
/// set) — defaults are *not* baked in, so a plugin upgrade that changes a
/// default reaches every install that never overrode it.
pub fn normalize(
    schema: &[SettingField],
    values: &Map<String, Value>,
    secrets: &Map<String, Value>,
) -> Result<(Map<String, Value>, Map<String, Value>)> {
    for key in values.keys().chain(secrets.keys()) {
        if !schema.iter().any(|f| &f.key == key) {
            return Err(PluginError::Validation(format!("unknown setting '{key}'")));
        }
    }
    let mut out_values = Map::new();
    let mut out_secrets = Map::new();
    for field in schema {
        let (src, dst, wrong) = if field.secret {
            (secrets, &mut out_secrets, values)
        } else {
            (values, &mut out_values, secrets)
        };
        if wrong.contains_key(&field.key) {
            return Err(invalid(
                field,
                if field.secret {
                    "is a secret; set it through `secrets`"
                } else {
                    "is not a secret"
                },
            ));
        }
        match src.get(&field.key) {
            None | Some(Value::Null) => {}
            Some(v) => {
                dst.insert(field.key.clone(), check_value(field, v)?);
            }
        }
    }
    Ok((out_values, out_secrets))
}

/// Merge stored values + secrets over the schema defaults into the
/// effective settings a plugin receives. Stored values that no longer fit
/// the schema (plugin upgraded) fall back to the default.
pub fn effective(
    schema: &[SettingField],
    values: &Map<String, Value>,
    secrets: &Map<String, Value>,
) -> PluginSettings {
    let mut out = Map::new();
    for field in schema {
        let src = if field.secret { secrets } else { values };
        let v = src
            .get(&field.key)
            .and_then(|v| check_value(field, v).ok())
            .unwrap_or_else(|| field.default.clone());
        out.insert(field.key.clone(), v);
    }
    PluginSettings(out)
}
