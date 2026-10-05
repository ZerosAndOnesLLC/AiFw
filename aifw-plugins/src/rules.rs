//! pf rules owned by plugins. Every plugin's rules are rendered together
//! into one anchor ([`aifw_common::anchors::PLUGINS`]) that pf.conf hooks
//! ahead of the other filter anchors. Plugins may only contribute `block`
//! and `match` rules that reference their own `plugin_*` tables — they can
//! drop or log traffic, never open a hole or redirect it.

use std::collections::BTreeMap;
use std::sync::Arc;

use aifw_pf::PfBackend;
use tokio::sync::Mutex;

use crate::error::{PluginError, Result};

/// Prefix every plugin-managed pf table must carry.
pub const TABLE_PREFIX: &str = "plugin_";

/// pf limits table names to 31 characters (PF_TABLE_NAME_SIZE - 1).
const MAX_TABLE_NAME: usize = 31;

const MAX_RULE_LEN: usize = 512;
const MAX_RULES_PER_PLUGIN: usize = 32;

/// Keywords that would let a plugin rule pass, redirect, translate, or
/// nest rules — none of which a plugin may do.
const FORBIDDEN_TOKENS: &[&str] = &[
    "pass",
    "anchor",
    "load",
    "table",
    "nat",
    "rdr",
    "binat",
    "nat-to",
    "rdr-to",
    "binat-to",
    "route-to",
    "reply-to",
    "dup-to",
    "af-to",
    "divert-to",
    "divert-reply",
    "set",
];

/// Check a pf table name a plugin wants to touch.
pub fn check_table_name(table: &str) -> Result<()> {
    let ok = table.starts_with(TABLE_PREFIX)
        && table.len() > TABLE_PREFIX.len()
        && table.len() <= MAX_TABLE_NAME
        && table
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(PluginError::Table(format!(
            "table '{table}' is not allowed: plugins may only use tables named \
             '{TABLE_PREFIX}<name>' ([A-Za-z0-9_], max {MAX_TABLE_NAME} chars)"
        )))
    }
}

/// Validate one plugin-supplied pf rule.
pub fn check_rule(rule: &str) -> Result<()> {
    let deny = |why: &str| Err(PluginError::Table(format!("rule rejected ({why}): {rule}")));
    if rule.len() > MAX_RULE_LEN {
        return deny("too long");
    }
    if rule
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ';' | '`' | '$'))
    {
        return deny("illegal character");
    }
    let mut tokens = rule.split_whitespace();
    match tokens.next() {
        Some("block") | Some("match") => {}
        _ => return deny("must start with 'block' or 'match'"),
    }
    if rule
        .split_whitespace()
        .any(|t| FORBIDDEN_TOKENS.contains(&t))
    {
        return deny("forbidden keyword");
    }
    let mut tables = 0;
    let mut rest = rule;
    while let Some(start) = rest.find('<') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('>') else {
            return deny("unterminated table reference");
        };
        check_table_name(&after[..end])?;
        tables += 1;
        rest = &after[end + 1..];
    }
    if tables == 0 {
        return deny("must reference a plugin_ table");
    }
    Ok(())
}

/// Collects every plugin's rules and loads them into the shared anchor.
pub struct RuleSink {
    pf: Arc<dyn PfBackend>,
    anchor: String,
    rules: Mutex<BTreeMap<String, Vec<String>>>,
}

impl RuleSink {
    /// Sink writing into `anchor`.
    pub fn new(pf: Arc<dyn PfBackend>, anchor: &str) -> Self {
        Self {
            pf,
            anchor: anchor.to_string(),
            rules: Mutex::new(BTreeMap::new()),
        }
    }

    /// Anchor the sink renders into.
    pub fn anchor(&self) -> &str {
        &self.anchor
    }

    /// Replace `plugin`'s rules (validated) and reload the anchor.
    pub async fn set(&self, plugin: &str, rules: Vec<String>) -> Result<()> {
        if rules.len() > MAX_RULES_PER_PLUGIN {
            return Err(PluginError::Table(format!(
                "at most {MAX_RULES_PER_PLUGIN} rules per plugin"
            )));
        }
        for r in &rules {
            check_rule(r)?;
        }
        let mut all = self.rules.lock().await;
        if rules.is_empty() {
            if all.remove(plugin).is_none() {
                return Ok(());
            }
        } else {
            all.insert(plugin.to_string(), rules);
        }
        self.load(&all).await
    }

    /// Render the current rule set into pf (boot / heal).
    pub async fn reload(&self) -> Result<()> {
        let all = self.rules.lock().await;
        self.load(&all).await
    }

    /// Rules currently contributed by `plugin`.
    pub async fn rules_of(&self, plugin: &str) -> Vec<String> {
        self.rules
            .lock()
            .await
            .get(plugin)
            .cloned()
            .unwrap_or_default()
    }

    async fn load(&self, all: &BTreeMap<String, Vec<String>>) -> Result<()> {
        let flat: Vec<String> = all.values().flatten().cloned().collect();
        let res = if flat.is_empty() {
            self.pf.flush_rules(&self.anchor).await
        } else {
            self.pf.load_rules(&self.anchor, &flat).await
        };
        res.map_err(|e| PluginError::Table(e.to_string()))
    }
}
