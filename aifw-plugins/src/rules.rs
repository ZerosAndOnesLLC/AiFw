//! pf rules owned by plugins. Every plugin's rules are rendered together
//! into one anchor ([`aifw_common::anchors::PLUGINS`]) that pf.conf hooks
//! ahead of the other filter anchors. Plugins may only contribute `block`
//! and `match` rules that reference their own `plugin_*` tables — they can
//! drop or log traffic, never open a hole, redirect, re-route or tag it.
//! [`check_rule`] is the gate; every escape it closes has a test in
//! `tests.rs`.

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

/// Keywords that would let a plugin rule pass, redirect, translate,
/// re-route, shape, tag or nest rules — none of which a plugin may do.
const FORBIDDEN_TOKENS: &[&str] = &[
    "pass",
    "anchor",
    "load",
    "include",
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
    "rtable",
    "dnpipe",
    "dnqueue",
    "queue",
    "prio",
    "tag",
    "tagged",
    "scrub",
    "antispoof",
    "altq",
];

/// Characters pf treats as token separators besides whitespace.
const SEPARATORS: &[char] = &['(', ')', '{', '}', ',', '/'];

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

/// Strip the one quoted string a rule may carry — its `label "…"` — and
/// return the rule without it. Any other quote, or a label text that could
/// smuggle a table reference, is refused.
fn strip_label(rule: &str) -> std::result::Result<String, &'static str> {
    let Some(open) = rule.find('"') else {
        return Ok(rule.to_string());
    };
    let before = &rule[..open];
    if before.split_whitespace().next_back() != Some("label") {
        return Err("quoted text is only allowed as a label");
    }
    let after = &rule[open + 1..];
    let Some(close) = after.find('"') else {
        return Err("unterminated label");
    };
    let text = &after[..close];
    if text.contains(['<', '>']) {
        return Err("label text must not contain a table reference");
    }
    let rest = &after[close + 1..];
    if rest.contains('"') {
        return Err("only one label is allowed");
    }
    Ok(format!("{before}{rest}"))
}

/// Validate one plugin-supplied pf rule.
///
/// A rule must start with `block` or `match`, may carry one `label "…"`,
/// must not use negation, comments or any keyword that passes, redirects,
/// translates, routes, shapes or tags traffic, and must reference at least
/// one `plugin_*` table in a `from` / `to` position. Tokens are split on
/// pf's own separators, so `nat-to(em0)` is caught as well as `nat-to (em0)`.
pub fn check_rule(rule: &str) -> Result<()> {
    let deny = |why: &str| Err(PluginError::Rule(format!("{why}: {rule}")));
    if rule.len() > MAX_RULE_LEN {
        return deny("too long");
    }
    if rule
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ';' | '`' | '$' | '#' | '!' | '\''))
    {
        return deny("illegal character");
    }
    let stripped = match strip_label(rule) {
        Ok(s) => s,
        Err(why) => return deny(why),
    };
    let tokens: Vec<&str> = stripped
        .split(|c: char| c.is_whitespace() || SEPARATORS.contains(&c))
        .filter(|t| !t.is_empty())
        .collect();
    match tokens.first() {
        Some(&"block") | Some(&"match") => {}
        _ => return deny("must start with 'block' or 'match'"),
    }
    let mut tables = 0;
    // A table may follow `from` / `to`, or another table inside a
    // `from { <a> <b> }` list.
    let mut address_position = false;
    for t in &tokens {
        if FORBIDDEN_TOKENS.contains(t) {
            return deny("forbidden keyword");
        }
        if t.contains(['<', '>']) {
            let Some(name) = t.strip_prefix('<').and_then(|n| n.strip_suffix('>')) else {
                return deny("malformed table reference");
            };
            if !address_position {
                return deny("table reference must follow 'from' or 'to'");
            }
            check_table_name(name)?;
            tables += 1;
            continue;
        }
        address_position = matches!(*t, "from" | "to");
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
            return Err(PluginError::Rule(format!(
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
        res.map_err(|e| PluginError::Rule(e.to_string()))
    }
}
