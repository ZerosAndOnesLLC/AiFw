//! Upgrade-time healing of `pf.conf.aifw`. aifw-setup only writes the
//! anchor hooks into newly generated files, so hooks added in later
//! releases must be patched into existing appliances. The text transform
//! is pure (tested here); `ensure_rdr_anchor` in main.rs validates and
//! commits the result.

use aifw_common::anchors;

/// ICMPv6 neighbor discovery pass (#601). Must precede the first filter
/// anchor, whose `block quick` rules would otherwise eat ND.
pub const ND_RULE: &str =
    "pass quick inet6 proto icmp6 icmp6-type { routersol, routeradv, neighbrsol, neighbradv }";

fn hook(anchor: &str) -> String {
    format!("anchor \"{anchor}\"")
}

/// Insert every missing AiFw hook into `content`. Returns `None` when
/// nothing needs to change.
///
/// - `rdr-anchor "aifw-nat"` after `nat-anchor "aifw-nat"`
/// - the ND pass rule, then `anchor "aifw-plugins"`, before the first
///   filter anchor (plugin `block quick` rules must run before the
///   multi-WAN `pass quick` policy routes)
/// - the multi-WAN anchors before `anchor "aifw"`
/// - the filter-class `anchor "aifw-nat"` after `anchor "aifw"` (#531)
pub fn patch_pf_conf(content: &str) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let has = |wanted: &str| lines.iter().any(|l| l.trim() == wanted);

    let has_rdr = has("rdr-anchor \"aifw-nat\"");
    let has_nat_filter = has(&hook(anchors::NAT));
    let has_nd = has(ND_RULE);
    let has_plugins = has(&hook(anchors::PLUGINS));
    let mwan_anchors = [anchors::PBR, anchors::MWAN_LEAK, anchors::MWAN_REPLY];
    let has_mwan: Vec<bool> = mwan_anchors.iter().map(|a| has(&hook(a))).collect();
    let filter_hooks: Vec<String> = anchors::FILTER_HOOKS
        .iter()
        .filter(|a| **a != anchors::PLUGINS)
        .map(|a| hook(a))
        .collect();

    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 8);
    let mut changed = false;
    let mut first_filter_seen = false;
    let mut mwan_inserted = false;

    for line in &lines {
        let t = line.trim();

        if t == "nat-anchor \"aifw-nat\"" {
            out.push((*line).to_string());
            if !has_rdr {
                out.push("rdr-anchor \"aifw-nat\"".to_string());
                changed = true;
            }
            continue;
        }

        // Exact match on the trimmed line — never nat-anchor / rdr-anchor.
        if !first_filter_seen && filter_hooks.iter().any(|h| t == h) {
            first_filter_seen = true;
            if !has_nd {
                out.push(ND_RULE.to_string());
                changed = true;
            }
            if !has_plugins {
                out.push(hook(anchors::PLUGINS));
                changed = true;
            }
        }

        if !mwan_inserted && t == hook(anchors::FILTER) {
            for (i, a) in mwan_anchors.iter().enumerate() {
                if !has_mwan[i] {
                    out.push(hook(a));
                    changed = true;
                }
            }
            mwan_inserted = true;
            out.push((*line).to_string());
            if !has_nat_filter {
                out.push(hook(anchors::NAT));
                changed = true;
            }
            continue;
        }

        out.push((*line).to_string());
    }

    changed.then(|| out.join("\n") + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pf.conf as current aifw-setup writes it.
    fn current() -> String {
        let mut s =
            String::from("nat-anchor \"aifw\"\nnat-anchor \"aifw-nat\"\nrdr-anchor \"aifw-nat\"\n");
        s.push_str(ND_RULE);
        s.push('\n');
        for a in anchors::FILTER_HOOKS {
            s.push_str(&hook(a));
            s.push('\n');
        }
        s.push_str("block in log all\n");
        s
    }

    #[test]
    fn current_file_is_left_alone() {
        assert_eq!(patch_pf_conf(&current()), None);
    }

    #[test]
    fn plugins_hook_added_before_first_filter_anchor() {
        let old = current().replace("anchor \"aifw-plugins\"\n", "");
        let patched = patch_pf_conf(&old).expect("must patch");
        let pos = |needle: &str| patched.find(needle).unwrap();
        assert!(pos(ND_RULE) < pos("anchor \"aifw-plugins\""));
        assert!(pos("anchor \"aifw-plugins\"") < pos("anchor \"aifw-pbr\""));
        assert_eq!(patched.matches("anchor \"aifw-plugins\"").count(), 1);
        // Idempotent.
        assert_eq!(patch_pf_conf(&patched), None);
    }

    #[test]
    fn very_old_file_gets_every_hook() {
        let old = "nat-anchor \"aifw\"\nnat-anchor \"aifw-nat\"\n\
                   anchor \"aifw\"\nanchor \"aifw-vpn\"\nblock in log all\n";
        let patched = patch_pf_conf(old).expect("must patch");
        let order = [
            "rdr-anchor \"aifw-nat\"",
            ND_RULE,
            "anchor \"aifw-plugins\"",
            "anchor \"aifw-pbr\"",
            "anchor \"aifw-mwan-leak\"",
            "anchor \"aifw-mwan-reply\"",
            "anchor \"aifw\"\n",
            "anchor \"aifw-nat\"\n",
        ];
        let mut last = 0;
        for needle in order {
            let p = patched[last..]
                .find(needle)
                .unwrap_or_else(|| panic!("{needle} missing or out of order"))
                + last;
            last = p;
        }
        assert_eq!(patch_pf_conf(&patched), None);
    }

    #[test]
    fn nat_anchor_lines_are_not_filter_anchors() {
        // A file with no filter anchors at all must not get the plugin hook
        // stuffed next to the nat-anchor lines.
        let only_nat = "nat-anchor \"aifw\"\nnat-anchor \"aifw-nat\"\nrdr-anchor \"aifw-nat\"\n";
        assert_eq!(patch_pf_conf(only_nat), None);
    }
}
