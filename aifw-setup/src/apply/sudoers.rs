//! The narrow sudoers grants for the `aifw` service user (+ guard tests).

/// The sudoers content AiFw writes to
/// `/usr/local/etc/sudoers.d/aifw`. Exposed as a function so a unit
/// test can validate the structure and CI can pipe the same content
/// into `visudo -cf -` for FreeBSD-side syntax checking.
///
/// **When adding a line**: keep the format `aifw ALL=(<runas>) NOPASSWD:
/// <command> [args...]`. Both `(root)` and `(ALL)` are accepted; the
/// structural test in `tests` below enforces this shape.
// dead_code on Linux dev builds: only the FreeBSD-gated apply() path
// + the cfg(test) checks reference this. Linux release builds don't
// touch it.
#[cfg_attr(not(target_os = "freebsd"), allow(dead_code))]
pub fn sudoers_content() -> &'static str {
    "\
# --- pfctl (every form aifw-pf/aifw-core/aifw-api actually invokes) ---
# Anchors are always aifw-prefixed; pf table names and addresses are
# caller-supplied so those use wildcards. Each grant maps to a specific call
# site — keep in sync with the pfctl invocations in aifw-pf/src/ioctl.rs,
# aifw-core/src/pf_tuning.rs and aifw-api/src/main.rs. A test in apply/sudoers.rs
# (pfctl_sudoers_covers_invocations) guards against forms going missing
# (the SEC-C2 narrowing dropped `-ss -vv`, breaking the connection list).
# Per-anchor rule/NAT/queue load, flush and show. Rule/NAT/queue loads pipe
# via stdin (`-f -` / `-N -f -`) so no ruleset is ever staged in a
# world-writable /tmp file (SEC-H5); the old `-f /tmp/aifw_pf_*.conf` grants
# were removed with that fix.
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -f -
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -n -f -
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -N -f -
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -f /usr/local/etc/aifw/anchors/aifw*
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -sr
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -sn
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -sq
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -Fr
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -Fn
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -Fq
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -F all
# Global status reads (-ss -vv feeds the connection list / NAT flows page):
aifw ALL=(root) NOPASSWD: /sbin/pfctl -si
aifw ALL=(root) NOPASSWD: /sbin/pfctl -sr
# -sn (global): REQUIRED by the daemon's pf drift auto-heal
# (aifw-daemon reconcile_pf_main). FreeBSD pf_start occasionally leaves the
# main ruleset empty (anchors populate but the nat-anchor/anchor hooks are
# missing) → NAT/LAN silently breaks. reconcile_pf_main detects this via
# pfctl -sn and reloads pf.conf.aifw. If this grant is missing the check
# gets a password-required error, bails, and never heals -> LAN outage. Do
# NOT drop this (it was missing in v5.96.16 and caused a LAN-down regression).
aifw ALL=(root) NOPASSWD: /sbin/pfctl -sn
aifw ALL=(root) NOPASSWD: /sbin/pfctl -e
aifw ALL=(root) NOPASSWD: /sbin/pfctl -ss
aifw ALL=(root) NOPASSWD: /sbin/pfctl -ss -v
aifw ALL=(root) NOPASSWD: /sbin/pfctl -ss -vv
aifw ALL=(root) NOPASSWD: /sbin/pfctl -vvsI
# pf table management (aliases / geo-IP / plugin blocklists) — table name
# and address are caller-supplied:
aifw ALL=(root) NOPASSWD: /sbin/pfctl -t * -T add *
aifw ALL=(root) NOPASSWD: /sbin/pfctl -t * -T delete *
aifw ALL=(root) NOPASSWD: /sbin/pfctl -t * -T replace -f -
aifw ALL=(root) NOPASSWD: /sbin/pfctl -t * -T flush
aifw ALL=(root) NOPASSWD: /sbin/pfctl -t * -T show
# State kills — by rule label, by src/dst pair, by interface:
aifw ALL=(root) NOPASSWD: /sbin/pfctl -k label -k aifw*
aifw ALL=(root) NOPASSWD: /sbin/pfctl -k * -k *
aifw ALL=(root) NOPASSWD: /sbin/pfctl -k 0.0.0.0/0 -k 0.0.0.0/0 -i *
# pf.conf validate/load + tuning merge:
aifw ALL=(root) NOPASSWD: /sbin/pfctl -f /etc/pf.conf
aifw ALL=(root) NOPASSWD: /sbin/pfctl -f /usr/local/etc/aifw/pf.conf.aifw
aifw ALL=(root) NOPASSWD: /sbin/pfctl -nf /tmp/aifw_pf_*.conf
aifw ALL=(root) NOPASSWD: /sbin/pfctl -nf /tmp/aifw-pf.conf.aifw.patched
aifw ALL=(root) NOPASSWD: /sbin/pfctl -m -f /usr/local/etc/aifw/pf-tuning.conf

# --- shutdown (exact forms only; -p power-off or -r reboot with +10s grace) ---
aifw ALL=(root) NOPASSWD: /sbin/shutdown -p +10s *
aifw ALL=(root) NOPASSWD: /sbin/shutdown -r +10s *

# --- Narrow wrapper scripts (GHSA-mjqh-2vx8-7hq7 follow-up #204; SEC-C2) ---
# Each helper enforces its own internal allowlist of valid arguments —
# paths, services, interfaces, rcvars. Preferred over the broad grants
# below; the helpers exist on every v5.96+ box thanks to
# `ensure_libexec_scripts` embedding them.
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-write *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-wg *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-freebsd-update *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-pkg *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-service *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-chown *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-ifconfig *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-install *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-sysrc *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-dhclient *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-route *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-pkill *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-rm *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-mkdir *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-cp *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-tar *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-tcpdump *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-swanctl *
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-dummynet
aifw ALL=(root) NOPASSWD: /usr/local/libexec/aifw-sudo-newsyslog *

# --- Broad compat grants ---
# Kept alongside the narrow helpers above for upgrade compat: in-place
# tarball install from a pre-#204 appliance bootstraps via these grants
# (write_embedded_script falls back to `sudo /usr/bin/install` when the
# narrow helper isn't yet on disk). Operators who have completed the
# transition to narrow-only operation may strip these by hand. A future
# release will add an `aifw-setup --tighten-sudoers` command that removes
# them automatically once narrow-helper coverage is verified.
aifw ALL=(ALL) NOPASSWD: /sbin/dhclient *
aifw ALL=(ALL) NOPASSWD: /sbin/route *
aifw ALL=(ALL) NOPASSWD: /sbin/ifconfig *
aifw ALL=(ALL) NOPASSWD: /bin/cp *
aifw ALL=(ALL) NOPASSWD: /bin/rm *
aifw ALL=(ALL) NOPASSWD: /bin/mkdir *
aifw ALL=(ALL) NOPASSWD: /bin/pkill *
aifw ALL=(ALL) NOPASSWD: /usr/bin/pkill *
aifw ALL=(ALL) NOPASSWD: /usr/bin/install *
aifw ALL=(ALL) NOPASSWD: /usr/bin/tar *
aifw ALL=(ALL) NOPASSWD: /usr/bin/tee *
aifw ALL=(ALL) NOPASSWD: /usr/bin/wg *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/chown *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/freebsd-update *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/pkg *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/service *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/sysrc *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump *

# --- Detached restart driver ---
# Required by aifw-core/src/updater/services.rs `restart_services()` so post-update
# bounces survive aifw-api dying mid-iteration. -f flag double-forks
# /usr/local/libexec/aifw-restart.sh into its own session.
aifw ALL=(root) NOPASSWD: /usr/sbin/daemon -f *
"
}

#[cfg(test)]
mod sudoers_tests {
    use super::sudoers_content;

    /// #627 guard: the reboot the updater actually runs must match a
    /// sudoers grant EXACTLY. The grant is `/sbin/shutdown -r +10s *`;
    /// schedule_reboot() drifting to any other form (it shipped with
    /// `-r +1`) makes sudo refuse and the UI strand the operator on a
    /// "system is going down" overlay for a reboot that never happens.
    #[test]
    fn shutdown_grant_matches_updater_invocation() {
        let args = aifw_core::updater::SHUTDOWN_REBOOT_ARGS;
        let grant_prefix = format!("{} {} {}", args[0], args[1], args[2]);
        let grant = format!("aifw ALL=(root) NOPASSWD: {grant_prefix} *");
        assert!(
            sudoers_content().lines().any(|l| l.trim() == grant),
            "sudoers has no grant matching the updater's reboot invocation: {grant}"
        );
    }

    /// The remote-syslog "stop storing logs locally" toggle stops/starts
    /// the pflog service through `aifw-sudo-service` (aifw_core::local_log).
    /// Guard against the helper's allowlist dropping the service — sudo
    /// would refuse and the toggle would silently stop working. NOTE the
    /// rc.d script is named `pflog` (the daemon binary is pflogd; verified
    /// on FreeBSD 15.1 — /etc/rc.d/pflogd does not exist).
    #[test]
    fn service_helper_allows_pflog() {
        let script = include_str!("../../../freebsd/overlay/usr/local/libexec/aifw-sudo-service");
        assert!(
            script.lines().any(|l| l.trim() == "pflog)"),
            "aifw-sudo-service allowlist must include the pflog service for \
             the remote-syslog disable_local toggle"
        );
    }

    /// Structural-validity check on the sudoers content. We can't run
    /// `visudo -cf` from a Linux dev box, but we can enforce that every
    /// non-empty, non-comment line is a well-formed `aifw ALL=(<runas>)
    /// NOPASSWD: <abs-path>` grant. CI on FreeBSD additionally pipes the
    /// same string into `visudo -cf -` (see build-iso.yml).
    #[test]
    fn sudoers_lines_are_well_formed() {
        let content = sudoers_content();
        for (lineno, raw) in content.lines().enumerate() {
            let line = raw.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            assert!(
                line.starts_with("aifw ALL=("),
                "line {} doesn't start with 'aifw ALL=(': {raw:?}",
                lineno + 1
            );
            let after_paren = line
                .split_once(") NOPASSWD: ")
                .unwrap_or_else(|| {
                    panic!(
                        "line {} missing ') NOPASSWD: ' separator: {raw:?}",
                        lineno + 1
                    )
                })
                .1;
            // Command path must be absolute.
            assert!(
                after_paren.starts_with('/'),
                "line {} command path is not absolute: {raw:?}",
                lineno + 1
            );
        }
    }

    /// Every pfctl form the code shells out to (`sudo /sbin/pfctl …`) must
    /// have a matching NOPASSWD grant. sudo matches the joined argument
    /// string with fnmatch, so each expected string below is the grant body
    /// that covers a specific call site in aifw-pf/src/ioctl.rs,
    /// aifw-core/src/pf_tuning.rs and aifw-api/src/main.rs. The SEC-C2
    /// narrowing dropped `-ss -vv` (and the table/kill/flush/tuning forms),
    /// which silently emptied the connection list and broke the NAT Flows
    /// page; this gate stops that from regressing again.
    #[test]
    fn pfctl_sudoers_covers_invocations() {
        let content = sudoers_content();
        // (call site, grant body that must appear verbatim in sudoers)
        let required: &[(&str, &str)] = &[
            // SEC-H5: rule/NAT/queue loads pipe via stdin, not a /tmp file.
            ("load_rules (stdin)", "/sbin/pfctl -a aifw* -f -"),
            ("add_rule (stdin)", "/sbin/pfctl -a aifw* -f -"),
            ("load_queues (stdin)", "/sbin/pfctl -a aifw* -f -"),
            ("load_nat_rules (stdin)", "/sbin/pfctl -a aifw* -N -f -"),
            (
                "validate_rules (stdin dry-run)",
                "/sbin/pfctl -a aifw* -n -f -",
            ),
            ("get_rules", "/sbin/pfctl -a aifw* -sr"),
            ("get_nat_rules", "/sbin/pfctl -a aifw* -sn"),
            ("daemon pf drift auto-heal (global -sn)", "/sbin/pfctl -sn"),
            ("daemon pf re-enable after boot", "/sbin/pfctl -e"),
            ("get_queues", "/sbin/pfctl -a aifw* -sq"),
            ("flush_rules", "/sbin/pfctl -a aifw* -Fr"),
            ("flush_nat_rules", "/sbin/pfctl -a aifw* -Fn"),
            ("flush_queues", "/sbin/pfctl -a aifw* -Fq"),
            ("get_stats (status)", "/sbin/pfctl -si"),
            ("get_stats (rules)", "/sbin/pfctl -sr"),
            ("get_states", "/sbin/pfctl -ss -vv"),
            ("kill_states_for_label (list)", "/sbin/pfctl -ss -v"),
            ("get_stats (ifaces)", "/sbin/pfctl -vvsI"),
            ("add_table_entry", "/sbin/pfctl -t * -T add *"),
            ("remove_table_entry", "/sbin/pfctl -t * -T delete *"),
            ("replace_table_entries", "/sbin/pfctl -t * -T replace -f -"),
            ("flush_table", "/sbin/pfctl -t * -T flush"),
            ("get_table_entries", "/sbin/pfctl -t * -T show"),
            ("kill_states (pair)", "/sbin/pfctl -k * -k *"),
            (
                "kill_states_on_iface",
                "/sbin/pfctl -k 0.0.0.0/0 -k 0.0.0.0/0 -i *",
            ),
            (
                "patch pf.conf validate",
                "/sbin/pfctl -nf /tmp/aifw-pf.conf.aifw.patched",
            ),
            (
                "patch/dhcp pf.conf load",
                "/sbin/pfctl -f /usr/local/etc/aifw/pf.conf.aifw",
            ),
            (
                "pf tuning merge",
                "/sbin/pfctl -m -f /usr/local/etc/aifw/pf-tuning.conf",
            ),
        ];
        for (site, grant) in required {
            assert!(
                content.contains(grant),
                "pfctl form for `{site}` is not granted in sudoers — missing `{grant}`. \
                 An uncovered form makes `sudo {grant}` prompt for a password and fail."
            );
        }

        // SEC-H5 regression guard: the world-writable /tmp rule-load grants
        // must NOT come back. Rule/NAT loads now pipe via stdin; a grant that
        // fnmatch-covers `/tmp/aifw_pf_*.conf` would reopen the TOCTOU.
        for forbidden in [
            "/sbin/pfctl -a aifw* -f /tmp/aifw_pf_*.conf",
            "/sbin/pfctl -a aifw* -N -f /tmp/aifw_pf_*.conf",
        ] {
            assert!(
                !content.contains(forbidden),
                "SEC-H5: removed /tmp pfctl load grant reappeared: `{forbidden}`"
            );
        }
    }

    /// Each `aifw-sudo-*` helper grant must reference a script that
    /// actually ships in `freebsd/overlay/usr/local/libexec/`. Catches
    /// typos and dropped scripts before they land on an appliance.
    #[test]
    fn helper_grants_point_at_real_scripts() {
        let content = sudoers_content();
        let helper_prefix = "/usr/local/libexec/aifw-sudo-";
        let overlay = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace dir")
            .join("freebsd/overlay/usr/local/libexec");
        for line in content.lines() {
            let Some(start) = line.find(helper_prefix) else {
                continue;
            };
            // Helper path ends at the first space after the prefix.
            let tail = &line[start..];
            let helper_path = tail.split_whitespace().next().unwrap();
            let basename = std::path::Path::new(helper_path)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();
            let on_disk = overlay.join(&basename);
            assert!(
                on_disk.exists(),
                "sudoers grants {helper_path} but {} is missing in overlay",
                on_disk.display()
            );
        }
    }

    /// The narrow `aifw-sudo-*` helpers must be granted in addition to the
    /// compat-tier broad grants — the helpers are the preferred path and
    /// `crate::sudo::*` wrappers always call them when on disk.
    #[test]
    fn narrow_helpers_are_granted() {
        let content = sudoers_content();
        for helper in [
            "/usr/local/libexec/aifw-sudo-install",
            "/usr/local/libexec/aifw-sudo-write",
            "/usr/local/libexec/aifw-sudo-wg",
            "/usr/local/libexec/aifw-sudo-freebsd-update",
            "/usr/local/libexec/aifw-sudo-pkg",
            "/usr/local/libexec/aifw-sudo-service",
            "/usr/local/libexec/aifw-sudo-chown",
            "/usr/local/libexec/aifw-sudo-ifconfig",
            "/usr/local/libexec/aifw-sudo-sysrc",
            "/usr/local/libexec/aifw-sudo-dhclient",
            "/usr/local/libexec/aifw-sudo-route",
            "/usr/local/libexec/aifw-sudo-pkill",
            "/usr/local/libexec/aifw-sudo-rm",
            "/usr/local/libexec/aifw-sudo-mkdir",
            "/usr/local/libexec/aifw-sudo-cp",
            "/usr/local/libexec/aifw-sudo-tar",
            "/usr/local/libexec/aifw-sudo-tcpdump",
            "/usr/local/libexec/aifw-sudo-swanctl",
            "/usr/local/libexec/aifw-sudo-dummynet",
            "/usr/local/libexec/aifw-sudo-newsyslog",
        ] {
            assert!(
                content.contains(helper),
                "narrow helper grant for {helper:?} is missing — \
                 v5.96 ships these alongside the compat-tier broad grants"
            );
        }
    }

    /// `cat *` and `chmod *` are NOT in the canonical sudoers — they were
    /// unused in current code and dropped entirely as part of SEC-C2.
    #[test]
    fn deprecated_unused_grants_stay_dropped() {
        let content = sudoers_content();
        for forbidden in ["/bin/cat *", "/bin/chmod *"] {
            assert!(
                !content.contains(forbidden),
                "grant {forbidden:?} was reintroduced — kept dropped because \
                 nothing in the codebase calls it (SEC-C2)"
            );
        }
    }

    /// SEC-C1: aifw-sudo-install MUST NOT accept /usr/local/etc/sudoers.d/aifw
    /// as a destination. Letting aifw-uid code write its own sudoers grants is
    /// a trivial PE primitive.
    #[test]
    fn aifw_sudo_install_does_not_target_sudoers_d() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let helper = manifest_dir
            .parent()
            .unwrap()
            .join("freebsd/overlay/usr/local/libexec/aifw-sudo-install");
        let script = std::fs::read_to_string(&helper)
            .unwrap_or_else(|e| panic!("read {}: {}", helper.display(), e));
        for line in script.lines() {
            let trimmed = line.trim_start();
            // Look only at non-comment lines that contain a `case` arm body.
            if trimmed.starts_with('#') {
                continue;
            }
            assert!(
                !trimmed.starts_with("/usr/local/etc/sudoers.d/aifw)"),
                "aifw-sudo-install dest allowlist re-introduces \
                 /usr/local/etc/sudoers.d/aifw (SEC-C1 regression). \
                 Sudoers must be shipped via the package, not migrated at runtime."
            );
        }
    }

    // ------------------------------------------------------------------
    // Wrapper-allowlist drift guards (batch C: #302 #303 #309 #314 #316).
    // The narrow helpers under freebsd/overlay/usr/local/libexec are the
    // privilege boundary; every time a Rust call site and a helper's
    // allowlist disagree, sudo refuses and a feature silently breaks
    // (#601, #627, sudoers-drift history). These tests pin the pairs.
    // ------------------------------------------------------------------

    fn libexec(name: &str) -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let path = root.join("freebsd/overlay/usr/local/libexec").join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn workspace_file(rel: &str) -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
    }

    /// Match `path` against a `case`-style allowlist entry where `*` is
    /// the only wildcard (sh `case` semantics — `*` matches `/` too, but
    /// the helper rejects `..`/`//` beforehand).
    fn case_glob_matches(pattern: &str, path: &str) -> bool {
        fn go(p: &[u8], s: &[u8]) -> bool {
            match p.first() {
                None => s.is_empty(),
                Some(b'*') => (0..=s.len()).any(|i| go(&p[1..], &s[i..])),
                Some(c) => s.first() == Some(c) && go(&p[1..], &s[1..]),
            }
        }
        go(pattern.as_bytes(), path.as_bytes())
    }

    /// Extract the `case "$DEST" in` allowlist entries from aifw-sudo-write:
    /// lines of the form `    /abs/path)` (possibly `a|b)`), before the `*)`.
    fn write_allowlist() -> Vec<String> {
        let script = libexec("aifw-sudo-write");
        let mut out = Vec::new();
        for line in script.lines() {
            let t = line.trim();
            if t.starts_with('/') && t.ends_with(')') {
                for alt in t.trim_end_matches(')').split('|') {
                    out.push(alt.trim().to_string());
                }
            }
        }
        assert!(
            !out.is_empty(),
            "no allowlist entries parsed from aifw-sudo-write"
        );
        out
    }

    /// SEC-M17 #314: every path the code hands to `sudo::write_file` must
    /// be covered by the aifw-sudo-write allowlist. Paths listed here are
    /// the literal targets at each call site (grep `sudo::write_file(`);
    /// when you add a call site, add its path here AND to the helper.
    #[test]
    fn write_helper_allowlist_covers_call_sites() {
        use aifw_core::ipsec::{
            SWANCTL_CONF_DIR, SWANCTL_PRIVATE_DIR, SWANCTL_X509_DIR, SWANCTL_X509CA_DIR,
        };
        let allow = write_allowlist();
        let example_id = "aifw-00000000-0000-0000-0000-000000000000";
        let targets: Vec<(&str, String)> = vec![
            (
                "aifw-api main.rs / dhcp.rs / pf_tuning.rs pf.conf.aifw",
                "/usr/local/etc/aifw/pf.conf.aifw".into(),
            ),
            (
                "aifw-api cluster.rs daemon.key",
                "/usr/local/etc/aifw/daemon.key".into(),
            ),
            (
                "aifw-api reverse_proxy.rs / aifw-cli trafficcop config",
                "/usr/local/etc/trafficcop/config.yaml".into(),
            ),
            (
                "aifw-core ipsec.rs conn file",
                format!("{SWANCTL_CONF_DIR}/{example_id}.conf"),
            ),
            (
                "aifw-core ipsec.rs private key",
                format!("{SWANCTL_PRIVATE_DIR}/{example_id}.pem"),
            ),
            (
                "aifw-core ipsec.rs cert",
                format!("{SWANCTL_X509_DIR}/{example_id}.pem"),
            ),
            (
                "aifw-core ipsec.rs ca cert",
                format!("{SWANCTL_X509CA_DIR}/{example_id}.pem"),
            ),
            (
                "aifw-core log_rotation.rs newsyslog fragment (#205)",
                aifw_core::log_rotation::CONF_PATH.into(),
            ),
        ];
        for (site, path) in &targets {
            assert!(
                allow.iter().any(|pat| case_glob_matches(pat, path)),
                "aifw-sudo-write allowlist does not cover {path} (call site: {site}). allowlist: {allow:?}"
            );
        }
        // Negative control: the matcher must not be trivially permissive.
        assert!(
            !allow
                .iter()
                .any(|pat| case_glob_matches(pat, "/etc/master.passwd"))
        );
    }

    /// Drift guard companion to the test above: the number of
    /// `sudo::write_file(` call sites in the tree must equal what the
    /// target list accounts for. A new call site fails here until its
    /// path is added to both the list above and the helper.
    #[test]
    fn write_file_call_site_count_is_accounted_for() {
        // Known call sites (file → count). Any `sudo::write_file(` found in
        // a file not listed here, or a count mismatch, fails the test.
        let known: &[(&str, usize)] = &[
            ("aifw-api/src/main.rs", 1),
            ("aifw-api/src/dhcp.rs", 1),
            ("aifw-api/src/cluster.rs", 1),
            ("aifw-api/src/reverse_proxy.rs", 1),
            ("aifw-cli/src/commands/reverse_proxy.rs", 1),
            ("aifw-core/src/pf_tuning.rs", 1),
            ("aifw-core/src/ipsec.rs", 1),
            ("aifw-core/src/log_rotation.rs", 1),
            // the definition itself
            ("aifw-core/src/sudo.rs", 0),
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut found: Vec<(String, usize)> = Vec::new();
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let mut files = Vec::new();
        for e in std::fs::read_dir(&root).unwrap().flatten() {
            let p = e.path();
            if p.is_dir()
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("aifw-"))
                && p.join("src").is_dir()
            {
                walk(&p.join("src"), &mut files);
            }
        }
        let this_file = std::path::Path::new(file!());
        for f in files {
            // Skip this test's own source, which mentions the pattern.
            if f.ends_with(this_file) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            let n = text.matches("sudo::write_file(").count();
            if n > 0 {
                let rel = f
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                found.push((rel, n));
            }
        }
        found.sort();
        let mut expected: Vec<(String, usize)> = known
            .iter()
            .filter(|(_, n)| *n > 0)
            .map(|(f, n)| (f.to_string(), *n))
            .collect();
        expected.sort();
        assert_eq!(
            found, expected,
            "sudo::write_file( call sites changed — update \
             write_helper_allowlist_covers_call_sites and aifw-sudo-write"
        );
    }

    /// SEC-M12 #309: `aifw-sudo-pkg install` only accepts the closed set of
    /// runtime packages. That set must equal freebsd/manifest.json
    /// "packages" (which drives the updater's dependency install loop).
    #[test]
    fn pkg_helper_allowlist_matches_manifest_packages() {
        let manifest: serde_json::Value =
            serde_json::from_str(&workspace_file("freebsd/manifest.json")).unwrap();
        let mut manifest_pkgs: Vec<String> = manifest["packages"]
            .as_array()
            .expect("manifest.packages")
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        manifest_pkgs.sort();

        let script = libexec("aifw-sudo-pkg");
        // The allowlist is the `case` arm inside valid_pkg_name():
        //     curl|minisign|...) return 0 ;;
        let arm = script
            .lines()
            .map(str::trim)
            .find(|l| l.ends_with(") return 0 ;;") && l.contains('|'))
            .expect("allowlist arm in aifw-sudo-pkg valid_pkg_name()");
        let mut helper_pkgs: Vec<String> = arm
            .trim_end_matches(") return 0 ;;")
            .split('|')
            .map(|s| s.trim().to_string())
            .collect();
        helper_pkgs.sort();
        assert_eq!(
            helper_pkgs, manifest_pkgs,
            "aifw-sudo-pkg allowlist must equal manifest.json packages"
        );
    }

    /// SEC-M5 #302: aifw-sudo-wg only accepts key-file paths of the shape
    /// aifw-core stages them as. If vpn.rs changes the staging path
    /// format, the helper's pattern must move with it (else wg set fails
    /// and every tunnel start breaks).
    #[test]
    fn wg_helper_key_path_pattern_matches_vpn_staging() {
        let vpn = workspace_file("aifw-core/src/vpn.rs");
        assert!(
            vpn.contains("\"/tmp/wg-{}-{}.key\""),
            "vpn.rs private key staging path changed"
        );
        assert!(
            vpn.contains("\"/tmp/wg-psk-{}-{}.key\""),
            "vpn.rs psk staging path changed"
        );
        let wg = libexec("aifw-sudo-wg");
        assert!(
            wg.contains("/tmp/wg-*.key)"),
            "aifw-sudo-wg staging path pattern changed"
        );
        // And the helper must know every `wg set` option vpn.rs emits.
        for opt in [
            "private-key",
            "listen-port",
            "peer",
            "allowed-ips",
            "endpoint",
            "persistent-keepalive",
            "preshared-key",
        ] {
            assert!(
                vpn.contains(&format!("\"{opt}\"")),
                "vpn.rs no longer uses wg option {opt}?"
            );
            assert!(wg.contains(opt), "aifw-sudo-wg missing wg option {opt}");
        }
    }

    /// SEC-L1 #316: the `ifconfig_*` value templates aifw-api writes via
    /// aifw-sudo-sysrc must be ones the helper's grammar accepts.
    #[test]
    fn sysrc_helper_accepts_iface_rs_templates() {
        let iface = workspace_file("aifw-api/src/iface.rs");
        let sysrc = libexec("aifw-sudo-sysrc");
        // Templates emitted by iface.rs.
        for tmpl in ["=DHCP\"", "=inet {}\"", "\"up\".to_string()"] {
            assert!(iface.contains(tmpl), "iface.rs no longer emits {tmpl}?");
        }
        assert!(
            sysrc.contains("DHCP|SYNCDHCP|up|down)"),
            "sysrc helper word-form arm changed"
        );
        assert!(
            sysrc.contains("\"inet \"*|\"inet6 \"*)"),
            "sysrc helper inet arm changed"
        );
        assert!(
            sysrc.contains("vlans_*)"),
            "sysrc helper vlans_ arm changed"
        );
    }
}
