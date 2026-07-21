//! IPsec data-plane engine (#530).
//!
//! [`IpsecEngine`] owns the `ipsec_tunnels` table (desired config) and
//! renders each enabled tunnel into a swanctl config file that strongSwan
//! (charon) negotiates into kernel SAs/SPs. All charon interaction goes
//! through the [`IkeControl`] trait: [`SwanctlControl`] shells out via
//! `sudo::swanctl` on a real appliance, [`MockIkeControl`] backs tests and
//! Linux development — mirroring the `PfBackend` mock/ioctl split.
//!
//! Live tunnel state is never stored: it is parsed from
//! `swanctl --list-sas` on demand (see `status` in the apply layer).

use std::sync::{Arc, Mutex};

use aifw_common::{AifwError, IpsecLiveStatus, IpsecTunnel, Result};
use async_trait::async_trait;
use sqlx::SqlitePool;
use uuid::Uuid;

/// Directory charon reads per-connection config from. Files are named
/// `aifw-<id>.conf` and owned by root (they contain PSKs).
pub const SWANCTL_CONF_DIR: &str = "/usr/local/etc/swanctl/conf.d";
/// Private key PEMs for cert-auth tunnels (`aifw-<id>.pem`).
pub const SWANCTL_PRIVATE_DIR: &str = "/usr/local/etc/swanctl/private";
/// Local certificate PEMs (`aifw-<id>.pem`).
pub const SWANCTL_X509_DIR: &str = "/usr/local/etc/swanctl/x509";
/// CA certificate PEMs (`aifw-<id>.pem`).
pub const SWANCTL_X509CA_DIR: &str = "/usr/local/etc/swanctl/x509ca";

/// Control-plane interface to the IKE daemon. Implementations must be
/// cheap to clone behind an `Arc` and safe to call concurrently.
#[async_trait]
pub trait IkeControl: Send + Sync {
    /// (Re)load all connections and credentials from swanctl config.
    /// Removes conns that disappeared from config.
    async fn load_all(&self) -> Result<()>;
    /// Initiate the named child SA (`aifw-<id>-1`), blocking up to
    /// `timeout_secs` for the negotiation outcome.
    async fn initiate(&self, child: &str, timeout_secs: u32) -> Result<()>;
    /// Terminate the named IKE SA and its children.
    async fn terminate_ike(&self, ike: &str, force: bool) -> Result<()>;
    /// Raw `swanctl --list-sas --raw` output for status parsing.
    async fn list_sas_raw(&self) -> Result<String>;
    /// Raw `swanctl --list-conns --raw` output.
    async fn list_conns_raw(&self) -> Result<String>;
}

/// Real control plane: drives charon through the `aifw-sudo-swanctl`
/// narrow wrapper. Constructed on FreeBSD appliances.
pub struct SwanctlControl;

/// Run a swanctl invocation and convert a non-zero exit into a
/// `Vpn`-flavored error carrying stderr (charon's diagnostics are the
/// only useful failure detail).
async fn swanctl_checked(args: &[&str]) -> Result<std::process::Output> {
    let output = crate::sudo::swanctl(args).await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AifwError::Config(format!(
            "swanctl {} failed: {}",
            args.first().copied().unwrap_or("?"),
            stderr.trim()
        )));
    }
    Ok(output)
}

#[async_trait]
impl IkeControl for SwanctlControl {
    async fn load_all(&self) -> Result<()> {
        swanctl_checked(&["--load-all", "--noprompt"]).await?;
        Ok(())
    }

    async fn initiate(&self, child: &str, timeout_secs: u32) -> Result<()> {
        let timeout = timeout_secs.to_string();
        swanctl_checked(&["--initiate", "--child", child, "--timeout", &timeout]).await?;
        Ok(())
    }

    async fn terminate_ike(&self, ike: &str, force: bool) -> Result<()> {
        let mut args = vec!["--terminate", "--ike", ike];
        if force {
            args.push("--force");
        }
        swanctl_checked(&args).await?;
        Ok(())
    }

    async fn list_sas_raw(&self) -> Result<String> {
        let output = swanctl_checked(&["--list-sas", "--raw"]).await?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    async fn list_conns_raw(&self) -> Result<String> {
        let output = swanctl_checked(&["--list-conns", "--raw"]).await?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

/// Platform-appropriate IKE control, mirroring `aifw_pf::create_backend`:
/// swanctl on FreeBSD, in-memory mock everywhere else.
#[cfg(target_os = "freebsd")]
pub fn create_ike_control() -> Arc<dyn IkeControl> {
    Arc::new(SwanctlControl)
}

/// Platform-appropriate IKE control, mirroring `aifw_pf::create_backend`:
/// swanctl on FreeBSD, in-memory mock everywhere else.
#[cfg(not(target_os = "freebsd"))]
pub fn create_ike_control() -> Arc<dyn IkeControl> {
    Arc::new(MockIkeControl::new())
}

/// Platform-appropriate swanctl conf store: real root-owned files on
/// FreeBSD, in-memory map everywhere else.
#[cfg(target_os = "freebsd")]
pub fn create_conf_store() -> Arc<dyn IpsecConfStore> {
    Arc::new(SystemConfStore)
}

/// Platform-appropriate swanctl conf store: real root-owned files on
/// FreeBSD, in-memory map everywhere else.
#[cfg(not(target_os = "freebsd"))]
pub fn create_conf_store() -> Arc<dyn IpsecConfStore> {
    Arc::new(MemConfStore::new())
}

/// Best-effort hook for the ACME renewal path (#568): after cert `cert_id`
/// is renewed (or received via HA cert-push), re-apply IPsec so any tunnel
/// referencing it presents the new material. Builds the platform-default
/// engine; failures are only logged — the renewal itself already succeeded
/// and must not be reported as failed because of a downstream consumer.
pub async fn on_acme_cert_renewed(pool: &SqlitePool, cert_id: i64) {
    let engine = IpsecEngine::new(pool.clone(), create_ike_control(), create_conf_store());
    match engine.reapply_for_acme_cert(cert_id).await {
        Ok(true) => {
            tracing::info!(cert_id, "ipsec: re-applied tunnels after ACME cert renewal");
        }
        Ok(false) => {}
        Err(e) => {
            tracing::warn!(cert_id, error = %e, "ipsec: re-apply after ACME cert renewal failed");
        }
    }
}

/// Recorded state of a [`MockIkeControl`], inspectable from tests.
#[derive(Debug, Default)]
pub struct MockIkeState {
    /// Number of `load_all` calls
    pub load_all_calls: u32,
    /// Child names passed to `initiate`, in order
    pub initiated: Vec<String>,
    /// IKE names passed to `terminate_ike`, in order
    pub terminated: Vec<String>,
    /// Canned `--list-sas --raw` output returned by `list_sas_raw`
    pub sas_raw: String,
    /// Canned `--list-conns --raw` output
    pub conns_raw: String,
    /// When set, `load_all` fails with this message (rollback testing)
    pub fail_load: Option<String>,
}

/// In-memory IKE control for tests and Linux/WSL development.
#[derive(Debug, Default)]
pub struct MockIkeControl {
    state: Mutex<MockIkeState>,
}

impl MockIkeControl {
    /// Fresh mock with empty recorded state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Run `f` against the recorded state (assert or arrange).
    pub fn with_state<R>(&self, f: impl FnOnce(&mut MockIkeState) -> R) -> R {
        let mut guard = self.state.lock().expect("mock ike state lock poisoned");
        f(&mut guard)
    }
}

#[async_trait]
impl IkeControl for MockIkeControl {
    async fn load_all(&self) -> Result<()> {
        self.with_state(|s| {
            s.load_all_calls += 1;
            match &s.fail_load {
                Some(msg) => Err(AifwError::Config(msg.clone())),
                None => Ok(()),
            }
        })
    }

    async fn initiate(&self, child: &str, _timeout_secs: u32) -> Result<()> {
        self.with_state(|s| s.initiated.push(child.to_string()));
        Ok(())
    }

    async fn terminate_ike(&self, ike: &str, _force: bool) -> Result<()> {
        self.with_state(|s| s.terminated.push(ike.to_string()));
        Ok(())
    }

    async fn list_sas_raw(&self) -> Result<String> {
        Ok(self.with_state(|s| s.sas_raw.clone()))
    }

    async fn list_conns_raw(&self) -> Result<String> {
        Ok(self.with_state(|s| s.conns_raw.clone()))
    }
}

/// Storage for AiFw-managed swanctl files (conn configs, certs, keys).
/// Abstracted so the apply/rollback lifecycle is fully testable on
/// Linux: the real store writes root-owned files through the narrow
/// sudo helpers, the mock keeps a HashMap.
#[async_trait]
pub trait IpsecConfStore: Send + Sync {
    /// Atomically write `content` to the absolute `path` (root-owned,
    /// mode fixed by the write helper's per-path policy).
    async fn write(&self, path: &str, content: &[u8]) -> Result<()>;
    /// Remove the file at `path`.
    async fn remove(&self, path: &str) -> Result<()>;
    /// All AiFw-managed swanctl file paths currently on disk
    /// (`aifw-*` files across conf.d/private/x509/x509ca).
    async fn list_managed(&self) -> Result<Vec<String>>;
}

/// Real store: writes via `aifw-sudo-write`, removes via `aifw-sudo-rm`.
/// Listing uses plain readdir — the swanctl dirs are root-owned but
/// world-listable; file *contents* stay root-only.
pub struct SystemConfStore;

/// The four swanctl directories AiFw manages files in.
const SWANCTL_DIRS: &[&str] = &[
    SWANCTL_CONF_DIR,
    SWANCTL_PRIVATE_DIR,
    SWANCTL_X509_DIR,
    SWANCTL_X509CA_DIR,
];

#[async_trait]
impl IpsecConfStore for SystemConfStore {
    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        crate::sudo::write_file(std::path::Path::new(path), content)
            .await
            .map_err(|e| AifwError::Config(format!("write {path} failed: {e}")))
    }

    async fn remove(&self, path: &str) -> Result<()> {
        let output = crate::sudo::rm(&[path]).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AifwError::Config(format!(
                "remove {path} failed: {}",
                stderr.trim()
            )));
        }
        Ok(())
    }

    async fn list_managed(&self) -> Result<Vec<String>> {
        let mut paths = Vec::new();
        for dir in SWANCTL_DIRS {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue; // dir absent (strongswan not installed yet)
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("aifw-") {
                    paths.push(format!("{dir}/{name}"));
                }
            }
        }
        Ok(paths)
    }
}

/// In-memory conf store for tests and Linux development.
#[derive(Debug, Default)]
pub struct MemConfStore {
    files: Mutex<std::collections::HashMap<String, Vec<u8>>>,
}

impl MemConfStore {
    /// Fresh empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Current content of `path`, if present.
    pub fn get(&self, path: &str) -> Option<Vec<u8>> {
        self.files
            .lock()
            .expect("mem conf store lock poisoned")
            .get(path)
            .cloned()
    }

    /// Number of stored files.
    pub fn len(&self) -> usize {
        self.files
            .lock()
            .expect("mem conf store lock poisoned")
            .len()
    }

    /// True when no files are stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl IpsecConfStore for MemConfStore {
    async fn write(&self, path: &str, content: &[u8]) -> Result<()> {
        self.files
            .lock()
            .expect("mem conf store lock poisoned")
            .insert(path.to_string(), content.to_vec());
        Ok(())
    }

    async fn remove(&self, path: &str) -> Result<()> {
        self.files
            .lock()
            .expect("mem conf store lock poisoned")
            .remove(path);
        Ok(())
    }

    async fn list_managed(&self) -> Result<Vec<String>> {
        Ok(self
            .files
            .lock()
            .expect("mem conf store lock poisoned")
            .keys()
            .cloned()
            .collect())
    }
}

/// Render one tunnel into its swanctl config file content: a
/// `connections` section plus, for PSK auth, a matching `secrets`
/// section. Cert-auth material lives in the swanctl x509/private
/// directories and is loaded implicitly by `--load-all`.
///
/// Every interpolated value is constrained by `IpsecTunnel::validate`
/// (no quotes, no newlines), so the rendered text cannot escape its
/// section — callers must validate before rendering.
pub fn render_swanctl_conf(t: &IpsecTunnel) -> String {
    use aifw_common::IpsecAuthMethod;

    let conn = t.conn_name();
    let child = t.child_name();
    let mut out = String::new();
    let push = |out: &mut String, line: &str| {
        out.push_str(line);
        out.push('\n');
    };

    push(&mut out, "# Managed by AiFw (#530 IPsec). Do not edit —");
    push(
        &mut out,
        "# regenerated from the AiFw database on every apply.",
    );
    push(&mut out, "connections {");
    push(&mut out, &format!("    {conn} {{"));
    push(&mut out, "        version = 2");
    if !t.local_addr.is_empty() {
        push(&mut out, &format!("        local_addrs = {}", t.local_addr));
    }
    push(
        &mut out,
        &format!("        remote_addrs = {}", t.remote_addr),
    );
    push(&mut out, &format!("        proposals = {}", t.ike_proposal));
    push(
        &mut out,
        &format!("        rekey_time = {}s", t.ike_lifetime_secs),
    );
    if t.dpd_delay_secs > 0 {
        push(
            &mut out,
            &format!("        dpd_delay = {}s", t.dpd_delay_secs),
        );
    }

    // local auth block
    push(&mut out, "        local {");
    match t.auth_method {
        IpsecAuthMethod::Psk => push(&mut out, "            auth = psk"),
        IpsecAuthMethod::Cert => {
            push(&mut out, "            auth = pubkey");
            push(&mut out, &format!("            certs = {conn}.pem"));
        }
    }
    if !t.local_id.is_empty() {
        push(&mut out, &format!("            id = \"{}\"", t.local_id));
    }
    push(&mut out, "        }");

    // remote auth block
    push(&mut out, "        remote {");
    match t.auth_method {
        IpsecAuthMethod::Psk => push(&mut out, "            auth = psk"),
        IpsecAuthMethod::Cert => push(&mut out, "            auth = pubkey"),
    }
    if !t.remote_id.is_empty() {
        push(&mut out, &format!("            id = \"{}\"", t.remote_id));
    }
    push(&mut out, "        }");

    // single child SA carrying all traffic selectors
    push(&mut out, "        children {");
    push(&mut out, &format!("            {child} {{"));
    push(
        &mut out,
        &format!("                local_ts = {}", t.local_ts.join(",")),
    );
    push(
        &mut out,
        &format!("                remote_ts = {}", t.remote_ts.join(",")),
    );
    push(
        &mut out,
        &format!("                esp_proposals = {}", t.esp_proposal),
    );
    push(
        &mut out,
        &format!("                rekey_time = {}s", t.esp_lifetime_secs),
    );
    push(
        &mut out,
        &format!("                start_action = {}", t.start_action),
    );
    if t.dpd_delay_secs > 0 {
        // Keep persistent tunnels up across dead peers; on-demand (trap)
        // tunnels fall back to the trap policy instead.
        let dpd_action = match t.start_action {
            aifw_common::IpsecStartAction::Start => "restart",
            aifw_common::IpsecStartAction::Trap => "trap",
            aifw_common::IpsecStartAction::None => "clear",
        };
        push(
            &mut out,
            &format!("                dpd_action = {dpd_action}"),
        );
    }
    push(&mut out, "            }");
    push(&mut out, "        }");
    push(&mut out, "    }");
    push(&mut out, "}");

    if t.auth_method == IpsecAuthMethod::Psk {
        push(&mut out, "secrets {");
        push(&mut out, &format!("    ike-{conn} {{"));
        push(&mut out, &format!("        secret = \"{}\"", t.psk));
        // Bind the secret to the peer identities so multiple PSK tunnels
        // to different peers can't cross-match.
        let local_ident = if t.local_id.is_empty() {
            t.local_addr.as_str()
        } else {
            t.local_id.as_str()
        };
        let remote_ident = if t.remote_id.is_empty() {
            t.remote_addr.as_str()
        } else {
            t.remote_id.as_str()
        };
        if !local_ident.is_empty() {
            push(&mut out, &format!("        id-1 = \"{local_ident}\""));
        }
        push(&mut out, &format!("        id-2 = \"{remote_ident}\""));
        push(&mut out, "    }");
        push(&mut out, "}");
    }

    out
}

/// Explicit column list for `IpsecTunnelRow` selects. Keep in `CREATE
/// TABLE` schema order.
const IPSEC_TUNNEL_COLUMNS: &str = "id, name, enabled, local_addr, remote_addr, local_id, \
     remote_id, auth_method, psk, cert_source, acme_cert_id, local_cert_pem, local_key_pem, \
     ca_cert_pem, ike_proposal, esp_proposal, local_ts, remote_ts, ike_lifetime_secs, \
     esp_lifetime_secs, dpd_delay_secs, start_action, created_at, updated_at";

#[derive(sqlx::FromRow)]
struct IpsecTunnelRow {
    id: String,
    name: String,
    enabled: i64,
    local_addr: String,
    remote_addr: String,
    local_id: String,
    remote_id: String,
    auth_method: String,
    psk: String,
    cert_source: Option<String>,
    acme_cert_id: Option<i64>,
    local_cert_pem: String,
    local_key_pem: String,
    ca_cert_pem: String,
    ike_proposal: String,
    esp_proposal: String,
    local_ts: String,
    remote_ts: String,
    ike_lifetime_secs: i64,
    esp_lifetime_secs: i64,
    dpd_delay_secs: i64,
    start_action: String,
    created_at: String,
    updated_at: String,
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(String::from)
        .collect()
}

fn parse_ts(field: &str, s: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| AifwError::Database(format!("bad {field} timestamp {s:?}: {e}")))
}

impl IpsecTunnelRow {
    fn into_tunnel(self) -> Result<IpsecTunnel> {
        use aifw_common::{IpsecAuthMethod, IpsecCertSource, IpsecStartAction};
        Ok(IpsecTunnel {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("bad tunnel id {:?}: {e}", self.id)))?,
            name: self.name,
            enabled: self.enabled != 0,
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
            local_id: self.local_id,
            remote_id: self.remote_id,
            auth_method: IpsecAuthMethod::parse(&self.auth_method)?,
            psk: self.psk,
            cert_source: match self.cert_source.as_deref() {
                None | Some("") => None,
                Some(s) => Some(IpsecCertSource::parse(s)?),
            },
            acme_cert_id: self.acme_cert_id,
            local_cert_pem: self.local_cert_pem,
            local_key_pem: self.local_key_pem,
            ca_cert_pem: self.ca_cert_pem,
            ike_proposal: self.ike_proposal,
            esp_proposal: self.esp_proposal,
            local_ts: split_csv(&self.local_ts),
            remote_ts: split_csv(&self.remote_ts),
            ike_lifetime_secs: self.ike_lifetime_secs as u32,
            esp_lifetime_secs: self.esp_lifetime_secs as u32,
            dpd_delay_secs: self.dpd_delay_secs as u32,
            start_action: IpsecStartAction::parse(&self.start_action)?,
            created_at: parse_ts("created_at", &self.created_at)?,
            updated_at: parse_ts("updated_at", &self.updated_at)?,
        })
    }
}

/// Engine owning desired IPsec tunnel config and the IKE control plane.
pub struct IpsecEngine {
    pool: SqlitePool,
    ike: Arc<dyn IkeControl>,
    store: Arc<dyn IpsecConfStore>,
}

impl IpsecEngine {
    /// Build the engine over the shared pool, an IKE control backend and
    /// a conf store (SwanctlControl + SystemConfStore on FreeBSD,
    /// mocks elsewhere).
    pub fn new(pool: SqlitePool, ike: Arc<dyn IkeControl>, store: Arc<dyn IpsecConfStore>) -> Self {
        Self { pool, ike, store }
    }

    /// The IKE control backend (used by the apply/status layer).
    pub fn ike(&self) -> &Arc<dyn IkeControl> {
        &self.ike
    }

    /// Create the `ipsec_tunnels` table if missing.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ipsec_tunnels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL DEFAULT 1,
                local_addr TEXT NOT NULL DEFAULT '',
                remote_addr TEXT NOT NULL,
                local_id TEXT NOT NULL DEFAULT '',
                remote_id TEXT NOT NULL DEFAULT '',
                auth_method TEXT NOT NULL,
                psk TEXT NOT NULL DEFAULT '',
                cert_source TEXT,
                acme_cert_id INTEGER,
                local_cert_pem TEXT NOT NULL DEFAULT '',
                local_key_pem TEXT NOT NULL DEFAULT '',
                ca_cert_pem TEXT NOT NULL DEFAULT '',
                ike_proposal TEXT NOT NULL,
                esp_proposal TEXT NOT NULL,
                local_ts TEXT NOT NULL,
                remote_ts TEXT NOT NULL,
                ike_lifetime_secs INTEGER NOT NULL,
                esp_lifetime_secs INTEGER NOT NULL,
                dpd_delay_secs INTEGER NOT NULL,
                start_action TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Validate and persist a new tunnel.
    pub async fn add_tunnel(&self, tunnel: IpsecTunnel) -> Result<IpsecTunnel> {
        Self::insert_tunnel_on(&self.pool, &tunnel).await?;
        Ok(tunnel)
    }

    /// Executor-generic validate + insert with no swanctl side effects.
    /// Public for the transactional restore path (#158/#535); callers apply
    /// the swanctl config separately.
    pub async fn insert_tunnel_on<'e, E>(exec: E, tunnel: &IpsecTunnel) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        tunnel.validate()?;
        sqlx::query(
            r#"
            INSERT INTO ipsec_tunnels (
                id, name, enabled, local_addr, remote_addr, local_id, remote_id,
                auth_method, psk, cert_source, acme_cert_id, local_cert_pem,
                local_key_pem, ca_cert_pem, ike_proposal, esp_proposal, local_ts,
                remote_ts, ike_lifetime_secs, esp_lifetime_secs, dpd_delay_secs,
                start_action, created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24
            )
            "#,
        )
        .bind(tunnel.id.to_string())
        .bind(&tunnel.name)
        .bind(tunnel.enabled as i64)
        .bind(&tunnel.local_addr)
        .bind(&tunnel.remote_addr)
        .bind(&tunnel.local_id)
        .bind(&tunnel.remote_id)
        .bind(tunnel.auth_method.to_string())
        .bind(&tunnel.psk)
        .bind(tunnel.cert_source.map(|s| s.to_string()))
        .bind(tunnel.acme_cert_id)
        .bind(&tunnel.local_cert_pem)
        .bind(&tunnel.local_key_pem)
        .bind(&tunnel.ca_cert_pem)
        .bind(&tunnel.ike_proposal)
        .bind(&tunnel.esp_proposal)
        .bind(tunnel.local_ts.join(","))
        .bind(tunnel.remote_ts.join(","))
        .bind(tunnel.ike_lifetime_secs as i64)
        .bind(tunnel.esp_lifetime_secs as i64)
        .bind(tunnel.dpd_delay_secs as i64)
        .bind(tunnel.start_action.to_string())
        .bind(tunnel.created_at.to_rfc3339())
        .bind(tunnel.updated_at.to_rfc3339())
        .execute(exec)
        .await?;
        Ok(())
    }

    /// All tunnels, oldest first.
    pub async fn list_tunnels(&self) -> Result<Vec<IpsecTunnel>> {
        let rows = sqlx::query_as::<_, IpsecTunnelRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {IPSEC_TUNNEL_COLUMNS} FROM ipsec_tunnels ORDER BY created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(IpsecTunnelRow::into_tunnel).collect()
    }

    /// One tunnel by id.
    pub async fn get_tunnel(&self, id: Uuid) -> Result<IpsecTunnel> {
        let row = sqlx::query_as::<_, IpsecTunnelRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {IPSEC_TUNNEL_COLUMNS} FROM ipsec_tunnels WHERE id = ?1"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AifwError::NotFound(format!("IPsec tunnel {id} not found")))?;
        row.into_tunnel()
    }

    /// Validate and persist changes to an existing tunnel (matched by
    /// `tunnel.id`); bumps `updated_at`.
    pub async fn update_tunnel(&self, mut tunnel: IpsecTunnel) -> Result<IpsecTunnel> {
        tunnel.validate()?;
        tunnel.updated_at = chrono::Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE ipsec_tunnels SET
                name = ?2, enabled = ?3, local_addr = ?4, remote_addr = ?5,
                local_id = ?6, remote_id = ?7, auth_method = ?8, psk = ?9,
                cert_source = ?10, acme_cert_id = ?11, local_cert_pem = ?12,
                local_key_pem = ?13, ca_cert_pem = ?14, ike_proposal = ?15,
                esp_proposal = ?16, local_ts = ?17, remote_ts = ?18,
                ike_lifetime_secs = ?19, esp_lifetime_secs = ?20,
                dpd_delay_secs = ?21, start_action = ?22, updated_at = ?23
            WHERE id = ?1
            "#,
        )
        .bind(tunnel.id.to_string())
        .bind(&tunnel.name)
        .bind(tunnel.enabled as i64)
        .bind(&tunnel.local_addr)
        .bind(&tunnel.remote_addr)
        .bind(&tunnel.local_id)
        .bind(&tunnel.remote_id)
        .bind(tunnel.auth_method.to_string())
        .bind(&tunnel.psk)
        .bind(tunnel.cert_source.map(|s| s.to_string()))
        .bind(tunnel.acme_cert_id)
        .bind(&tunnel.local_cert_pem)
        .bind(&tunnel.local_key_pem)
        .bind(&tunnel.ca_cert_pem)
        .bind(&tunnel.ike_proposal)
        .bind(&tunnel.esp_proposal)
        .bind(tunnel.local_ts.join(","))
        .bind(tunnel.remote_ts.join(","))
        .bind(tunnel.ike_lifetime_secs as i64)
        .bind(tunnel.esp_lifetime_secs as i64)
        .bind(tunnel.dpd_delay_secs as i64)
        .bind(tunnel.start_action.to_string())
        .bind(tunnel.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "IPsec tunnel {} not found",
                tunnel.id
            )));
        }
        Ok(tunnel)
    }

    /// Delete a tunnel record. (The apply layer is responsible for
    /// terminating any live SA and removing rendered config first.)
    pub async fn delete_tunnel(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM ipsec_tunnels WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("IPsec tunnel {id} not found")));
        }
        Ok(())
    }

    // ============================================================
    // Apply lifecycle — DB is the source of truth; swanctl files are
    // derived state, regenerated wholesale on every apply.
    // ============================================================

    /// The complete set of swanctl files the current DB state demands:
    /// conn config per enabled tunnel, plus cert/key material for
    /// cert-auth tunnels (resolved from the ACME store or the stored
    /// PEM fields).
    async fn desired_files(
        &self,
        tunnels: &[IpsecTunnel],
    ) -> Result<std::collections::HashMap<String, Vec<u8>>> {
        use aifw_common::{IpsecAuthMethod, IpsecCertSource};

        let mut files = std::collections::HashMap::new();
        for t in tunnels.iter().filter(|t| t.enabled) {
            let conn = t.conn_name();
            files.insert(
                format!("{SWANCTL_CONF_DIR}/{conn}.conf"),
                render_swanctl_conf(t).into_bytes(),
            );

            if t.auth_method == IpsecAuthMethod::Cert {
                let (cert_pem, key_pem, chain_pem) = match t.cert_source {
                    Some(IpsecCertSource::Manual) => {
                        (t.local_cert_pem.clone(), t.local_key_pem.clone(), None)
                    }
                    Some(IpsecCertSource::Acme) => {
                        let id = t.acme_cert_id.ok_or_else(|| {
                            AifwError::Config(format!("tunnel {} has no acme_cert_id", t.name))
                        })?;
                        let cert =
                            crate::acme::load_cert(&self.pool, id)
                                .await
                                .ok_or_else(|| {
                                    AifwError::Config(format!(
                                        "ACME cert {id} referenced by tunnel {} not found",
                                        t.name
                                    ))
                                })?;
                        let cert_pem = cert.cert_pem.unwrap_or_default();
                        let key_pem = cert.key_pem.unwrap_or_default();
                        if cert_pem.is_empty() || key_pem.is_empty() {
                            return Err(AifwError::Config(format!(
                                "ACME cert {id} for tunnel {} has no issued material yet",
                                t.name
                            )));
                        }
                        (cert_pem, key_pem, cert.chain_pem.filter(|c| !c.is_empty()))
                    }
                    None => {
                        return Err(AifwError::Config(format!(
                            "tunnel {} uses cert auth without a cert source",
                            t.name
                        )));
                    }
                };
                files.insert(
                    format!("{SWANCTL_X509_DIR}/{conn}.pem"),
                    cert_pem.into_bytes(),
                );
                files.insert(
                    format!("{SWANCTL_PRIVATE_DIR}/{conn}.pem"),
                    key_pem.into_bytes(),
                );
                if let Some(chain) = chain_pem {
                    files.insert(
                        format!("{SWANCTL_X509CA_DIR}/{conn}-chain.pem"),
                        chain.into_bytes(),
                    );
                }
            }
            if !t.ca_cert_pem.is_empty() {
                files.insert(
                    format!("{SWANCTL_X509CA_DIR}/{conn}-ca.pem"),
                    t.ca_cert_pem.clone().into_bytes(),
                );
            }
        }
        Ok(files)
    }

    /// Regenerate every AiFw-managed swanctl file from the DB, remove
    /// stale ones, and `--load-all`. charon diffs the loaded config:
    /// changed conns are replaced, vanished conns are unloaded, and
    /// `start_action = start` children are (re)initiated.
    pub async fn apply_all(&self) -> Result<()> {
        let tunnels = self.list_tunnels().await?;
        let desired = self.desired_files(&tunnels).await?;
        let existing = self.store.list_managed().await?;

        for path in &existing {
            if !desired.contains_key(path)
                && let Err(e) = self.store.remove(path).await
            {
                tracing::warn!(path, error = %e, "ipsec: failed to remove stale swanctl file");
            }
        }
        for (path, content) in &desired {
            self.store.write(path, content).await?;
        }
        if desired.is_empty() && existing.is_empty() {
            // Nothing managed and nothing to clean up — don't poke charon
            // (it may not even be installed on a box that never used IPsec).
            return Ok(());
        }
        self.ensure_service().await;
        self.ike.load_all().await
    }

    /// Re-apply if any enabled tunnel resolves its certificate from ACME
    /// store row `cert_id` (#568). Called after that cert is renewed so the
    /// swanctl x509/private files pick up the new material; without this a
    /// tunnel keeps presenting the pre-renewal cert until some unrelated
    /// IPsec change triggers an apply. Returns whether an apply ran.
    /// Reload-safe: established SAs are unaffected until the next IKE
    /// re-auth/rekey presents the new cert.
    pub async fn reapply_for_acme_cert(&self, cert_id: i64) -> Result<bool> {
        let referenced: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM ipsec_tunnels \
             WHERE enabled = 1 AND cert_source = ? AND acme_cert_id = ?",
        )
        .bind(aifw_common::IpsecCertSource::Acme.to_string())
        .bind(cert_id)
        .fetch_one(&self.pool)
        .await?;
        if referenced == 0 {
            return Ok(false);
        }
        self.apply_all().await?;
        Ok(true)
    }

    /// Validate, persist, and apply a new tunnel. If the apply fails the
    /// record is rolled back and the previous rendered state restored,
    /// so a bad tunnel can't take down working ones.
    pub async fn create_tunnel_applied(&self, tunnel: IpsecTunnel) -> Result<IpsecTunnel> {
        let tunnel = self.add_tunnel(tunnel).await?;
        if let Err(e) = self.apply_all().await {
            tracing::warn!(tunnel = %tunnel.name, error = %e, "ipsec: apply failed — rolling back create");
            if let Err(re) = self.delete_tunnel(tunnel.id).await {
                tracing::warn!(error = %re, "ipsec: rollback delete failed");
            }
            if let Err(re) = self.apply_all().await {
                tracing::warn!(error = %re, "ipsec: rollback re-apply failed");
            }
            return Err(e);
        }
        Ok(tunnel)
    }

    /// Validate, persist, and apply changes to a tunnel. On apply
    /// failure the previous record is restored and re-applied.
    pub async fn update_tunnel_applied(&self, tunnel: IpsecTunnel) -> Result<IpsecTunnel> {
        let previous = self.get_tunnel(tunnel.id).await?;
        let updated = self.update_tunnel(tunnel).await?;
        if let Err(e) = self.apply_all().await {
            tracing::warn!(tunnel = %updated.name, error = %e, "ipsec: apply failed — restoring previous config");
            if let Err(re) = self.update_tunnel(previous).await {
                tracing::warn!(error = %re, "ipsec: rollback restore failed");
            }
            if let Err(re) = self.apply_all().await {
                tracing::warn!(error = %re, "ipsec: rollback re-apply failed");
            }
            return Err(e);
        }
        Ok(updated)
    }

    /// Terminate any live SA, delete the record, and apply (which
    /// removes the rendered files and unloads the conn).
    pub async fn delete_tunnel_applied(&self, id: Uuid) -> Result<()> {
        let tunnel = self.get_tunnel(id).await?;
        if let Err(e) = self.ike.terminate_ike(&tunnel.conn_name(), true).await {
            // Not fatal: the SA may simply not be up.
            tracing::debug!(tunnel = %tunnel.name, error = %e, "ipsec: terminate before delete failed");
        }
        self.delete_tunnel(id).await?;
        self.apply_all().await
    }

    /// Manually initiate a tunnel's child SA (negotiation outcome
    /// surfaces as the error string on failure).
    pub async fn start_tunnel(&self, id: Uuid) -> Result<()> {
        let tunnel = self.get_tunnel(id).await?;
        if !tunnel.enabled {
            return Err(AifwError::Validation(format!(
                "tunnel {} is disabled",
                tunnel.name
            )));
        }
        self.ike.initiate(&tunnel.child_name(), 30).await
    }

    /// Tear down a tunnel's IKE SA (and children). The config stays
    /// loaded; the peer or a manual start can bring it back up.
    pub async fn stop_tunnel(&self, id: Uuid) -> Result<()> {
        let tunnel = self.get_tunnel(id).await?;
        self.ike.terminate_ike(&tunnel.conn_name(), false).await
    }

    /// Reconcile rendered state with the DB at service startup — covers
    /// reboot, restore-from-backup, and upgrades. No-op when the box has
    /// never had IPsec tunnels.
    pub async fn ensure_applied(&self) -> Result<()> {
        let have_tunnels = !self.list_tunnels().await?.is_empty();
        let have_files = !self.store.list_managed().await?.is_empty();
        if have_tunnels || have_files {
            self.apply_all().await?;
        }
        Ok(())
    }

    /// Live negotiated status for every tunnel, ordered like
    /// `list_tunnels`. Tunnels charon has no SA for — including disabled
    /// ones — report as `DOWN`. A failing `list-sas` (charon not
    /// running) degrades to all-down rather than erroring: status pages
    /// must render on a box where IPsec never started.
    pub async fn live_status(&self) -> Result<Vec<IpsecLiveStatus>> {
        let tunnels = self.list_tunnels().await?;
        if tunnels.is_empty() {
            return Ok(Vec::new());
        }
        let raw = match self.ike.list_sas_raw().await {
            Ok(raw) => raw,
            Err(e) => {
                tracing::warn!(error = %e, "ipsec: list-sas failed — reporting all tunnels down");
                String::new()
            }
        };
        let mut live = crate::ipsec_status::parse_list_sas(&raw);
        Ok(tunnels
            .iter()
            .map(|t| {
                live.remove(&t.conn_name())
                    .unwrap_or_else(|| IpsecLiveStatus::down(t.id, t.conn_name()))
            })
            .collect())
    }

    /// Live negotiated status for one tunnel.
    pub async fn tunnel_status(&self, id: Uuid) -> Result<IpsecLiveStatus> {
        let tunnel = self.get_tunnel(id).await?;
        let raw = match self.ike.list_sas_raw().await {
            Ok(raw) => raw,
            Err(e) => {
                tracing::warn!(error = %e, "ipsec: list-sas failed — reporting tunnel down");
                String::new()
            }
        };
        let mut live = crate::ipsec_status::parse_list_sas(&raw);
        Ok(live
            .remove(&tunnel.conn_name())
            .unwrap_or_else(|| IpsecLiveStatus::down(tunnel.id, tunnel.conn_name())))
    }

    /// Make sure the strongSwan service is enabled and running before we
    /// talk to it (FreeBSD only; best-effort — a failure surfaces
    /// naturally as the subsequent `--load-all` error).
    async fn ensure_service(&self) {
        if !cfg!(target_os = "freebsd") {
            return;
        }
        let status = crate::sudo::service("strongswan", "status").await;
        let running = status.map(|o| o.status.success()).unwrap_or(false);
        if running {
            return;
        }
        if let Err(e) = crate::sudo::sysrc(&["strongswan_enable=YES"]).await {
            tracing::warn!(error = %e, "ipsec: failed to set strongswan_enable");
        }
        match crate::sudo::service("strongswan", "start").await {
            Ok(o) if !o.status.success() => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                tracing::warn!(stderr = %stderr.trim(), "ipsec: strongswan start failed");
            }
            Err(e) => tracing::warn!(error = %e, "ipsec: strongswan start failed"),
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use aifw_common::{IpsecAuthMethod, IpsecCertSource, IpsecStartAction};

    async fn engine() -> (IpsecEngine, Arc<MockIkeControl>, Arc<MemConfStore>) {
        let db = Database::new_in_memory().await.unwrap();
        let ike = Arc::new(MockIkeControl::new());
        let store = Arc::new(MemConfStore::new());
        let engine = IpsecEngine::new(db.pool().clone(), ike.clone(), store.clone());
        engine.migrate().await.unwrap();
        (engine, ike, store)
    }

    fn tunnel(name: &str) -> IpsecTunnel {
        IpsecTunnel::new(
            name.to_string(),
            "203.0.113.10".to_string(),
            "correct-horse-battery-staple".to_string(),
            vec!["10.0.0.0/24".to_string()],
            vec!["10.1.0.0/24".to_string()],
        )
    }

    #[tokio::test]
    async fn crud_roundtrip() {
        let (engine, _, _) = engine().await;
        let t = engine.add_tunnel(tunnel("site-a")).await.unwrap();

        let fetched = engine.get_tunnel(t.id).await.unwrap();
        assert_eq!(fetched.name, "site-a");
        assert_eq!(fetched.remote_addr, "203.0.113.10");
        assert_eq!(fetched.local_ts, vec!["10.0.0.0/24"]);
        assert_eq!(fetched.auth_method, IpsecAuthMethod::Psk);
        assert_eq!(fetched.start_action, IpsecStartAction::Start);

        let mut updated = fetched.clone();
        updated.remote_ts = vec!["10.2.0.0/16".to_string(), "10.3.0.0/24".to_string()];
        updated.enabled = false;
        engine.update_tunnel(updated).await.unwrap();
        let fetched = engine.get_tunnel(t.id).await.unwrap();
        assert_eq!(fetched.remote_ts.len(), 2);
        assert!(!fetched.enabled);
        assert!(fetched.updated_at >= fetched.created_at);

        engine.delete_tunnel(t.id).await.unwrap();
        assert!(matches!(
            engine.get_tunnel(t.id).await,
            Err(AifwError::NotFound(_))
        ));
        assert!(engine.list_tunnels().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn duplicate_name_rejected() {
        let (engine, _, _) = engine().await;
        engine.add_tunnel(tunnel("dup")).await.unwrap();
        assert!(engine.add_tunnel(tunnel("dup")).await.is_err());
    }

    #[tokio::test]
    async fn invalid_tunnel_rejected_before_persist() {
        let (engine, _, _) = engine().await;
        let mut t = tunnel("bad");
        t.psk = "short".to_string();
        assert!(matches!(
            engine.add_tunnel(t).await,
            Err(AifwError::Validation(_))
        ));
        assert!(engine.list_tunnels().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn update_missing_tunnel_is_not_found() {
        let (engine, _, _) = engine().await;
        assert!(matches!(
            engine.update_tunnel(tunnel("ghost")).await,
            Err(AifwError::NotFound(_))
        ));
        assert!(matches!(
            engine.delete_tunnel(Uuid::new_v4()).await,
            Err(AifwError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn cert_tunnel_roundtrip() {
        let (engine, _, _) = engine().await;
        let mut t = tunnel("cert-site");
        t.auth_method = IpsecAuthMethod::Cert;
        t.psk = String::new();
        t.cert_source = Some(IpsecCertSource::Manual);
        t.local_cert_pem =
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".to_string();
        t.local_key_pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".to_string();
        let t = engine.add_tunnel(t).await.unwrap();
        let fetched = engine.get_tunnel(t.id).await.unwrap();
        assert_eq!(fetched.auth_method, IpsecAuthMethod::Cert);
        assert_eq!(fetched.cert_source, Some(IpsecCertSource::Manual));
        assert!(fetched.local_key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn render_psk_conf_golden() {
        let mut t = tunnel("site-a");
        t.id = Uuid::nil();
        t.local_addr = "198.51.100.1".to_string();
        let conf = render_swanctl_conf(&t);
        let conn = "aifw-00000000-0000-0000-0000-000000000000";
        assert!(conf.contains(&format!("    {conn} {{")));
        assert!(conf.contains("version = 2"));
        assert!(conf.contains("local_addrs = 198.51.100.1"));
        assert!(conf.contains("remote_addrs = 203.0.113.10"));
        assert!(conf.contains("proposals = aes256gcm16-prfsha256-ecp256"));
        assert!(conf.contains("rekey_time = 14400s"));
        assert!(conf.contains("dpd_delay = 30s"));
        assert!(conf.contains("auth = psk"));
        assert!(conf.contains(&format!("{conn}-1 {{")));
        assert!(conf.contains("local_ts = 10.0.0.0/24"));
        assert!(conf.contains("remote_ts = 10.1.0.0/24"));
        assert!(conf.contains("esp_proposals = aes256gcm16-ecp256"));
        assert!(conf.contains("rekey_time = 3600s"));
        assert!(conf.contains("start_action = start"));
        assert!(conf.contains("dpd_action = restart"));
        assert!(conf.contains(&format!("ike-{conn} {{")));
        assert!(conf.contains("secret = \"correct-horse-battery-staple\""));
        assert!(conf.contains("id-1 = \"198.51.100.1\""));
        assert!(conf.contains("id-2 = \"203.0.113.10\""));
    }

    #[test]
    fn render_cert_conf_has_no_secrets_section() {
        let mut t = tunnel("cert-site");
        t.auth_method = IpsecAuthMethod::Cert;
        t.psk = String::new();
        t.cert_source = Some(IpsecCertSource::Manual);
        t.local_cert_pem =
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".to_string();
        t.local_key_pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".to_string();
        t.local_id = "CN=site-a".to_string();
        t.remote_id = "CN=site-b".to_string();
        t.validate().unwrap();
        let conf = render_swanctl_conf(&t);
        assert!(conf.contains("auth = pubkey"));
        assert!(conf.contains(&format!("certs = {}.pem", t.conn_name())));
        assert!(conf.contains("id = \"CN=site-a\""));
        assert!(conf.contains("id = \"CN=site-b\""));
        assert!(!conf.contains("secrets {"));
        assert!(!conf.contains("PRIVATE KEY")); // key material never in conf
    }

    #[test]
    fn render_multi_ts_and_trap() {
        let mut t = tunnel("multi");
        t.local_ts = vec!["10.0.0.0/24".to_string(), "10.5.0.0/24".to_string()];
        t.start_action = IpsecStartAction::Trap;
        let conf = render_swanctl_conf(&t);
        assert!(conf.contains("local_ts = 10.0.0.0/24,10.5.0.0/24"));
        assert!(conf.contains("start_action = trap"));
        assert!(conf.contains("dpd_action = trap"));
    }

    #[tokio::test]
    async fn apply_writes_conf_and_loads() {
        let (engine, ike, store) = engine().await;
        let t = engine
            .create_tunnel_applied(tunnel("site-a"))
            .await
            .unwrap();
        let conf_path = format!("{SWANCTL_CONF_DIR}/{}.conf", t.conn_name());
        let conf = String::from_utf8(store.get(&conf_path).unwrap()).unwrap();
        assert!(conf.contains("remote_addrs = 203.0.113.10"));
        ike.with_state(|s| assert_eq!(s.load_all_calls, 1));
    }

    #[tokio::test]
    async fn disabled_tunnel_not_rendered() {
        let (engine, _, store) = engine().await;
        let mut t = tunnel("off");
        t.enabled = false;
        engine.create_tunnel_applied(t).await.unwrap();
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn failed_apply_rolls_back_create() {
        let (engine, ike, store) = engine().await;
        engine.create_tunnel_applied(tunnel("good")).await.unwrap();
        assert_eq!(store.len(), 1);

        ike.with_state(|s| s.fail_load = Some("charon rejected config".to_string()));
        let err = engine
            .create_tunnel_applied(tunnel("bad"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("charon rejected config"));

        // Record rolled back; only the good tunnel's file remains after
        // the (also failing, but file-restoring) rollback re-apply.
        ike.with_state(|s| s.fail_load = None);
        let tunnels = engine.list_tunnels().await.unwrap();
        assert_eq!(tunnels.len(), 1);
        assert_eq!(tunnels[0].name, "good");
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn failed_apply_rolls_back_update() {
        let (engine, ike, _) = engine().await;
        let t = engine
            .create_tunnel_applied(tunnel("site-a"))
            .await
            .unwrap();

        ike.with_state(|s| s.fail_load = Some("boom".to_string()));
        let mut changed = t.clone();
        changed.remote_addr = "203.0.113.99".to_string();
        assert!(engine.update_tunnel_applied(changed).await.is_err());

        let fetched = engine.get_tunnel(t.id).await.unwrap();
        assert_eq!(fetched.remote_addr, "203.0.113.10");
    }

    #[tokio::test]
    async fn delete_terminates_and_removes_files() {
        let (engine, ike, store) = engine().await;
        let t = engine
            .create_tunnel_applied(tunnel("site-a"))
            .await
            .unwrap();
        assert_eq!(store.len(), 1);

        engine.delete_tunnel_applied(t.id).await.unwrap();
        assert!(store.is_empty());
        ike.with_state(|s| {
            assert_eq!(s.terminated, vec![t.conn_name()]);
            assert_eq!(s.load_all_calls, 2);
        });
        assert!(engine.list_tunnels().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn cert_tunnel_renders_material_files() {
        let (engine, _, store) = engine().await;
        let mut t = tunnel("cert-site");
        t.auth_method = IpsecAuthMethod::Cert;
        t.psk = String::new();
        t.cert_source = Some(IpsecCertSource::Manual);
        t.local_cert_pem =
            "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".to_string();
        t.local_key_pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".to_string();
        t.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----".to_string();
        let t = engine.create_tunnel_applied(t).await.unwrap();

        let conn = t.conn_name();
        assert!(
            store
                .get(&format!("{SWANCTL_CONF_DIR}/{conn}.conf"))
                .is_some()
        );
        assert!(
            store
                .get(&format!("{SWANCTL_X509_DIR}/{conn}.pem"))
                .is_some()
        );
        assert!(
            store
                .get(&format!("{SWANCTL_PRIVATE_DIR}/{conn}.pem"))
                .is_some()
        );
        assert!(
            store
                .get(&format!("{SWANCTL_X509CA_DIR}/{conn}-ca.pem"))
                .is_some()
        );

        engine.delete_tunnel_applied(t.id).await.unwrap();
        assert!(store.is_empty());
    }

    #[tokio::test]
    async fn acme_cert_source_missing_cert_fails_apply() {
        let (engine, _, _) = engine().await;
        crate::acme::migrate(&engine.pool).await.unwrap();
        let mut t = tunnel("acme-site");
        t.auth_method = IpsecAuthMethod::Cert;
        t.psk = String::new();
        t.cert_source = Some(IpsecCertSource::Acme);
        t.acme_cert_id = Some(999);
        let err = engine.create_tunnel_applied(t).await.unwrap_err();
        assert!(err.to_string().contains("not found"));
        assert!(engine.list_tunnels().await.unwrap().is_empty());
    }

    /// Insert an issued cert directly into `acme_cert` and return its id.
    async fn insert_acme_cert(pool: &SqlitePool, cert_pem: &str, key_pem: &str) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO acme_cert (common_name, status, cert_pem, key_pem) \
             VALUES ('vpn.example.com', 'active', ?, ?) RETURNING id",
        )
        .bind(cert_pem)
        .bind(key_pem)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    fn acme_tunnel(name: &str, cert_id: i64) -> IpsecTunnel {
        let mut t = tunnel(name);
        t.auth_method = IpsecAuthMethod::Cert;
        t.psk = String::new();
        t.cert_source = Some(IpsecCertSource::Acme);
        t.acme_cert_id = Some(cert_id);
        t
    }

    #[tokio::test]
    async fn acme_renewal_reapplies_referencing_tunnels() {
        let (engine, ike, store) = engine().await;
        crate::acme::migrate(&engine.pool).await.unwrap();
        let cert_id = insert_acme_cert(&engine.pool, "OLD-CERT", "OLD-KEY").await;
        let t = engine
            .create_tunnel_applied(acme_tunnel("acme-site", cert_id))
            .await
            .unwrap();
        let x509_path = format!("{SWANCTL_X509_DIR}/{}.pem", t.conn_name());
        assert_eq!(store.get(&x509_path), Some(b"OLD-CERT".to_vec()));

        // Simulate a renewal, then the #568 hook.
        sqlx::query("UPDATE acme_cert SET cert_pem = 'NEW-CERT', key_pem = 'NEW-KEY' WHERE id = ?")
            .bind(cert_id)
            .execute(&engine.pool)
            .await
            .unwrap();
        assert!(engine.reapply_for_acme_cert(cert_id).await.unwrap());
        assert_eq!(store.get(&x509_path), Some(b"NEW-CERT".to_vec()));
        ike.with_state(|s| assert_eq!(s.load_all_calls, 2));
    }

    #[tokio::test]
    async fn acme_renewal_skips_apply_when_cert_unreferenced() {
        let (engine, ike, _) = engine().await;
        crate::acme::migrate(&engine.pool).await.unwrap();
        let referenced = insert_acme_cert(&engine.pool, "CERT-A", "KEY-A").await;
        let unreferenced = insert_acme_cert(&engine.pool, "CERT-B", "KEY-B").await;
        let t = engine
            .create_tunnel_applied(acme_tunnel("acme-site", referenced))
            .await
            .unwrap();

        // Renewing a cert no tunnel points at must not poke charon.
        assert!(!engine.reapply_for_acme_cert(unreferenced).await.unwrap());
        ike.with_state(|s| assert_eq!(s.load_all_calls, 1));

        // A disabled tunnel isn't rendered, so its cert doesn't trigger
        // an apply either.
        let mut disabled = t.clone();
        disabled.enabled = false;
        engine.update_tunnel_applied(disabled).await.unwrap();
        ike.with_state(|s| assert_eq!(s.load_all_calls, 2));
        assert!(!engine.reapply_for_acme_cert(referenced).await.unwrap());
        ike.with_state(|s| assert_eq!(s.load_all_calls, 2));
    }

    #[tokio::test]
    async fn start_stop_drive_ike_control() {
        let (engine, ike, _) = engine().await;
        let t = engine
            .create_tunnel_applied(tunnel("site-a"))
            .await
            .unwrap();
        engine.start_tunnel(t.id).await.unwrap();
        engine.stop_tunnel(t.id).await.unwrap();
        ike.with_state(|s| {
            assert_eq!(s.initiated, vec![t.child_name()]);
            assert_eq!(s.terminated, vec![t.conn_name()]);
        });

        let mut disabled = t.clone();
        disabled.enabled = false;
        engine.update_tunnel_applied(disabled).await.unwrap();
        assert!(engine.start_tunnel(t.id).await.is_err());
    }

    #[tokio::test]
    async fn ensure_applied_noop_when_untouched() {
        let (engine, ike, _) = engine().await;
        engine.ensure_applied().await.unwrap();
        ike.with_state(|s| assert_eq!(s.load_all_calls, 0));

        engine
            .create_tunnel_applied(tunnel("site-a"))
            .await
            .unwrap();
        engine.ensure_applied().await.unwrap();
        ike.with_state(|s| assert_eq!(s.load_all_calls, 2));
    }

    #[tokio::test]
    async fn stale_files_removed_on_apply() {
        let (engine, _, store) = engine().await;
        store
            .write(&format!("{SWANCTL_CONF_DIR}/aifw-stale.conf"), b"leftover")
            .await
            .unwrap();
        engine
            .create_tunnel_applied(tunnel("site-a"))
            .await
            .unwrap();
        assert!(
            store
                .get(&format!("{SWANCTL_CONF_DIR}/aifw-stale.conf"))
                .is_none()
        );
        assert_eq!(store.len(), 1);
    }

    #[tokio::test]
    async fn mock_ike_records_calls() {
        let (_, ike, _) = engine().await;
        ike.load_all().await.unwrap();
        ike.initiate("aifw-x-1", 30).await.unwrap();
        ike.terminate_ike("aifw-x", false).await.unwrap();
        ike.with_state(|s| {
            assert_eq!(s.load_all_calls, 1);
            assert_eq!(s.initiated, vec!["aifw-x-1"]);
            assert_eq!(s.terminated, vec!["aifw-x"]);
        });
        ike.with_state(|s| s.fail_load = Some("boom".to_string()));
        assert!(ike.load_all().await.is_err());
    }
}
