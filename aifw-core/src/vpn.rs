use aifw_common::{
    Address, AifwError, Interface, IpsecMode, IpsecProtocol, IpsecSa, Result, VpnStatus, WgPeer,
    WgTunnel,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use tokio::process::Command;
use uuid::Uuid;

/// VPN engine: WireGuard tunnels and peers (`wg_tunnels`, `wg_peers`
/// tables) and IPsec SAs (`ipsec_sas` table). Tunnel lifecycle shells out
/// to ifconfig/wg on FreeBSD; VPN pf rules use the `aifw-vpn` anchor.
pub struct VpnEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
}

impl VpnEngine {
    /// Build a VPN engine over the shared pool and pf backend, targeting
    /// the `aifw-vpn` anchor
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: "aifw-vpn".to_string(),
        }
    }

    /// Create the `wg_tunnels`, `wg_peers`, `ipsec_sas`, and shared
    /// `interface_roles` tables if missing, plus idempotent column adds and
    /// the indexes used by write-path validation lookups
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wg_tunnels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                interface TEXT NOT NULL,
                private_key TEXT NOT NULL,
                public_key TEXT NOT NULL,
                listen_port INTEGER NOT NULL,
                address TEXT NOT NULL,
                dns TEXT,
                mtu INTEGER,
                status TEXT NOT NULL DEFAULT 'down',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS wg_peers (
                id TEXT PRIMARY KEY,
                tunnel_id TEXT NOT NULL,
                name TEXT NOT NULL,
                public_key TEXT NOT NULL,
                preshared_key TEXT,
                endpoint TEXT,
                allowed_ips TEXT NOT NULL DEFAULT 'any',
                persistent_keepalive INTEGER,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (tunnel_id) REFERENCES wg_tunnels(id) ON DELETE CASCADE
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // Add client_private_key column if missing (idempotent migration)
        let _ = sqlx::query("ALTER TABLE wg_peers ADD COLUMN client_private_key TEXT")
            .execute(&self.pool)
            .await;

        // Add listen_interface column to tunnels if missing
        let _ = sqlx::query("ALTER TABLE wg_tunnels ADD COLUMN listen_interface TEXT")
            .execute(&self.pool)
            .await;

        // Add split_routes column: comma-separated CIDRs used for split-tunnel
        // AllowedIPs. NULL means fall back to tunnel's own network CIDR.
        let _ = sqlx::query("ALTER TABLE wg_tunnels ADD COLUMN split_routes TEXT")
            .execute(&self.pool)
            .await;

        // Add address6 column: the server's IPv6 tunnel address for
        // dual-stack tunnels (#471). NULL means no inner IPv6.
        let _ = sqlx::query("ALTER TABLE wg_tunnels ADD COLUMN address6 TEXT")
            .execute(&self.pool)
            .await;

        // Shared with aifw-setup / aifw-api (QUAL-C5) — wan_interface() below
        // reads it to build the WireGuard outbound NAT rule.
        sqlx::query(aifw_common::schemas::INTERFACE_ROLES_CREATE)
            .execute(&self.pool)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS ipsec_sas (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                src_addr TEXT NOT NULL,
                dst_addr TEXT NOT NULL,
                protocol TEXT NOT NULL,
                mode TEXT NOT NULL,
                spi INTEGER NOT NULL,
                enc_algo TEXT NOT NULL,
                auth_algo TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'down',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        // PERF-H5: index the columns the write-path validation queries hit so
        // the duplicate-port and per-tunnel peer lookups don't scan.
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_wg_tunnels_listen_port ON wg_tunnels(listen_port);",
        )
        .execute(&self.pool)
        .await?;
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_wg_peers_tunnel_id ON wg_peers(tunnel_id);")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    // ============================================================
    // WireGuard tunnels
    // ============================================================

    /// Insert a WireGuard tunnel row (including its private key). Fails
    /// validation when the name is empty, the listen port is 0, or another
    /// tunnel already uses that listen port. Does not bring the interface
    /// up — see [`Self::start_tunnel`]
    pub async fn add_wg_tunnel(&self, tunnel: WgTunnel) -> Result<WgTunnel> {
        if tunnel.name.is_empty() {
            return Err(AifwError::Validation("tunnel name required".to_string()));
        }
        if tunnel.listen_port == 0 {
            return Err(AifwError::Validation("listen port required".to_string()));
        }

        // Check for duplicate port (PERF-H5: targeted query, not a full scan).
        if let Some((name,)) = sqlx::query_as::<_, (String,)>(
            "SELECT name FROM wg_tunnels WHERE listen_port = ?1 AND id != ?2 LIMIT 1",
        )
        .bind(tunnel.listen_port as i64)
        .bind(tunnel.id.to_string())
        .fetch_optional(&self.pool)
        .await?
        {
            return Err(AifwError::Validation(format!(
                "Port {} is already used by tunnel '{}'",
                tunnel.listen_port, name
            )));
        }

        Self::insert_wg_tunnel_on(&self.pool, &tunnel).await?;

        tracing::info!(id = %tunnel.id, name = %tunnel.name, "WireGuard tunnel added");
        Ok(tunnel)
    }

    /// Executor-generic validate + insert with no duplicate-port lookup
    /// (callers must ensure port uniqueness, e.g. the restore path
    /// pre-validates the whole config). Public for the transactional restore
    /// path (#158/#535).
    pub async fn insert_wg_tunnel_on<'e, E>(exec: E, tunnel: &WgTunnel) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        if tunnel.name.is_empty() {
            return Err(AifwError::Validation("tunnel name required".to_string()));
        }
        if tunnel.listen_port == 0 {
            return Err(AifwError::Validation("listen port required".to_string()));
        }
        tunnel.validate_addresses()?;
        sqlx::query(
            r#"
            INSERT INTO wg_tunnels (id, name, interface, private_key, public_key, listen_port,
                address, address6, dns, mtu, listen_interface, split_routes, status,
                created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
            "#,
        )
        .bind(tunnel.id.to_string())
        .bind(&tunnel.name)
        .bind(&tunnel.interface.0)
        .bind(&tunnel.private_key)
        .bind(&tunnel.public_key)
        .bind(tunnel.listen_port as i64)
        .bind(tunnel.address.to_string())
        .bind(tunnel.address6.as_ref().map(|a| a.to_string()))
        .bind(tunnel.dns.as_deref())
        .bind(tunnel.mtu.map(|m| m as i64))
        .bind(tunnel.listen_interface.as_deref())
        .bind(tunnel.split_routes.as_deref())
        .bind(tunnel.status.to_string())
        .bind(tunnel.created_at.to_rfc3339())
        .bind(tunnel.updated_at.to_rfc3339())
        .execute(exec)
        .await?;
        Ok(())
    }

    /// All WireGuard tunnels, oldest first
    pub async fn list_wg_tunnels(&self) -> Result<Vec<WgTunnel>> {
        let rows = sqlx::query_as::<_, WgTunnelRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {WG_TUNNEL_COLUMNS} FROM wg_tunnels ORDER BY created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_tunnel()).collect()
    }

    /// Fetch a WireGuard tunnel by id. Fails with `NotFound` if it doesn't
    /// exist
    pub async fn get_wg_tunnel(&self, id: Uuid) -> Result<WgTunnel> {
        let row = sqlx::query_as::<_, WgTunnelRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {WG_TUNNEL_COLUMNS} FROM wg_tunnels WHERE id = ?1"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AifwError::NotFound(format!("WG tunnel {id} not found")))?;
        row.into_tunnel()
    }

    /// Update a tunnel's settings (including keys). Same validation as
    /// [`Self::add_wg_tunnel`]: non-empty name, non-zero and non-duplicate
    /// listen port. Fails with `NotFound` for an unknown id
    pub async fn update_wg_tunnel(&self, tunnel: WgTunnel) -> Result<WgTunnel> {
        if tunnel.name.is_empty() {
            return Err(AifwError::Validation("tunnel name required".to_string()));
        }
        if tunnel.listen_port == 0 {
            return Err(AifwError::Validation("listen port required".to_string()));
        }

        // PERF-H5: targeted duplicate-port check, not a full-table scan.
        if let Some((name,)) = sqlx::query_as::<_, (String,)>(
            "SELECT name FROM wg_tunnels WHERE listen_port = ?1 AND id != ?2 LIMIT 1",
        )
        .bind(tunnel.listen_port as i64)
        .bind(tunnel.id.to_string())
        .fetch_optional(&self.pool)
        .await?
        {
            return Err(AifwError::Validation(format!(
                "Port {} is already used by tunnel '{}'",
                tunnel.listen_port, name
            )));
        }

        tunnel.validate_addresses()?;

        let result = sqlx::query(
            r#"
            UPDATE wg_tunnels
               SET name = ?1, listen_port = ?2, address = ?3, address6 = ?4, dns = ?5,
                   mtu = ?6, listen_interface = ?7, split_routes = ?8,
                   private_key = ?9, public_key = ?10, updated_at = ?11
             WHERE id = ?12
            "#,
        )
        .bind(&tunnel.name)
        .bind(tunnel.listen_port as i64)
        .bind(tunnel.address.to_string())
        .bind(tunnel.address6.as_ref().map(|a| a.to_string()))
        .bind(tunnel.dns.as_deref())
        .bind(tunnel.mtu.map(|m| m as i64))
        .bind(tunnel.listen_interface.as_deref())
        .bind(tunnel.split_routes.as_deref())
        .bind(&tunnel.private_key)
        .bind(&tunnel.public_key)
        .bind(tunnel.updated_at.to_rfc3339())
        .bind(tunnel.id.to_string())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "WG tunnel {} not found",
                tunnel.id
            )));
        }

        tracing::info!(id = %tunnel.id, name = %tunnel.name, "WireGuard tunnel updated");
        Ok(tunnel)
    }

    /// Delete a tunnel and all of its peers. Fails with `NotFound` for an
    /// unknown id
    pub async fn delete_wg_tunnel(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM wg_tunnels WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("WG tunnel {id} not found")));
        }
        // Cascade deletes peers
        sqlx::query("DELETE FROM wg_peers WHERE tunnel_id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        tracing::info!(%id, "WireGuard tunnel deleted");
        Ok(())
    }

    // ============================================================
    // WireGuard peers
    // ============================================================

    /// Insert a peer on an existing tunnel. Fails validation when the
    /// public key is empty, the tunnel doesn't exist, or one of the peer's
    /// allowed IPs is already assigned to another peer in the same tunnel
    pub async fn add_wg_peer(&self, peer: WgPeer) -> Result<WgPeer> {
        if peer.public_key.is_empty() {
            return Err(AifwError::Validation(
                "peer public key required".to_string(),
            ));
        }
        // Verify tunnel exists
        let _ = self.get_wg_tunnel(peer.tunnel_id).await?;

        // Check for duplicate IPs — no two peers in the same tunnel can share an IP
        let existing_peers = self.list_wg_peers(peer.tunnel_id).await?;
        let new_ips: std::collections::HashSet<String> = peer
            .allowed_ips
            .iter()
            .map(|a| a.to_string().split('/').next().unwrap_or("").to_string())
            .collect();
        for ep in &existing_peers {
            for eip in &ep.allowed_ips {
                let eip_str = eip.to_string().split('/').next().unwrap_or("").to_string();
                if new_ips.contains(&eip_str) {
                    return Err(AifwError::Validation(format!(
                        "IP {} is already assigned to peer '{}'",
                        eip_str, ep.name
                    )));
                }
            }
        }

        Self::insert_wg_peer_on(&self.pool, &peer).await?;

        tracing::info!(id = %peer.id, name = %peer.name, "WireGuard peer added");
        Ok(peer)
    }

    /// Executor-generic validate + insert with no tunnel-exists or
    /// duplicate-IP lookups (the restore path inserts the tunnel in the same
    /// transaction, so those pool-side reads would not see it). Public for
    /// the transactional restore path (#158/#535).
    pub async fn insert_wg_peer_on<'e, E>(exec: E, peer: &WgPeer) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        if peer.public_key.is_empty() {
            return Err(AifwError::Validation(
                "peer public key required".to_string(),
            ));
        }
        let allowed_ips: Vec<String> = peer.allowed_ips.iter().map(|a| a.to_string()).collect();

        sqlx::query(
            r#"
            INSERT INTO wg_peers (id, tunnel_id, name, public_key, preshared_key, client_private_key,
                endpoint, allowed_ips, persistent_keepalive, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
            "#,
        )
        .bind(peer.id.to_string())
        .bind(peer.tunnel_id.to_string())
        .bind(&peer.name)
        .bind(&peer.public_key)
        .bind(peer.preshared_key.as_deref())
        .bind(peer.client_private_key.as_deref())
        .bind(peer.endpoint.as_deref())
        .bind(allowed_ips.join(","))
        .bind(peer.persistent_keepalive.map(|k| k as i64))
        .bind(peer.created_at.to_rfc3339())
        .bind(peer.updated_at.to_rfc3339())
        .execute(exec)
        .await?;
        Ok(())
    }

    /// Peers of one tunnel, oldest first
    pub async fn list_wg_peers(&self, tunnel_id: Uuid) -> Result<Vec<WgPeer>> {
        let rows = sqlx::query_as::<_, WgPeerRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {WG_PEER_COLUMNS} FROM wg_peers WHERE tunnel_id = ?1 ORDER BY created_at ASC"
        )))
        .bind(tunnel_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_peer()).collect()
    }

    /// PERF-H7: fetch every peer in one query and group by tunnel id. Callers
    /// that need peers for many tunnels at once (e.g. config snapshot/backup)
    /// use this instead of an N+1 loop of [`Self::list_wg_peers`].
    pub async fn list_all_wg_peers_grouped(
        &self,
    ) -> Result<std::collections::HashMap<Uuid, Vec<WgPeer>>> {
        let rows = sqlx::query_as::<_, WgPeerRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {WG_PEER_COLUMNS} FROM wg_peers ORDER BY tunnel_id ASC, created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;

        let mut grouped: std::collections::HashMap<Uuid, Vec<WgPeer>> =
            std::collections::HashMap::new();
        for row in rows {
            let peer = row.into_peer()?;
            grouped.entry(peer.tunnel_id).or_default().push(peer);
        }
        Ok(grouped)
    }

    /// Fetch a peer by id. Fails with `NotFound` if it doesn't exist
    pub async fn get_wg_peer(&self, id: Uuid) -> Result<WgPeer> {
        let row = sqlx::query_as::<_, WgPeerRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {WG_PEER_COLUMNS} FROM wg_peers WHERE id = ?1"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AifwError::NotFound(format!("WG peer {id} not found")))?;
        row.into_peer()
    }

    /// Update a peer's settings; updating an unknown id is silently a no-op
    pub async fn update_wg_peer(&self, peer: &WgPeer) -> Result<()> {
        let allowed_ips: Vec<String> = peer.allowed_ips.iter().map(|a| a.to_string()).collect();
        sqlx::query(
            r#"
            UPDATE wg_peers SET name = ?1, public_key = ?2, preshared_key = ?3,
                client_private_key = ?4, endpoint = ?5, allowed_ips = ?6,
                persistent_keepalive = ?7, updated_at = ?8
            WHERE id = ?9
            "#,
        )
        .bind(&peer.name)
        .bind(&peer.public_key)
        .bind(peer.preshared_key.as_deref())
        .bind(peer.client_private_key.as_deref())
        .bind(peer.endpoint.as_deref())
        .bind(allowed_ips.join(","))
        .bind(peer.persistent_keepalive.map(|k| k as i64))
        .bind(Utc::now().to_rfc3339())
        .bind(peer.id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a peer. Fails with `NotFound` for an unknown id
    pub async fn delete_wg_peer(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM wg_peers WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("WG peer {id} not found")));
        }
        Ok(())
    }

    // ============================================================
    // IPsec SAs
    // ============================================================

    /// Insert an IPsec security-association row. Fails validation when the
    /// name is empty
    pub async fn add_ipsec_sa(&self, sa: IpsecSa) -> Result<IpsecSa> {
        Self::insert_ipsec_sa_on(&self.pool, &sa).await?;
        tracing::info!(id = %sa.id, name = %sa.name, "IPsec SA added");
        Ok(sa)
    }

    /// Executor-generic validate + insert. Public for the transactional
    /// restore path (#158/#535).
    pub async fn insert_ipsec_sa_on<'e, E>(exec: E, sa: &IpsecSa) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        if sa.name.is_empty() {
            return Err(AifwError::Validation("SA name required".to_string()));
        }

        sqlx::query(
            r#"
            INSERT INTO ipsec_sas (id, name, src_addr, dst_addr, protocol, mode, spi,
                enc_algo, auth_algo, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
            "#,
        )
        .bind(sa.id.to_string())
        .bind(&sa.name)
        .bind(sa.src_addr.to_string())
        .bind(sa.dst_addr.to_string())
        .bind(sa.protocol.to_string())
        .bind(sa.mode.to_string())
        .bind(sa.spi as i64)
        .bind(&sa.enc_algo)
        .bind(&sa.auth_algo)
        .bind(sa.status.to_string())
        .bind(sa.created_at.to_rfc3339())
        .bind(sa.updated_at.to_rfc3339())
        .execute(exec)
        .await?;
        Ok(())
    }

    /// All IPsec SAs, oldest first
    pub async fn list_ipsec_sas(&self) -> Result<Vec<IpsecSa>> {
        let rows = sqlx::query_as::<_, IpsecSaRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {IPSEC_SA_COLUMNS} FROM ipsec_sas ORDER BY created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_sa()).collect()
    }

    /// Delete an IPsec SA. Fails with `NotFound` for an unknown id
    pub async fn delete_ipsec_sa(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM ipsec_sas WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("IPsec SA {id} not found")));
        }
        tracing::info!(%id, "IPsec SA deleted");
        Ok(())
    }

    // ============================================================
    // WireGuard tunnel lifecycle (FreeBSD)
    // ============================================================

    /// Bring up a WireGuard tunnel: create interface, set key, add peers, update status.
    pub async fn start_tunnel(&self, id: Uuid) -> Result<()> {
        let tunnel = self.get_wg_tunnel(id).await?;
        let iface = &tunnel.interface.0;

        // Write private key to temp file (wg set reads from file, not stdin)
        let key_path = format!("/tmp/wg-{}.key", tunnel.id);
        tokio::fs::write(&key_path, &tunnel.private_key)
            .await
            .map_err(|e| AifwError::Pf(format!("Failed to write key file: {e}")))?;
        // Restrict permissions
        let _ = Command::new("chmod")
            .args(["600", &key_path])
            .output()
            .await;

        // Create the WireGuard interface
        let _ = crate::sudo::ifconfig(iface, "destroy", &[]).await; // clean up if exists
        let output = crate::sudo::ifconfig(iface, "create", &[])
            .await
            .map_err(|e| AifwError::Pf(format!("ifconfig create failed: {e}")))?;
        if !output.status.success() {
            let _ = tokio::fs::remove_file(&key_path).await;
            return Err(AifwError::Pf(format!(
                "ifconfig {} create failed: {}",
                iface,
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Set addresses and bring up. The keyword must match the address
        // family — FreeBSD's `ifconfig <if> inet <v6-addr>` fails, which is
        // how IPv6 tunnel addresses used to silently not configure (#471).
        let addr = tunnel.address.to_string();
        let v6_primary = matches!(
            &tunnel.address,
            Address::Single(std::net::IpAddr::V6(_)) | Address::Network(std::net::IpAddr::V6(_), _)
        );
        if v6_primary {
            Self::ifconfig_logged(iface, "inet6", &[&addr]).await;
            Self::ifconfig_logged(iface, "up", &[]).await;
        } else {
            Self::ifconfig_logged(iface, "inet", &[&addr, "up"]).await;
        }
        if let Some(ref a6) = tunnel.address6 {
            let a6 = a6.to_string();
            Self::ifconfig_logged(iface, "inet6", &[&a6]).await;
        }

        // Set MTU if specified
        if let Some(mtu) = tunnel.mtu {
            let mtu_s = mtu.to_string();
            let _ = crate::sudo::ifconfig(iface, "mtu", &[&mtu_s]).await;
        }

        // Configure WireGuard private key and listen port.
        //
        // HA: WireGuard binds 0.0.0.0 by default (wireguard-go), so CARP VIPs
        // floating on the WAN interface are accepted automatically — no explicit
        // ListenAddress override needed. Some WG implementations support
        // ListenAddress for explicit binding; if AiFw ever migrates to one,
        // this is where the per-iface bind would be wired.
        //
        // TODO(#486): WG role-change subscriber for explicit wg-quick down on BACKUP
        // (default-false `wg_deconfigure_on_backup` flag, deferred — out of
        // scope for Commit 9 #222).
        let listen_port_s = tunnel.listen_port.to_string();
        let output = crate::sudo::wg(
            "set",
            iface,
            &["private-key", &key_path, "listen-port", &listen_port_s],
        )
        .await
        .map_err(|e| AifwError::Pf(format!("wg set failed: {e}")))?;
        let _ = tokio::fs::remove_file(&key_path).await;
        if !output.status.success() {
            let _ = crate::sudo::ifconfig(iface, "destroy", &[]).await;
            return Err(AifwError::Pf(format!(
                "wg set failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }

        // Add all peers
        let peers = self.list_wg_peers(id).await?;
        for peer in &peers {
            self.apply_peer_to_interface(iface, peer).await?;
        }

        // Update status in DB
        let _ = sqlx::query("UPDATE wg_tunnels SET status = 'up', updated_at = ?1 WHERE id = ?2")
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await;

        // Refresh the aifw-vpn anchor: opens WAN UDP for this tunnel's
        // listen-port (without it, handshakes are dropped by the default
        // block rule) and adds outbound NAT so clients reach the internet.
        if let Err(e) = self.apply_vpn_rules().await {
            tracing::warn!(%id, error = %e, "failed to refresh aifw-vpn anchor after start");
        }

        tracing::info!(%id, iface, "WireGuard tunnel started");
        Ok(())
    }

    /// Run an ifconfig action, logging (not failing) on error. Address
    /// configuration problems shouldn't abort tunnel startup, but they must
    /// be visible — a swallowed error here is how IPv6 addresses silently
    /// failed to configure before #471.
    async fn ifconfig_logged(iface: &str, action: &str, args: &[&str]) {
        match crate::sudo::ifconfig(iface, action, args).await {
            Ok(out) if !out.status.success() => {
                tracing::warn!(
                    iface,
                    action,
                    stderr = %String::from_utf8_lossy(&out.stderr),
                    "ifconfig failed"
                );
            }
            Err(e) => tracing::warn!(iface, action, error = %e, "ifconfig failed"),
            _ => {}
        }
    }

    /// Stop a WireGuard tunnel: destroy the interface.
    pub async fn stop_tunnel(&self, id: Uuid) -> Result<()> {
        let tunnel = self.get_wg_tunnel(id).await?;
        let iface = &tunnel.interface.0;

        let _ = crate::sudo::ifconfig(iface, "destroy", &[]).await;

        let _ = sqlx::query("UPDATE wg_tunnels SET status = 'down', updated_at = ?1 WHERE id = ?2")
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await;

        // Close this tunnel's pass + NAT rules by recomputing from remaining
        // up tunnels only.
        if let Err(e) = self.apply_vpn_rules().await {
            tracing::warn!(%id, error = %e, "failed to refresh aifw-vpn anchor after stop");
        }

        tracing::info!(%id, iface, "WireGuard tunnel stopped");
        Ok(())
    }

    /// Apply a single peer to a running WireGuard interface via `wg set`.
    async fn apply_peer_to_interface(&self, iface: &str, peer: &WgPeer) -> Result<()> {
        let allowed: Vec<String> = peer.allowed_ips.iter().map(|a| a.to_string()).collect();
        let allowed_joined = allowed.join(",");
        let mut args: Vec<String> = vec![
            "peer".to_string(),
            peer.public_key.clone(),
            "allowed-ips".to_string(),
            allowed_joined,
        ];
        if let Some(ref endpoint) = peer.endpoint
            && !endpoint.is_empty()
        {
            args.push("endpoint".to_string());
            args.push(endpoint.clone());
        }
        if let Some(ka) = peer.persistent_keepalive {
            args.push("persistent-keepalive".to_string());
            args.push(ka.to_string());
        }
        // PSK requires a temp file
        let psk_path = if let Some(ref psk) = peer.preshared_key {
            let path = format!("/tmp/wg-psk-{}.key", peer.id);
            tokio::fs::write(&path, psk)
                .await
                .map_err(|e| AifwError::Pf(format!("Failed to write PSK: {e}")))?;
            let _ = Command::new("chmod").args(["600", &path]).output().await;
            args.push("preshared-key".to_string());
            args.push(path.clone());
            Some(path)
        } else {
            None
        };

        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = crate::sudo::wg("set", iface, &arg_refs)
            .await
            .map_err(|e| AifwError::Pf(format!("wg set peer failed: {e}")))?;

        if let Some(ref path) = psk_path {
            let _ = tokio::fs::remove_file(path).await;
        }

        if !output.status.success() {
            return Err(AifwError::Pf(format!(
                "wg set peer failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(())
    }

    /// Get live tunnel status from `wg show`.
    pub async fn tunnel_status(&self, id: Uuid) -> Result<serde_json::Value> {
        let tunnel = self.get_wg_tunnel(id).await?;
        let iface = &tunnel.interface.0;

        let output = crate::sudo::wg("show", iface, &["dump"])
            .await
            .map_err(|e| AifwError::Pf(format!("wg show failed: {e}")))?;

        if !output.status.success() {
            return Ok(serde_json::json!({
                "running": false,
                "interface": iface,
                "peers": [],
            }));
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut peers = Vec::new();
        let mut lines = text.lines();
        // First line is the interface info: private-key, public-key, listen-port, fwmark
        let _iface_line = lines.next();

        // Remaining lines are peers: public-key, preshared-key, endpoint, allowed-ips, latest-handshake, transfer-rx, transfer-tx, persistent-keepalive
        for line in lines {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 7 {
                let handshake_ts: i64 = cols[4].parse().unwrap_or(0);
                let handshake_ago = if handshake_ts > 0 {
                    Utc::now().timestamp() - handshake_ts
                } else {
                    -1
                };
                peers.push(serde_json::json!({
                    "public_key": cols[0],
                    "endpoint": if cols[2] == "(none)" { serde_json::Value::Null } else { serde_json::Value::String(cols[2].to_string()) },
                    "allowed_ips": cols[3],
                    "latest_handshake_secs_ago": handshake_ago,
                    "transfer_rx": cols[5].parse::<u64>().unwrap_or(0),
                    "transfer_tx": cols[6].parse::<u64>().unwrap_or(0),
                    "persistent_keepalive": if cols.len() > 7 && cols[7] != "off" { cols[7].parse::<u16>().ok() } else { None::<u16> },
                }));
            }
        }

        Ok(serde_json::json!({
            "running": true,
            "interface": iface,
            "listen_port": tunnel.listen_port,
            "public_key": tunnel.public_key,
            "peer_count": peers.len(),
            "peers": peers,
        }))
    }

    /// Start all tunnels that have status "up" in the DB (for boot recovery).
    pub async fn start_active_tunnels(&self) -> Result<u32> {
        let tunnels = self.list_wg_tunnels().await?;
        let mut started = 0u32;
        for t in &tunnels {
            if t.status == VpnStatus::Up {
                if let Err(e) = self.start_tunnel(t.id).await {
                    tracing::warn!(id = %t.id, name = %t.name, error = %e, "Failed to restart tunnel");
                } else {
                    started += 1;
                }
            }
        }
        Ok(started)
    }

    /// Compute the next available IP(s) in a tunnel's subnet for
    /// auto-assigning to a new peer. IPv4 tunnels yield `a.b.c.d/32`;
    /// dual-stack tunnels (#471) yield `a.b.c.d/32, x::y/128` so the new
    /// peer gets an address in every family the tunnel carries. Errors when
    /// any carried family has no free addresses left — a dual-stack peer
    /// with only half its addresses would silently lose one family.
    pub async fn next_peer_ip(&self, tunnel_id: Uuid) -> Result<String> {
        use std::net::IpAddr;

        let tunnel = self.get_wg_tunnel(tunnel_id).await?;
        let peers = self.list_wg_peers(tunnel_id).await?;
        let used: std::collections::HashSet<IpAddr> = peers
            .iter()
            .flat_map(|p| p.allowed_ips.iter())
            .filter_map(|a| match a {
                Address::Single(ip) => Some(*ip),
                Address::Network(ip, _) => Some(*ip),
                _ => None,
            })
            .collect();

        let mut parts: Vec<String> = Vec::new();
        // A Single (prefix-less) tunnel address falls back to the
        // conventional subnet size for its family.
        match &tunnel.address {
            Address::Single(IpAddr::V4(ip)) => parts.push(next_free_v4(*ip, 24, &used)?),
            Address::Network(IpAddr::V4(ip), p) => parts.push(next_free_v4(*ip, *p, &used)?),
            Address::Single(IpAddr::V6(ip)) => parts.push(next_free_v6(*ip, 64, &used)?),
            Address::Network(IpAddr::V6(ip), p) => parts.push(next_free_v6(*ip, *p, &used)?),
            _ => return Err(AifwError::Validation("Invalid tunnel address".to_string())),
        }
        match &tunnel.address6 {
            Some(Address::Single(IpAddr::V6(ip))) => parts.push(next_free_v6(*ip, 64, &used)?),
            Some(Address::Network(IpAddr::V6(ip), p)) => parts.push(next_free_v6(*ip, *p, &used)?),
            _ => {}
        }
        Ok(parts.join(", "))
    }

    // ============================================================
    // Apply VPN pf rules
    // ============================================================

    /// Collect VPN pf filter (pass) rules without loading them. Only tunnels
    /// marked up contribute rules — a stopped tunnel must not hold its
    /// listen-port open. Enabled IPsec tunnels (#530 `ipsec_tunnels`)
    /// contribute IKE/ESP/enc0 rules; legacy `ipsec_sas` records are
    /// configuration-only and deliberately emit nothing — they never had a
    /// data plane, so their pf holes were pure attack surface.
    pub async fn collect_vpn_rules(&self) -> Result<Vec<String>> {
        let mut pf_rules = Vec::new();
        let tunnels = self.list_wg_tunnels().await?;
        for t in tunnels.iter().filter(|t| t.status == VpnStatus::Up) {
            pf_rules.extend(t.to_pf_rules());
        }
        // Tolerate a missing ipsec_tunnels table: some callers (daemon
        // early boot, partial restores) run before IpsecEngine::migrate.
        match sqlx::query_as::<_, (String, String, String)>(
            "SELECT id, local_addr, remote_addr FROM ipsec_tunnels WHERE enabled = 1 ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => {
                for (id, local, remote) in &rows {
                    pf_rules.extend(aifw_common::ipsec::endpoint_pf_rules(
                        &format!("aifw-{id}"),
                        local,
                        remote,
                    ));
                }
            }
            Err(e) => {
                tracing::debug!(error = %e, "ipsec_tunnels not readable (pre-migration?) — no IPsec pf rules");
            }
        }
        Ok(pf_rules)
    }

    /// Collect outbound NAT rules for up WireGuard tunnels so clients reach
    /// the internet through the WAN (#469). These load into the `aifw-vpn`
    /// nat-anchor declared in pf.conf — do NOT mix them into the filter-rule
    /// extras, pfctl requires translation rules before filter rules.
    pub async fn collect_vpn_nat_rules(&self) -> Result<Vec<String>> {
        let tunnels = self.list_wg_tunnels().await?;
        let up: Vec<&WgTunnel> = tunnels
            .iter()
            .filter(|t| t.status == VpnStatus::Up)
            .collect();
        if up.is_empty() {
            return Ok(Vec::new());
        }
        let Some(wan) = self.wan_interface().await else {
            tracing::warn!(
                "no WAN interface role assigned — WireGuard clients will not be NAT'd to the internet"
            );
            return Ok(Vec::new());
        };
        Ok(up.iter().filter_map(|t| t.to_nat_rule(&wan)).collect())
    }

    /// Resolve the WAN interface from the interface_roles table (seeded by
    /// the setup wizard, editable via the Interfaces page).
    async fn wan_interface(&self) -> Option<String> {
        match sqlx::query_scalar::<_, String>(
            "SELECT interface_name FROM interface_roles WHERE role = 'WAN' ORDER BY interface_name LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "failed to look up WAN interface for VPN NAT");
                None
            }
        }
    }

    /// Load the full VPN rule set (NAT + filter) into the `aifw-vpn` anchor.
    /// Idempotent: replaces the anchor's contents, so stopped tunnels
    /// disappear and started tunnels appear.
    pub async fn apply_vpn_rules(&self) -> Result<()> {
        // NAT rules must precede filter rules within a pfctl ruleset load.
        let mut pf_rules = self.collect_vpn_nat_rules().await?;
        pf_rules.extend(self.collect_vpn_rules().await?);

        tracing::info!(count = pf_rules.len(), "applying VPN pf rules");
        self.pf
            .load_rules(&self.anchor, &pf_rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }
}

/// Scanning more candidates than this per family means the subnet is
/// effectively full for auto-assignment purposes (a /64 has 2^64 hosts —
/// exhaustive iteration is not an option).
const MAX_AUTO_IP_SCAN: u32 = 65536;

/// Next free IPv4 host in `server`'s subnet as a `/32` peer address:
/// skips the network address, the broadcast address, the server itself,
/// and every already-assigned peer IP.
fn next_free_v4(
    server: std::net::Ipv4Addr,
    prefix: u8,
    used: &std::collections::HashSet<std::net::IpAddr>,
) -> Result<String> {
    let p = prefix.min(32);
    let server_bits = u32::from(server);
    let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
    let net = server_bits & mask;
    let bcast = net | !mask;

    let mut candidate = net.saturating_add(1);
    let mut tries = 0u32;
    while candidate < bcast && tries < MAX_AUTO_IP_SCAN {
        if candidate != server_bits {
            let ip = std::net::Ipv4Addr::from(candidate);
            if !used.contains(&std::net::IpAddr::V4(ip)) {
                return Ok(format!("{ip}/32"));
            }
        }
        candidate += 1;
        tries += 1;
    }
    Err(AifwError::Validation(
        "No free IPv4 addresses in tunnel subnet".to_string(),
    ))
}

/// Next free IPv6 host in `server`'s subnet as a `/128` peer address:
/// skips the subnet-router anycast address (all-zero host part), the
/// server itself, and every already-assigned peer IP.
fn next_free_v6(
    server: std::net::Ipv6Addr,
    prefix: u8,
    used: &std::collections::HashSet<std::net::IpAddr>,
) -> Result<String> {
    let p = prefix.min(128);
    let server_bits = u128::from(server);
    let mask: u128 = if p == 0 { 0 } else { u128::MAX << (128 - p) };
    let net = server_bits & mask;
    let last = net | !mask;

    let mut candidate = net.saturating_add(1);
    let mut tries = 0u32;
    while candidate <= last && tries < MAX_AUTO_IP_SCAN {
        if candidate != server_bits {
            let ip = std::net::Ipv6Addr::from(candidate);
            if !used.contains(&std::net::IpAddr::V6(ip)) {
                return Ok(format!("{ip}/128"));
            }
        }
        candidate += 1;
        tries += 1;
    }
    Err(AifwError::Validation(
        "No free IPv6 addresses in tunnel subnet".to_string(),
    ))
}

// ============================================================
// Row types
// ============================================================

/// Explicit column list for `WgTunnelRow` selects (#348). `SELECT *` triggers
/// a sqlx-sqlite column-count panic and blocks column pruning; the `wg_tunnels`
/// table gained `listen_interface`/`split_routes` via ALTER TABLE, so an
/// explicit list keeps the column count deterministic. Order matches the
/// CREATE TABLE (base columns then ALTER-added columns).
const WG_TUNNEL_COLUMNS: &str = "id, name, interface, private_key, public_key, \
    listen_port, address, dns, mtu, status, created_at, updated_at, \
    listen_interface, split_routes, address6";

#[derive(sqlx::FromRow)]
struct WgTunnelRow {
    id: String,
    name: String,
    interface: String,
    private_key: String,
    public_key: String,
    listen_port: i64,
    address: String,
    dns: Option<String>,
    mtu: Option<i64>,
    listen_interface: Option<String>,
    #[sqlx(default)]
    split_routes: Option<String>,
    #[sqlx(default)]
    address6: Option<String>,
    status: String,
    created_at: String,
    updated_at: String,
}

impl WgTunnelRow {
    fn into_tunnel(self) -> Result<WgTunnel> {
        Ok(WgTunnel {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            name: self.name,
            interface: Interface(self.interface),
            private_key: self.private_key,
            public_key: self.public_key,
            listen_port: self.listen_port as u16,
            address: Address::parse(&self.address)?,
            address6: self.address6.as_deref().map(Address::parse).transpose()?,
            dns: self.dns,
            mtu: self.mtu.map(|m| m as u16),
            listen_interface: self.listen_interface,
            split_routes: self.split_routes,
            status: parse_vpn_status(&self.status),
            created_at: parse_dt(&self.created_at)?,
            updated_at: parse_dt(&self.updated_at)?,
        })
    }
}

/// Explicit column list for `WgPeerRow` selects (#348). `client_private_key`
/// was added via ALTER TABLE, so an explicit list (rather than `SELECT *`)
/// keeps the column count deterministic and avoids the sqlx-sqlite panic.
const WG_PEER_COLUMNS: &str = "id, tunnel_id, name, public_key, preshared_key, \
    endpoint, allowed_ips, persistent_keepalive, created_at, updated_at, \
    client_private_key";

#[derive(sqlx::FromRow)]
struct WgPeerRow {
    id: String,
    tunnel_id: String,
    name: String,
    public_key: String,
    preshared_key: Option<String>,
    client_private_key: Option<String>,
    endpoint: Option<String>,
    allowed_ips: String,
    persistent_keepalive: Option<i64>,
    created_at: String,
    updated_at: String,
}

impl WgPeerRow {
    fn into_peer(self) -> Result<WgPeer> {
        let allowed_ips: Vec<Address> = self
            .allowed_ips
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| Address::parse(s.trim()))
            .collect::<Result<Vec<_>>>()?;

        Ok(WgPeer {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            tunnel_id: Uuid::parse_str(&self.tunnel_id)
                .map_err(|e| AifwError::Database(format!("{e}")))?,
            name: self.name,
            public_key: self.public_key,
            preshared_key: self.preshared_key,
            client_private_key: self.client_private_key,
            endpoint: self.endpoint,
            allowed_ips,
            persistent_keepalive: self.persistent_keepalive.map(|k| k as u16),
            created_at: parse_dt(&self.created_at)?,
            updated_at: parse_dt(&self.updated_at)?,
        })
    }
}

/// Explicit column list for `IpsecSaRow` selects (#348). Avoids `SELECT *`,
/// which triggers a sqlx-sqlite column-count panic and blocks column pruning.
const IPSEC_SA_COLUMNS: &str = "id, name, src_addr, dst_addr, protocol, mode, \
    spi, enc_algo, auth_algo, status, created_at, updated_at";

#[derive(sqlx::FromRow)]
struct IpsecSaRow {
    id: String,
    name: String,
    src_addr: String,
    dst_addr: String,
    protocol: String,
    mode: String,
    spi: i64,
    enc_algo: String,
    auth_algo: String,
    status: String,
    created_at: String,
    updated_at: String,
}

impl IpsecSaRow {
    fn into_sa(self) -> Result<IpsecSa> {
        Ok(IpsecSa {
            id: Uuid::parse_str(&self.id).map_err(|e| AifwError::Database(format!("{e}")))?,
            name: self.name,
            src_addr: Address::parse(&self.src_addr)?,
            dst_addr: Address::parse(&self.dst_addr)?,
            protocol: IpsecProtocol::parse(&self.protocol)?,
            mode: match self.mode.as_str() {
                "transport" => IpsecMode::Transport,
                _ => IpsecMode::Tunnel,
            },
            spi: self.spi as u32,
            enc_algo: self.enc_algo,
            auth_algo: self.auth_algo,
            status: parse_vpn_status(&self.status),
            created_at: parse_dt(&self.created_at)?,
            updated_at: parse_dt(&self.updated_at)?,
        })
    }
}

fn parse_vpn_status(s: &str) -> VpnStatus {
    match s {
        "up" => VpnStatus::Up,
        "error" => VpnStatus::Error,
        _ => VpnStatus::Down,
    }
}

fn parse_dt(s: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|d| d.with_timezone(&Utc))
        .map_err(|e| AifwError::Database(format!("invalid date: {e}")))
}
