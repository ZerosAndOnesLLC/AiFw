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

pub struct VpnEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
}

impl VpnEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: "aifw-vpn".to_string(),
        }
    }

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

        Ok(())
    }

    // ============================================================
    // WireGuard tunnels
    // ============================================================

    pub async fn add_wg_tunnel(&self, tunnel: WgTunnel) -> Result<WgTunnel> {
        if tunnel.name.is_empty() {
            return Err(AifwError::Validation("tunnel name required".to_string()));
        }
        if tunnel.listen_port == 0 {
            return Err(AifwError::Validation("listen port required".to_string()));
        }

        // Check for duplicate port across all tunnels
        let existing = self.list_wg_tunnels().await?;
        for t in &existing {
            if t.id != tunnel.id && t.listen_port == tunnel.listen_port {
                return Err(AifwError::Validation(format!(
                    "Port {} is already used by tunnel '{}'",
                    tunnel.listen_port, t.name
                )));
            }
        }

        sqlx::query(
            r#"
            INSERT INTO wg_tunnels (id, name, interface, private_key, public_key, listen_port,
                address, dns, mtu, listen_interface, split_routes, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
            "#,
        )
        .bind(tunnel.id.to_string())
        .bind(&tunnel.name)
        .bind(&tunnel.interface.0)
        .bind(&tunnel.private_key)
        .bind(&tunnel.public_key)
        .bind(tunnel.listen_port as i64)
        .bind(tunnel.address.to_string())
        .bind(tunnel.dns.as_deref())
        .bind(tunnel.mtu.map(|m| m as i64))
        .bind(tunnel.listen_interface.as_deref())
        .bind(tunnel.split_routes.as_deref())
        .bind(tunnel.status.to_string())
        .bind(tunnel.created_at.to_rfc3339())
        .bind(tunnel.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %tunnel.id, name = %tunnel.name, "WireGuard tunnel added");
        Ok(tunnel)
    }

    pub async fn list_wg_tunnels(&self) -> Result<Vec<WgTunnel>> {
        let rows =
            sqlx::query_as::<_, WgTunnelRow>("SELECT * FROM wg_tunnels ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter().map(|r| r.into_tunnel()).collect()
    }

    pub async fn get_wg_tunnel(&self, id: Uuid) -> Result<WgTunnel> {
        let row = sqlx::query_as::<_, WgTunnelRow>("SELECT * FROM wg_tunnels WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AifwError::NotFound(format!("WG tunnel {id} not found")))?;
        row.into_tunnel()
    }

    pub async fn update_wg_tunnel(&self, tunnel: WgTunnel) -> Result<WgTunnel> {
        if tunnel.name.is_empty() {
            return Err(AifwError::Validation("tunnel name required".to_string()));
        }
        if tunnel.listen_port == 0 {
            return Err(AifwError::Validation("listen port required".to_string()));
        }

        let existing = self.list_wg_tunnels().await?;
        for t in &existing {
            if t.id != tunnel.id && t.listen_port == tunnel.listen_port {
                return Err(AifwError::Validation(format!(
                    "Port {} is already used by tunnel '{}'",
                    tunnel.listen_port, t.name
                )));
            }
        }

        let result = sqlx::query(
            r#"
            UPDATE wg_tunnels
               SET name = ?1, listen_port = ?2, address = ?3, dns = ?4, mtu = ?5,
                   listen_interface = ?6, split_routes = ?7,
                   private_key = ?8, public_key = ?9, updated_at = ?10
             WHERE id = ?11
            "#,
        )
        .bind(&tunnel.name)
        .bind(tunnel.listen_port as i64)
        .bind(tunnel.address.to_string())
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
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %peer.id, name = %peer.name, "WireGuard peer added");
        Ok(peer)
    }

    pub async fn list_wg_peers(&self, tunnel_id: Uuid) -> Result<Vec<WgPeer>> {
        let rows = sqlx::query_as::<_, WgPeerRow>(
            "SELECT * FROM wg_peers WHERE tunnel_id = ?1 ORDER BY created_at ASC",
        )
        .bind(tunnel_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_peer()).collect()
    }

    pub async fn get_wg_peer(&self, id: Uuid) -> Result<WgPeer> {
        let row = sqlx::query_as::<_, WgPeerRow>("SELECT * FROM wg_peers WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AifwError::NotFound(format!("WG peer {id} not found")))?;
        row.into_peer()
    }

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

    pub async fn add_ipsec_sa(&self, sa: IpsecSa) -> Result<IpsecSa> {
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
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %sa.id, name = %sa.name, "IPsec SA added");
        Ok(sa)
    }

    pub async fn list_ipsec_sas(&self) -> Result<Vec<IpsecSa>> {
        let rows =
            sqlx::query_as::<_, IpsecSaRow>("SELECT * FROM ipsec_sas ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?;
        rows.into_iter().map(|r| r.into_sa()).collect()
    }

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
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["ifconfig", iface, "destroy"])
            .output()
            .await; // clean up if exists
        let output = Command::new("/usr/local/bin/sudo")
            .args(["ifconfig", iface, "create"])
            .output()
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

        // Set address and bring up
        let addr = tunnel.address.to_string();
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["ifconfig", iface, "inet", &addr, "up"])
            .output()
            .await;

        // Set MTU if specified
        if let Some(mtu) = tunnel.mtu {
            let _ = Command::new("/usr/local/bin/sudo")
                .args(["ifconfig", iface, "mtu", &mtu.to_string()])
                .output()
                .await;
        }

        // Configure WireGuard private key and listen port
        let output = Command::new("/usr/local/bin/sudo")
            .args([
                "/usr/bin/wg",
                "set",
                iface,
                "private-key",
                &key_path,
                "listen-port",
                &tunnel.listen_port.to_string(),
            ])
            .output()
            .await
            .map_err(|e| AifwError::Pf(format!("wg set failed: {e}")))?;
        let _ = tokio::fs::remove_file(&key_path).await;
        if !output.status.success() {
            let _ = Command::new("/usr/local/bin/sudo")
                .args(["ifconfig", iface, "destroy"])
                .output()
                .await;
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

        // Open WAN UDP for this tunnel's listen-port in the aifw-vpn anchor.
        // Without this, handshake packets are dropped by the default block rule.
        let _ = self.rebuild_vpn_pf_anchor().await;

        tracing::info!(%id, iface, "WireGuard tunnel started");
        Ok(())
    }

    /// Stop a WireGuard tunnel: destroy the interface.
    pub async fn stop_tunnel(&self, id: Uuid) -> Result<()> {
        let tunnel = self.get_wg_tunnel(id).await?;
        let iface = &tunnel.interface.0;

        let _ = Command::new("/usr/local/bin/sudo")
            .args(["ifconfig", iface, "destroy"])
            .output()
            .await;

        let _ = sqlx::query("UPDATE wg_tunnels SET status = 'down', updated_at = ?1 WHERE id = ?2")
            .bind(Utc::now().to_rfc3339())
            .bind(id.to_string())
            .execute(&self.pool)
            .await;

        // Close the WAN pass rule for this tunnel by recomputing from remaining
        // up tunnels only.
        let _ = self.rebuild_vpn_pf_anchor().await;

        tracing::info!(%id, iface, "WireGuard tunnel stopped");
        Ok(())
    }

    /// Rebuild the `aifw-vpn` filter anchor from the set of currently-up
    /// WireGuard tunnels. Emits one UDP pass rule per listen_port, optionally
    /// scoped to the tunnel's listen_interface when set.
    ///
    /// Idempotent: replaces the anchor's contents, so stopped tunnels disappear
    /// and started tunnels appear.
    pub async fn rebuild_vpn_pf_anchor(&self) -> Result<()> {
        let tunnels = self.list_wg_tunnels().await?;
        let mut rules: Vec<String> = Vec::new();
        for t in tunnels.iter().filter(|t| t.status == VpnStatus::Up) {
            let iface_clause = match t.listen_interface.as_deref() {
                Some(iface) if !iface.is_empty() && iface != "any" => format!(" on {iface}"),
                _ => String::new(),
            };
            rules.push(format!(
                "pass in quick{iface_clause} proto udp to any port {} keep state label \"wg-{}\"",
                t.listen_port, t.name
            ));
        }
        self.pf
            .load_rules("aifw-vpn", &rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        tracing::info!(count = rules.len(), "aifw-vpn anchor rebuilt");
        Ok(())
    }

    /// Apply a single peer to a running WireGuard interface via `wg set`.
    async fn apply_peer_to_interface(&self, iface: &str, peer: &WgPeer) -> Result<()> {
        let allowed: Vec<String> = peer.allowed_ips.iter().map(|a| a.to_string()).collect();
        let mut args = vec![
            "/usr/bin/wg".to_string(),
            "set".to_string(),
            iface.to_string(),
            "peer".to_string(),
            peer.public_key.clone(),
            "allowed-ips".to_string(),
            allowed.join(","),
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
        if let Some(ref psk) = peer.preshared_key {
            let psk_path = format!("/tmp/wg-psk-{}.key", peer.id);
            tokio::fs::write(&psk_path, psk)
                .await
                .map_err(|e| AifwError::Pf(format!("Failed to write PSK: {e}")))?;
            let _ = Command::new("chmod")
                .args(["600", &psk_path])
                .output()
                .await;
            args.push("preshared-key".to_string());
            args.push(psk_path.clone());
            let output = Command::new("/usr/local/bin/sudo")
                .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                .output()
                .await
                .map_err(|e| AifwError::Pf(format!("wg set peer failed: {e}")))?;
            let _ = tokio::fs::remove_file(&psk_path).await;
            if !output.status.success() {
                return Err(AifwError::Pf(format!(
                    "wg set peer failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        } else {
            let output = Command::new("/usr/local/bin/sudo")
                .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
                .output()
                .await
                .map_err(|e| AifwError::Pf(format!("wg set peer failed: {e}")))?;
            if !output.status.success() {
                return Err(AifwError::Pf(format!(
                    "wg set peer failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }
        Ok(())
    }

    /// Get live tunnel status from `wg show`.
    pub async fn tunnel_status(&self, id: Uuid) -> Result<serde_json::Value> {
        let tunnel = self.get_wg_tunnel(id).await?;
        let iface = &tunnel.interface.0;

        let output = Command::new("/usr/local/bin/sudo")
            .args(["/usr/bin/wg", "show", iface, "dump"])
            .output()
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

    /// Compute the next available IP in a tunnel's subnet for auto-assigning to a new peer.
    pub async fn next_peer_ip(&self, tunnel_id: Uuid) -> Result<String> {
        let tunnel = self.get_wg_tunnel(tunnel_id).await?;
        let addr_str = tunnel.address.to_string();
        // Parse "10.10.0.1/24" → base "10.10.0", server_last = 1
        let parts: Vec<&str> = addr_str.split('/').collect();
        let ip_str = parts[0];
        let octets: Vec<u8> = ip_str.split('.').filter_map(|o| o.parse().ok()).collect();
        if octets.len() != 4 {
            return Err(AifwError::Validation("Invalid tunnel address".to_string()));
        }

        // Collect existing peer IPs
        let peers = self.list_wg_peers(tunnel_id).await?;
        let used: std::collections::HashSet<String> = peers
            .iter()
            .flat_map(|p| {
                p.allowed_ips
                    .iter()
                    .map(|a| a.to_string().split('/').next().unwrap_or("").to_string())
            })
            .collect();

        // Find next free IP in the /24 (or smaller) range
        let base = [octets[0], octets[1], octets[2]];
        for last in 2u8..=254 {
            let candidate = format!("{}.{}.{}.{}", base[0], base[1], base[2], last);
            if candidate != ip_str && !used.contains(&candidate) {
                return Ok(format!("{candidate}/32"));
            }
        }
        Err(AifwError::Validation(
            "No free IPs in tunnel subnet".to_string(),
        ))
    }

    // ============================================================
    // Apply VPN pf rules
    // ============================================================

    /// Collect all VPN pf rules without loading them.
    pub async fn collect_vpn_rules(&self) -> Result<Vec<String>> {
        let mut pf_rules = Vec::new();
        let tunnels = self.list_wg_tunnels().await?;
        for t in &tunnels {
            pf_rules.extend(t.to_pf_rules());
        }
        let sas = self.list_ipsec_sas().await?;
        for sa in &sas {
            pf_rules.extend(sa.to_pf_rules());
        }
        Ok(pf_rules)
    }

    pub async fn apply_vpn_rules(&self) -> Result<()> {
        let pf_rules = self.collect_vpn_rules().await?;

        tracing::info!(count = pf_rules.len(), "applying VPN pf rules");
        self.pf
            .load_rules(&self.anchor, &pf_rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }
}

// ============================================================
// Row types
// ============================================================

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
