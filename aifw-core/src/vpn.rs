use aifw_common::{
    Address, AifwError, Interface, IpsecMode, IpsecProtocol, IpsecSa, Result, VpnStatus, WgPeer,
    WgTunnel,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
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

        sqlx::query(
            r#"
            INSERT INTO wg_tunnels (id, name, interface, private_key, public_key, listen_port,
                address, dns, mtu, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
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
        .bind(tunnel.status.to_string())
        .bind(tunnel.created_at.to_rfc3339())
        .bind(tunnel.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %tunnel.id, name = %tunnel.name, "WireGuard tunnel added");
        Ok(tunnel)
    }

    pub async fn list_wg_tunnels(&self) -> Result<Vec<WgTunnel>> {
        let rows = sqlx::query_as::<_, WgTunnelRow>(
            "SELECT * FROM wg_tunnels ORDER BY created_at ASC",
        )
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
            return Err(AifwError::Validation("peer public key required".to_string()));
        }
        // Verify tunnel exists
        let _ = self.get_wg_tunnel(peer.tunnel_id).await?;

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
        let rows = sqlx::query_as::<_, IpsecSaRow>(
            "SELECT * FROM ipsec_sas ORDER BY created_at ASC",
        )
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
    // Apply VPN pf rules
    // ============================================================

    pub async fn apply_vpn_rules(&self) -> Result<()> {
        let mut pf_rules = Vec::new();

        // WireGuard rules
        let tunnels = self.list_wg_tunnels().await?;
        for t in &tunnels {
            pf_rules.extend(t.to_pf_rules());
        }

        // IPsec rules
        let sas = self.list_ipsec_sas().await?;
        for sa in &sas {
            pf_rules.extend(sa.to_pf_rules());
        }

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
