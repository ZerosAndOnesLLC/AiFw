//! `aifw vpn …` (WireGuard + IPsec).

use aifw_common::{Address, Interface, WgPeer, WgTunnel};
use aifw_core::{Database, VpnEngine};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

// --- VPN commands ---

async fn create_vpn_engine(db_path: &Path) -> anyhow::Result<VpnEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    let engine = VpnEngine::new(db.pool().clone(), pf);
    engine.migrate().await?;
    Ok(engine)
}

pub async fn vpn_wg_add(
    db_path: &Path,
    name: &str,
    interface: &str,
    port: u16,
    address: &str,
) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let tunnel = WgTunnel::new(
        name.to_string(),
        Interface(interface.to_string()),
        port,
        Address::parse(address)?,
    )?;
    let tunnel = engine.add_wg_tunnel(tunnel).await?;
    println!("Added WireGuard tunnel {}", tunnel.id);
    println!("  Interface:  {}", tunnel.interface);
    println!("  Port:       {}", tunnel.listen_port);
    println!("  Address:    {}", tunnel.address);
    println!("  Public Key: {}", tunnel.public_key);
    Ok(())
}

pub async fn vpn_wg_peer_add(
    db_path: &Path,
    tunnel_id: &str,
    name: &str,
    pubkey: &str,
    endpoint: Option<&str>,
    allowed_ips: &str,
    keepalive: Option<u16>,
) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let tid = Uuid::parse_str(tunnel_id)?;

    let mut peer = WgPeer::new(tid, name.to_string(), pubkey.to_string());
    peer.endpoint = endpoint.map(String::from);
    peer.allowed_ips = allowed_ips
        .split(',')
        .map(|s| Address::parse(s.trim()))
        .collect::<aifw_common::Result<Vec<_>>>()?;
    peer.persistent_keepalive = keepalive;

    let peer = engine.add_wg_peer(peer).await?;
    println!("Added WireGuard peer {}", peer.id);
    println!("  Name:     {}", peer.name);
    println!(
        "  Endpoint: {}",
        peer.endpoint.as_deref().unwrap_or("(none)")
    );
    Ok(())
}

async fn create_ipsec_engine(db_path: &Path) -> anyhow::Result<aifw_core::IpsecEngine> {
    let db = Database::new(db_path).await?;
    let engine = aifw_core::IpsecEngine::new(
        db.pool().clone(),
        aifw_core::create_ike_control(),
        aifw_core::create_conf_store(),
    );
    engine.migrate().await?;
    Ok(engine)
}

fn split_ts(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub async fn vpn_ipsec_add(
    db_path: &Path,
    name: &str,
    remote: &str,
    psk: &str,
    local_ts: &str,
    remote_ts: &str,
    local: Option<&str>,
) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;

    let mut tunnel = aifw_common::IpsecTunnel::new(
        name.to_string(),
        remote.to_string(),
        psk.to_string(),
        split_ts(local_ts),
        split_ts(remote_ts),
    );
    if let Some(local) = local {
        tunnel.local_addr = local.to_string();
    }
    let tunnel = engine.create_tunnel_applied(tunnel).await?;
    println!("Added IPsec tunnel {}", tunnel.id);
    println!("  Name:      {}", tunnel.name);
    println!("  Remote:    {}", tunnel.remote_addr);
    println!("  Local TS:  {}", tunnel.local_ts.join(","));
    println!("  Remote TS: {}", tunnel.remote_ts.join(","));
    println!("  IKE:       v2, {}", tunnel.ike_proposal);
    println!("  ESP:       {}", tunnel.esp_proposal);
    Ok(())
}

pub async fn vpn_ipsec_start(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.start_tunnel(uuid).await?;
    println!("IPsec tunnel {id} initiated");
    Ok(())
}

pub async fn vpn_ipsec_stop(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;
    engine.stop_tunnel(uuid).await?;
    println!("IPsec tunnel {id} terminated");
    Ok(())
}

pub async fn vpn_ipsec_status(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_ipsec_engine(db_path).await?;
    let statuses = engine.live_status().await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&statuses)?);
        return Ok(());
    }
    if statuses.is_empty() {
        println!("No IPsec tunnels configured");
        return Ok(());
    }
    println!(
        "{:<38} {:<14} {:<20} {:<10}",
        "TUNNEL", "IKE STATE", "REMOTE", "UPTIME"
    );
    println!("{}", "-".repeat(85));
    for s in &statuses {
        let uptime = s
            .established_secs
            .map(|secs| format!("{}m{}s", secs / 60, secs % 60))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<38} {:<14} {:<20} {:<10}",
            s.tunnel_id,
            s.ike_state,
            s.remote_host.as_deref().unwrap_or("-"),
            uptime,
        );
        for c in &s.child_sas {
            println!(
                "  child {}: {} in={}B out={}B rekey_in={}s ts={} <-> {}",
                c.name,
                c.state,
                c.bytes_in,
                c.bytes_out,
                c.rekey_in_secs.unwrap_or(0),
                c.local_ts.join(","),
                c.remote_ts.join(","),
            );
        }
    }
    Ok(())
}

pub async fn vpn_remove(db_path: &Path, id: &str) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;
    let uuid = Uuid::parse_str(id)?;

    // Try WG tunnel first, then IPsec tunnel, legacy SA, WG peer
    if engine.delete_wg_tunnel(uuid).await.is_ok() {
        println!("Removed WireGuard tunnel {id}");
    } else if let Ok(ipsec) = create_ipsec_engine(db_path).await
        && ipsec.delete_tunnel_applied(uuid).await.is_ok()
    {
        println!("Removed IPsec tunnel {id}");
    } else if engine.delete_ipsec_sa(uuid).await.is_ok() {
        println!("Removed legacy IPsec SA record {id}");
    } else if engine.delete_wg_peer(uuid).await.is_ok() {
        println!("Removed WireGuard peer {id}");
    } else {
        anyhow::bail!("VPN resource {id} not found");
    }
    Ok(())
}

pub async fn vpn_list(db_path: &Path, json: bool) -> anyhow::Result<()> {
    let engine = create_vpn_engine(db_path).await?;

    let tunnels = engine.list_wg_tunnels().await?;
    let sas = engine.list_ipsec_sas().await?;
    let ipsec_engine = create_ipsec_engine(db_path).await?;
    let ipsec_tunnels = ipsec_engine.list_tunnels().await?;

    if json {
        let data = serde_json::json!({
            "wireguard": tunnels,
            "ipsec_tunnels": ipsec_tunnels
                .iter()
                .map(|t| t.redacted())
                .collect::<Vec<_>>(),
            "ipsec_legacy_sas": sas,
        });
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }

    // WireGuard
    if tunnels.is_empty() {
        println!("No WireGuard tunnels configured");
    } else {
        println!("WireGuard Tunnels:");
        println!(
            "{:<38} {:<12} {:<8} {:<6} {:<20} {:<8}",
            "ID", "NAME", "IFACE", "PORT", "ADDRESS", "STATUS"
        );
        println!("{}", "-".repeat(95));
        for t in &tunnels {
            println!(
                "{:<38} {:<12} {:<8} {:<6} {:<20} {:<8}",
                t.id, t.name, t.interface, t.listen_port, t.address, t.status,
            );

            // List peers
            if let Ok(peers) = engine.list_wg_peers(t.id).await {
                for p in &peers {
                    println!(
                        "  Peer: {} | {} | endpoint: {} | allowed: {}",
                        p.name,
                        &p.public_key[..12],
                        p.endpoint.as_deref().unwrap_or("(none)"),
                        p.allowed_ips
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    );
                }
            }
        }
        println!("\n{} tunnel(s)", tunnels.len());
    }

    println!();

    // IPsec tunnels (#530 real data plane)
    if ipsec_tunnels.is_empty() {
        println!("No IPsec tunnels configured");
    } else {
        println!("IPsec Tunnels:");
        println!(
            "{:<38} {:<14} {:<20} {:<8} {:<6} {:<24}",
            "ID", "NAME", "REMOTE", "AUTH", "ON", "TRAFFIC"
        );
        println!("{}", "-".repeat(115));
        for t in &ipsec_tunnels {
            println!(
                "{:<38} {:<14} {:<20} {:<8} {:<6} {:<24}",
                t.id,
                t.name,
                t.remote_addr,
                t.auth_method,
                if t.enabled { "yes" } else { "no" },
                format!("{} <-> {}", t.local_ts.join(","), t.remote_ts.join(",")),
            );
        }
        println!("\n{} tunnel(s)", ipsec_tunnels.len());
    }

    println!();

    // Legacy IPsec SA records (configuration-only, no data plane)
    if sas.is_empty() {
        println!("No legacy IPsec SA records");
    } else {
        println!("Legacy IPsec SA records (inactive — no data plane):");
        println!(
            "{:<38} {:<12} {:<20} {:<20} {:<8} {:<10} {:<8}",
            "ID", "NAME", "SOURCE", "DESTINATION", "PROTO", "MODE", "STATUS"
        );
        println!("{}", "-".repeat(115));
        for sa in &sas {
            println!(
                "{:<38} {:<12} {:<20} {:<20} {:<8} {:<10} {:<8}",
                sa.id, sa.name, sa.src_addr, sa.dst_addr, sa.protocol, sa.mode, sa.status,
            );
        }
        println!("\n{} SA(s)", sas.len());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::split_ts;

    #[test]
    fn split_ts_trims_and_drops_empties() {
        assert_eq!(
            split_ts("10.0.0.0/24, 10.1.0.0/24 ,,"),
            vec!["10.0.0.0/24", "10.1.0.0/24"]
        );
        assert!(split_ts("").is_empty());
        assert!(split_ts(" , ").is_empty());
    }
}
