//! `aifw multiwan …`.

use aifw_core::{Database, GatewayEngine, GroupEngine, InstanceEngine, LeakEngine, PolicyEngine};
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

// ============================================================
// Multi-WAN CLI commands (#132)
// ============================================================

async fn open_pf() -> Arc<dyn aifw_pf::PfBackend> {
    Arc::from(aifw_pf::create_backend())
}

pub async fn multiwan_instances(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let engine = InstanceEngine::new(pool, pf);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<16} {:<6} {:<8} STATUS",
        "ID", "NAME", "FIB", "MGMT"
    );
    for i in list {
        println!(
            "{:<36} {:<16} {:<6} {:<8} {}",
            i.id,
            i.name,
            i.fib_number,
            if i.mgmt_reachable { "yes" } else { "no" },
            i.status.as_str(),
        );
    }
    Ok(())
}

pub async fn multiwan_gateways(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let engine = GatewayEngine::new(pool);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<16} {:<8} {:<16} {:<12} {:<8} MOS",
        "ID", "NAME", "STATE", "NEXT-HOP", "IFACE", "RTT"
    );
    for g in list {
        println!(
            "{:<36} {:<16} {:<8} {:<16} {:<12} {:<8} {}",
            g.id,
            g.name,
            g.state.as_str(),
            g.next_hop,
            g.interface,
            g.last_rtt_ms
                .map(|v| format!("{v:.1}ms"))
                .unwrap_or_else(|| "-".into()),
            g.last_mos
                .map(|v| format!("{v:.2}"))
                .unwrap_or_else(|| "-".into()),
        );
    }
    Ok(())
}

pub async fn multiwan_groups(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let engine = GroupEngine::new(pool);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<16} {:<14} {:<8} STICKY",
        "ID", "NAME", "POLICY", "PREEMPT"
    );
    for g in list {
        let members = engine.list_members(g.id).await.unwrap_or_default();
        println!(
            "{:<36} {:<16} {:<14} {:<8} {:<10} ({} members)",
            g.id,
            g.name,
            g.policy.as_str(),
            if g.preempt { "yes" } else { "no" },
            g.sticky.as_str(),
            members.len(),
        );
    }
    Ok(())
}

pub async fn multiwan_policies(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let engine = PolicyEngine::new(pool, pf);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<5} {:<20} {:<10} {:<12} MATCH",
        "ID", "PRI", "NAME", "STATUS", "ACTION"
    );
    for p in list {
        println!(
            "{:<36} {:<5} {:<20} {:<10} {:<12} {} → {}:{}",
            p.id,
            p.priority,
            p.name,
            p.status,
            p.action_kind,
            p.src_addr,
            p.dst_addr,
            p.dst_port.as_deref().unwrap_or("*"),
        );
    }
    Ok(())
}

pub async fn multiwan_leaks(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let engine = LeakEngine::new(pool, pf);
    engine.migrate().await?;
    let list = engine.list().await?;
    println!(
        "{:<36} {:<20} {:<20} {:<8} DIRECTION",
        "ID", "NAME", "PREFIX", "ENABLED"
    );
    for l in list {
        println!(
            "{:<36} {:<20} {:<20} {:<8} {}",
            l.id,
            l.name,
            l.prefix,
            if l.enabled { "yes" } else { "no" },
            l.direction
        );
    }
    Ok(())
}

pub async fn multiwan_flows() -> anyhow::Result<()> {
    let pf = open_pf().await;
    let states = pf.get_states().await?;
    println!(
        "{:<8} {:<8} {:<28} {:<28} {:<6} BYTES",
        "PROTO", "IFACE", "SRC", "DST", "FIB"
    );
    for s in states.into_iter().take(100) {
        println!(
            "{:<8} {:<8} {:<28} {:<28} {:<6} {}",
            s.protocol,
            s.iface.as_deref().unwrap_or("-"),
            format!("{}:{}", s.src_addr, s.src_port),
            format!("{}:{}", s.dst_addr, s.dst_port),
            s.rtable
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into()),
            s.bytes_in + s.bytes_out,
        );
    }
    Ok(())
}

pub async fn multiwan_fib_info() -> anyhow::Result<()> {
    let pf = open_pf().await;
    let n = pf.list_fibs().await?;
    println!("available FIBs: {n}");
    Ok(())
}

pub async fn multiwan_apply(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;

    let inst_engine = InstanceEngine::new(pool.clone(), pf.clone());
    let gw_engine = GatewayEngine::new(pool.clone());
    let grp_engine = GroupEngine::new(pool.clone());
    let policy_engine = PolicyEngine::new(pool.clone(), pf.clone());
    let leak_engine = LeakEngine::new(pool.clone(), pf.clone());
    inst_engine.migrate().await?;
    gw_engine.migrate().await?;
    grp_engine.migrate().await?;
    policy_engine.migrate().await?;
    leak_engine.migrate().await?;

    let instances = inst_engine.list().await?;
    let gateways = gw_engine.list().await?;
    let groups = grp_engine.list().await?;
    let mut members = std::collections::HashMap::new();
    for g in &groups {
        members.insert(g.id, grp_engine.list_members(g.id).await?);
    }
    policy_engine
        .apply(&instances, &gateways, &groups, &members)
        .await?;
    leak_engine.apply(&instances).await?;
    println!("multi-WAN anchors reloaded");
    Ok(())
}

pub async fn multiwan_seed_mgmt(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let inst_engine = InstanceEngine::new(pool.clone(), pf.clone());
    let leak_engine = LeakEngine::new(pool.clone(), pf);
    inst_engine.migrate().await?;
    leak_engine.migrate().await?;
    let instances = inst_engine.list().await?;
    leak_engine.seed_mgmt_escapes(&instances).await?;
    leak_engine.apply(&instances).await?;
    println!("mgmt-escape leaks seeded");
    Ok(())
}

pub async fn multiwan_probe(db_path: &Path, id: &str, outcome: &str) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let engine = GatewayEngine::new(pool);
    engine.migrate().await?;
    let uuid: Uuid = id.parse()?;
    let success = matches!(outcome, "ok" | "success" | "up");
    let sample = aifw_core::multiwan::ProbeOutcome {
        success,
        rtt_ms: if success { Some(10.0) } else { None },
        error: if success {
            None
        } else {
            Some("cli-fail".into())
        },
    };
    engine.inject_sample(uuid, sample).await?;
    let gw = engine.get(uuid).await?;
    println!("gateway {} → {}", gw.name, gw.state.as_str());
    Ok(())
}

pub async fn multiwan_export(db_path: &Path) -> anyhow::Result<()> {
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;
    let inst = InstanceEngine::new(pool.clone(), pf.clone());
    let gw = GatewayEngine::new(pool.clone());
    let grp = GroupEngine::new(pool.clone());
    let pol = PolicyEngine::new(pool.clone(), pf.clone());
    let lk = LeakEngine::new(pool, pf);
    inst.migrate().await?;
    gw.migrate().await?;
    grp.migrate().await?;
    pol.migrate().await?;
    lk.migrate().await?;
    let bundle = serde_json::json!({
        "instances": inst.list().await?,
        "gateways": gw.list().await?,
        "groups": grp.list().await?,
        "policies": pol.list().await?,
        "leaks": lk.list().await?,
    });
    println!("{}", serde_json::to_string_pretty(&bundle)?);
    Ok(())
}

pub async fn multiwan_import(db_path: &Path, file: &str) -> anyhow::Result<()> {
    let content = tokio::fs::read_to_string(file).await?;
    let bundle: serde_json::Value = serde_json::from_str(&content)?;
    let db = Database::new(db_path).await?;
    let pool = db.pool().clone();
    let pf = open_pf().await;

    let inst = InstanceEngine::new(pool.clone(), pf.clone());
    let gw = GatewayEngine::new(pool.clone());
    let grp = GroupEngine::new(pool.clone());
    let pol = PolicyEngine::new(pool.clone(), pf.clone());
    let lk = LeakEngine::new(pool.clone(), pf.clone());
    inst.migrate().await?;
    gw.migrate().await?;
    grp.migrate().await?;
    pol.migrate().await?;
    lk.migrate().await?;

    let mut n = (0usize, 0usize, 0usize, 0usize, 0usize);
    if let Some(arr) = bundle.get("instances").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(i) = serde_json::from_value::<aifw_common::RoutingInstance>(v.clone()) {
                if i.mgmt_reachable {
                    continue;
                }
                if inst.get(i.id).await.is_ok() {
                    let _ = inst.update(i).await;
                } else {
                    let _ = inst.add(i).await;
                }
                n.0 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("gateways").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(g) = serde_json::from_value::<aifw_common::Gateway>(v.clone()) {
                if gw.get(g.id).await.is_ok() {
                    let _ = gw.update(g).await;
                } else {
                    let _ = gw.add(g).await;
                }
                n.1 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("groups").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(g) = serde_json::from_value::<aifw_common::GatewayGroup>(v.clone()) {
                if grp.get(g.id).await.is_ok() {
                    let _ = grp.update(g).await;
                } else {
                    let _ = grp.add(g).await;
                }
                n.2 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("policies").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(p) = serde_json::from_value::<aifw_common::PolicyRule>(v.clone()) {
                if pol.get(p.id).await.is_ok() {
                    let _ = pol.update(p).await;
                } else {
                    let _ = pol.add(p).await;
                }
                n.3 += 1;
            }
        }
    }
    if let Some(arr) = bundle.get("leaks").and_then(|v| v.as_array()) {
        for v in arr {
            if let Ok(l) = serde_json::from_value::<aifw_common::RouteLeak>(v.clone()) {
                if lk.get(l.id).await.is_ok() {
                    let _ = lk.update(l).await;
                } else {
                    let _ = lk.add(l).await;
                }
                n.4 += 1;
            }
        }
    }
    println!(
        "imported: instances={} gateways={} groups={} policies={} leaks={}",
        n.0, n.1, n.2, n.3, n.4
    );
    Ok(())
}
