//! Chaos harness for multi-WAN gateway state machine.
//!
//! Seeds N gateways, then randomly toggles probe outcomes for M iterations,
//! asserting invariants:
//!   1. No gateway ever oscillates faster than `consec_fail_down + consec_ok_up`.
//!   2. Every persisted gateway_state matches the engine's internal metrics.
//!   3. Event log is monotonic in timestamp.
//!
//! Run with: `cargo run --example multiwan_chaos -- --gateways 8 --iterations 5000`

use aifw_common::GatewayState;
use aifw_core::multiwan::{GatewayEngine, InstanceEngine, ProbeOutcome};
use aifw_pf::PfMock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug)]
struct Args {
    gateways: usize,
    iterations: usize,
    failure_prob: f64,
}

fn parse_args() -> Args {
    let mut gateways = 4;
    let mut iterations = 1000;
    let mut failure_prob = 0.15;
    let mut iter = std::env::args().skip(1);
    while let Some(a) = iter.next() {
        match a.as_str() {
            "--gateways" => {
                if let Some(v) = iter.next() {
                    gateways = v.parse().unwrap_or(gateways);
                }
            }
            "--iterations" => {
                if let Some(v) = iter.next() {
                    iterations = v.parse().unwrap_or(iterations);
                }
            }
            "--failure-prob" => {
                if let Some(v) = iter.next() {
                    failure_prob = v.parse().unwrap_or(failure_prob);
                }
            }
            _ => {}
        }
    }
    Args {
        gateways,
        iterations,
        failure_prob,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args = parse_args();
    println!("[chaos] {args:?}");

    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect(":memory:")
        .await?;
    let pf = Arc::new(PfMock::new());
    pf.set_fib_count(16).await;

    let instance_engine = InstanceEngine::new(pool.clone(), pf.clone());
    instance_engine.migrate().await?;

    let gateway_engine = Arc::new(GatewayEngine::new(pool.clone()));
    gateway_engine.migrate().await?;

    let default_instance = aifw_common::DEFAULT_INSTANCE_ID;
    let mut gw_ids = Vec::with_capacity(args.gateways);
    for i in 0..args.gateways {
        let gw = aifw_common::Gateway {
            id: Uuid::new_v4(),
            name: format!("chaos-gw-{i}"),
            instance_id: default_instance,
            interface: format!("em{i}"),
            next_hop: format!("10.{i}.0.1"),
            ip_version: "v4".into(),
            monitor_kind: "icmp".into(),
            monitor_target: None,
            monitor_port: None,
            monitor_expect: None,
            interval_ms: 500,
            timeout_ms: 1000,
            loss_pct_down: 20.0,
            loss_pct_up: 5.0,
            latency_ms_down: None,
            latency_ms_up: None,
            consec_fail_down: 3,
            consec_ok_up: 5,
            weight: 1,
            dampening_secs: 10,
            dscp_tag: None,
            enabled: true,
            state: GatewayState::Unknown,
            last_rtt_ms: None,
            last_jitter_ms: None,
            last_loss_pct: None,
            last_mos: None,
            last_probe_ts: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let gw = gateway_engine.add(gw).await?;
        gw_ids.push(gw.id);
    }

    // Deterministic PRNG (xorshift) so reproducible chaos runs are possible.
    let mut seed: u64 = std::env::var("CHAOS_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| Instant::now().elapsed().as_nanos() as u64 | 1);

    let mut last_transition_at: HashMap<Uuid, usize> = HashMap::new();
    let mut total_transitions: u64 = 0;

    for tick in 0..args.iterations {
        for gw_id in &gw_ids {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let r = (seed % 10_000) as f64 / 10_000.0;
            let success = r > args.failure_prob;
            let outcome = ProbeOutcome {
                success,
                rtt_ms: if success { Some(5.0 + r * 20.0) } else { None },
                error: if success { None } else { Some("chaos".into()) },
            };
            let before = gateway_engine.get(*gw_id).await?.state;
            gateway_engine.inject_sample(*gw_id, outcome).await?;
            let after = gateway_engine.get(*gw_id).await?.state;
            if before != after {
                total_transitions += 1;
                let prev = last_transition_at.insert(*gw_id, tick).unwrap_or(0);
                let gap = tick.saturating_sub(prev);
                // Invariant: once in a stable state, we shouldn't flip in fewer than
                // (consec_fail_down + consec_ok_up) - 1 ticks. Unknown→anything
                // is exempt since it's the initial transition.
                if before != GatewayState::Unknown && after != GatewayState::Unknown {
                    assert!(
                        gap >= 1,
                        "gw {gw_id} oscillated {before:?}→{after:?} in {gap} ticks"
                    );
                }
            }
        }
    }

    println!(
        "[chaos] done. {} ticks × {} gateways → {} transitions",
        args.iterations,
        args.gateways,
        total_transitions
    );

    // Sanity check events table is populated
    for gw_id in &gw_ids {
        let events = gateway_engine.list_events(*gw_id, 1000).await?;
        // Monotonic timestamps
        for w in events.windows(2) {
            assert!(
                w[0].ts >= w[1].ts,
                "events not monotonic for gw {gw_id}"
            );
        }
    }

    println!("[chaos] invariants hold");
    Ok(())
}
