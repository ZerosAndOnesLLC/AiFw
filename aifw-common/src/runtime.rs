//! Tokio runtime sizing shared by the long-running binaries (#409).
//!
//! `#[tokio::main]` sizes the worker pool to `available_parallelism()`. On a
//! 2-vCPU appliance that leaves two workers for the API's dozen periodic
//! tasks (dashboard producer, memstats, retention, WAL checkpoint, SLA
//! aggregation, cluster replication, …) plus every request — a single
//! slow-but-not-blocking task visibly stalls the dashboard. A small floor
//! keeps the scheduler from being fully subscribed on tiny boxes without
//! over-provisioning large ones.

/// Fewest workers a long-running AiFw binary runs with.
pub const MIN_WORKER_THREADS: usize = 4;
/// Most workers we ever start regardless of core count (`AIFW_WORKER_THREADS`
/// can still go higher explicitly).
pub const MAX_WORKER_THREADS: usize = 32;
/// Environment override, e.g. `AIFW_WORKER_THREADS=8`.
pub const WORKER_THREADS_ENV: &str = "AIFW_WORKER_THREADS";

/// Worker count for the given core count and optional env override: the
/// override wins when it parses to ≥ 1; otherwise `cores` clamped to
/// [`MIN_WORKER_THREADS`]..=[`MAX_WORKER_THREADS`].
pub fn worker_threads_for(cores: usize, env_override: Option<&str>) -> usize {
    if let Some(v) = env_override
        && let Ok(n) = v.trim().parse::<usize>()
        && n >= 1
    {
        return n;
    }
    cores.clamp(MIN_WORKER_THREADS, MAX_WORKER_THREADS)
}

/// Worker count for this host (see [`worker_threads_for`]).
pub fn worker_threads() -> usize {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(MIN_WORKER_THREADS);
    worker_threads_for(cores, std::env::var(WORKER_THREADS_ENV).ok().as_deref())
}

/// Build the multi-thread runtime every long-running AiFw binary uses:
/// explicit worker count, named threads (visible in `top -H`/`procstat`),
/// all drivers enabled.
pub fn build(name: &'static str) -> std::io::Result<tokio::runtime::Runtime> {
    let workers = worker_threads();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .thread_name(name)
        .enable_all()
        .build()
}

/// Snapshot of the stable tokio runtime metrics, for `/api/v1/metrics` and
/// logs (#413). Only counters tokio exposes without `tokio_unstable` — the
/// full task-level view needs a `--features tokio-console` build.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RuntimeSnapshot {
    /// Configured worker threads.
    pub worker_threads: usize,
    /// Tasks currently alive (spawned and not yet completed).
    pub alive_tasks: usize,
    /// Tasks waiting in the global (injection) queue — sustained > 0 means
    /// the workers can't keep up.
    pub global_queue_depth: usize,
}

/// Read the runtime metrics of the current runtime.
pub fn snapshot() -> RuntimeSnapshot {
    let m = tokio::runtime::Handle::current().metrics();
    RuntimeSnapshot {
        worker_threads: m.num_workers(),
        alive_tasks: m.num_alive_tasks(),
        global_queue_depth: m.global_queue_depth(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_threads_floor_ceiling_and_override() {
        assert_eq!(worker_threads_for(1, None), MIN_WORKER_THREADS);
        assert_eq!(worker_threads_for(2, None), MIN_WORKER_THREADS);
        assert_eq!(worker_threads_for(8, None), 8);
        assert_eq!(worker_threads_for(128, None), MAX_WORKER_THREADS);
        assert_eq!(worker_threads_for(2, Some("6")), 6);
        assert_eq!(
            worker_threads_for(2, Some(" 48 ")),
            48,
            "explicit override may exceed the cap"
        );
        assert_eq!(
            worker_threads_for(2, Some("0")),
            MIN_WORKER_THREADS,
            "0 is not a valid count"
        );
        assert_eq!(worker_threads_for(2, Some("lots")), MIN_WORKER_THREADS);
    }

    #[test]
    fn build_creates_a_runtime_and_snapshot_reads_it() {
        let rt = build("aifw-test").unwrap();
        let snap = rt.block_on(async { snapshot() });
        assert!(snap.worker_threads >= 1);
        assert!(snap.alive_tasks <= 1);
    }
}
