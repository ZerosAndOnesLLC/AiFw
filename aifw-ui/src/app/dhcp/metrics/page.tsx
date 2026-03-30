"use client";

import { useState, useEffect, useCallback, useRef } from "react";

interface PoolStats {
  subnet: string;
  total: number;
  allocated: number;
  available: number;
  utilization: number;
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

export default function DhcpMetricsPage() {
  const [stats, setStats] = useState<PoolStats[]>([]);
  const [rawMetrics, setRawMetrics] = useState("");
  const [loading, setLoading] = useState(true);
  const [showRaw, setShowRaw] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/pool-stats", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setStats(body.data || []);
    } catch {
      /* silent */
    }
  }, []);

  const fetchRawMetrics = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/metrics", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRawMetrics(await res.text());
    } catch {
      setRawMetrics("# rDHCP metrics unavailable (service may not be running)");
    }
  }, []);

  const fetchAll = useCallback(async () => {
    await Promise.all([fetchStats(), fetchRawMetrics()]);
  }, [fetchStats, fetchRawMetrics]);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchAll();
      setLoading(false);
    })();
  }, [fetchAll]);

  useEffect(() => {
    if (!autoRefresh) {
      if (intervalRef.current) clearInterval(intervalRef.current);
      return;
    }
    intervalRef.current = setInterval(fetchAll, 5000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, fetchAll]);

  const utilizationColor = (pct: number) => {
    if (pct >= 90) return "text-red-400";
    if (pct >= 70) return "text-yellow-400";
    return "text-green-400";
  };

  const barColor = (pct: number) => {
    if (pct >= 90) return "bg-red-500";
    if (pct >= 70) return "bg-yellow-500";
    return "bg-blue-500";
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">Loading metrics...</div>;
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">DHCP Metrics</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Pool utilization and Prometheus metrics from rDHCP
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-xs text-[var(--text-muted)] cursor-pointer">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded border-gray-600"
            />
            Auto-refresh (5s)
          </label>
          <button
            onClick={fetchAll}
            className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded-md transition-colors"
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Pool Utilization Cards */}
      {stats.length === 0 ? (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg px-6 py-8 text-center text-sm text-[var(--text-muted)]">
          No active subnets. Configure and apply DHCP subnets to see pool metrics.
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {stats.map((s) => (
            <div key={s.subnet} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5">
              <div className="flex items-center justify-between mb-3">
                <span className="font-mono text-sm text-[var(--text-primary)] font-medium">{s.subnet}</span>
                <span className={`text-lg font-bold ${utilizationColor(s.utilization)}`}>
                  {s.utilization.toFixed(1)}%
                </span>
              </div>
              <div className="h-3 bg-gray-800 rounded-full overflow-hidden mb-3">
                <div
                  className={`h-full rounded-full transition-all ${barColor(s.utilization)}`}
                  style={{ width: `${Math.min(s.utilization, 100)}%` }}
                />
              </div>
              <div className="grid grid-cols-3 text-center text-xs">
                <div>
                  <span className="block text-[var(--text-muted)]">Total</span>
                  <span className="text-[var(--text-primary)] font-semibold">{s.total.toLocaleString()}</span>
                </div>
                <div>
                  <span className="block text-[var(--text-muted)]">Allocated</span>
                  <span className="text-[var(--text-primary)] font-semibold">{s.allocated.toLocaleString()}</span>
                </div>
                <div>
                  <span className="block text-[var(--text-muted)]">Available</span>
                  <span className="text-[var(--text-primary)] font-semibold">{s.available.toLocaleString()}</span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Raw Prometheus Metrics */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <button
          onClick={() => setShowRaw((p) => !p)}
          className="w-full px-4 py-3 flex items-center justify-between hover:bg-white/[0.02] transition-colors"
        >
          <span className="text-sm font-medium text-[var(--text-primary)]">Prometheus Metrics</span>
          <svg
            className={`w-4 h-4 text-[var(--text-muted)] transition-transform ${showRaw ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </button>
        {showRaw && (
          <div className="border-t border-[var(--border)] p-4 overflow-x-auto">
            <pre className="font-mono text-xs text-[var(--text-secondary)] whitespace-pre-wrap">{rawMetrics || "No metrics available"}</pre>
          </div>
        )}
      </div>
    </div>
  );
}
