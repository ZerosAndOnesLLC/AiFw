"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { api } from "@/lib/api";
import { usePolling } from "@/lib/usePolling";
import {
  RELAY_ABUSE_REASONS,
  RELAY_DROP_REASONS,
  RELAY_REASON_HELP,
  parseRelayMetrics,
  relayDelta,
  type RelayMetrics,
} from "@/lib/dhcp/relayMetrics";

interface PoolStats {
  subnet: string;
  total: number;
  allocated: number;
  available: number;
  utilization: number;
}

export default function DhcpMetricsPage() {
  const [stats, setStats] = useState<PoolStats[]>([]);
  const [rawMetrics, setRawMetrics] = useState("");
  // Relay counters (#159): current sample plus the delta since the previous
  // poll so a burst of drops stands out even against a large lifetime total.
  const [relay, setRelay] = useState<RelayMetrics | null>(null);
  const [relayDeltaState, setRelayDeltaState] = useState<RelayMetrics | null>(null);
  const prevRelay = useRef<RelayMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [showRaw, setShowRaw] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchStats = useCallback(async () => {
    try {
      const body = await api.get<{ data?: PoolStats[] }>("/api/v1/dhcp/pool-stats");
      setStats(body.data || []);
    } catch {
      /* silent */
    }
  }, []);

  const fetchRawMetrics = useCallback(async () => {
    try {
      const text = await api.getText("/api/v1/dhcp/metrics");
      setRawMetrics(text);
      const parsed = parseRelayMetrics(text);
      setRelayDeltaState(relayDelta(prevRelay.current, parsed));
      prevRelay.current = parsed;
      setRelay(parsed);
    } catch {
      setRawMetrics("# rDHCP metrics unavailable (service may not be running)");
    }
  }, []);

  const fetchAll = useCallback(async () => {
    await Promise.all([fetchStats(), fetchRawMetrics()]);
    setLoading(false);
  }, [fetchStats, fetchRawMetrics]);

  // Fetch on mount even when auto-refresh is off.
  useEffect(() => {
    if (!autoRefresh) queueMicrotask(fetchAll);
  }, [fetchAll, autoRefresh]);
  usePolling(fetchAll, 5000, autoRefresh);

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
              <div className="grid grid-cols-1 sm:grid-cols-3 text-center text-xs">
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

      {/* DHCP relay (#159) — global counters from rDHCP */}
      {relay?.present && (() => {
        const abuse = RELAY_ABUSE_REASONS.some((r) => (relayDeltaState?.dropped[r] ?? 0) > 0);
        return (
          <div className={`bg-[var(--bg-card)] border rounded-lg p-5 ${abuse ? "border-red-500/50" : "border-[var(--border)]"}`}>
            <div className="flex items-center justify-between mb-3">
              <div>
                <h2 className="text-sm font-medium text-[var(--text-primary)]">DHCP relay</h2>
                <p className="text-xs text-[var(--text-muted)]">Relayed (giaddr ≠ 0) DHCPv4 traffic across all subnets — lifetime totals, with the change since the last refresh.</p>
              </div>
              {abuse && (
                <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border border-red-500/40 text-red-400 bg-red-500/10">
                  new untrusted / bad-giaddr drops
                </span>
              )}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-center text-xs mb-4">
              <div>
                <span className="block text-[var(--text-muted)]">Received</span>
                <span className="text-lg font-bold text-[var(--text-primary)]">{relay.received.toLocaleString()}</span>
                {relayDeltaState && relayDeltaState.received > 0 && <span className="block text-[10px] text-cyan-400">+{relayDeltaState.received}</span>}
              </div>
              <div>
                <span className="block text-[var(--text-muted)]">Accepted</span>
                <span className="text-lg font-bold text-green-400">{relay.accepted.toLocaleString()}</span>
                {relayDeltaState && relayDeltaState.accepted > 0 && <span className="block text-[10px] text-green-400">+{relayDeltaState.accepted}</span>}
              </div>
              <div>
                <span className="block text-[var(--text-muted)]">Dropped</span>
                <span className={`text-lg font-bold ${relay.droppedTotal > 0 ? "text-red-400" : "text-[var(--text-primary)]"}`}>{relay.droppedTotal.toLocaleString()}</span>
                {relayDeltaState && relayDeltaState.droppedTotal > 0 && <span className="block text-[10px] text-red-400">+{relayDeltaState.droppedTotal}</span>}
              </div>
            </div>
            <table className="w-full text-xs">
              <thead className="text-[var(--text-muted)] uppercase tracking-wider text-[10px]">
                <tr><th className="text-left py-1">Drop reason</th><th className="text-right py-1">Total</th><th className="text-right py-1">Since refresh</th></tr>
              </thead>
              <tbody>
                {RELAY_DROP_REASONS.map((r) => {
                  const hot = RELAY_ABUSE_REASONS.includes(r) && (relayDeltaState?.dropped[r] ?? 0) > 0;
                  return (
                    <tr key={r} className={`border-t border-[var(--border)] ${hot ? "text-red-300" : ""}`} title={RELAY_REASON_HELP[r]}>
                      <td className="py-1.5 font-mono">{r}<span className="ml-2 font-sans text-[var(--text-muted)] hidden sm:inline">— {RELAY_REASON_HELP[r]}</span></td>
                      <td className="py-1.5 text-right font-mono">{relay.dropped[r].toLocaleString()}</td>
                      <td className="py-1.5 text-right font-mono">{(relayDeltaState?.dropped[r] ?? 0) > 0 ? `+${relayDeltaState?.dropped[r]}` : "–"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        );
      })()}

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
