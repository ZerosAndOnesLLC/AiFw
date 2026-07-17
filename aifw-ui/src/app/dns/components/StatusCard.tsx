"use client";

import type { DnsStatus, ServiceAction } from "@/lib/api/dns";

interface StatusCardProps {
  status: DnsStatus | null;
  actionLoading: string | null;
  onAction: (action: ServiceAction) => void;
}

/// Service status card: backend/health badges, last-switch banner,
/// stats grid, and start/stop/restart controls.
export function StatusCard({ status, actionLoading, onAction }: StatusCardProps) {
  const cacheTotal = (status?.cache_hits ?? 0) + (status?.cache_misses ?? 0);
  const cacheHitRate = cacheTotal > 0 ? ((status?.cache_hits ?? 0) / cacheTotal * 100).toFixed(1) : "0";

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold">Service Status</h2>
        <div className="flex items-center gap-2">
          {status?.backend && (
            <span className="text-xs px-2.5 py-1 rounded-full border font-medium bg-[var(--bg-primary)] border-[var(--border)] text-[var(--text-secondary)]">
              {status.backend === "rdns" ? "rDNS" : status.backend === "unbound" ? "Unbound" : status.backend}
            </span>
          )}
          <span
            className={`text-xs px-2.5 py-1 rounded-full border font-medium ${
              !status?.probe_enabled
                ? (status?.running
                    ? "bg-slate-500/20 text-slate-300 border-slate-500/30"
                    : "bg-red-500/20 text-red-400 border-red-500/30")
                : status?.listening_udp
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : status?.running
                    ? "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"
                    : "bg-red-500/20 text-red-400 border-red-500/30"
            }`}
            title={
              status?.probe_enabled
                ? `UDP: ${status?.listening_udp ? "up" : "down"} · TCP: ${status?.listening_tcp ? "up" : "down"}`
                : "Probe disabled — status reflects service process only, not port 53 liveness"
            }
          >
            {!status?.probe_enabled
              ? (status?.running ? "Running (probe off)" : "Stopped")
              : status?.listening_udp
                ? `Healthy${status?.listening_tcp ? "" : " (UDP only)"}`
                : status?.running
                  ? "Process up, port 53 silent"
                  : "Stopped"}
          </span>
        </div>
      </div>

      {status?.last_switch_result && (
        <div className={`mb-4 p-3 text-xs rounded border ${
          status.last_switch_result.startsWith("rolled_back") || status.last_switch_result.startsWith("failed")
            ? "bg-red-500/10 text-red-300 border-red-500/30"
            : "bg-blue-500/10 text-blue-300 border-blue-500/30"
        }`}>
          <span className="font-semibold">
            Last switch{status.last_switch_at ? " " + new Date(status.last_switch_at).toLocaleString() : ""}:
          </span>{" "}
          {status.last_switch_result}
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4 text-sm mb-5">
        <div>
          <span className="block text-xs text-[var(--text-muted)] mb-0.5">Version</span>
          <span className="text-[var(--text-primary)] font-mono text-xs">
            {status?.version || "-"}
          </span>
        </div>
        <div>
          <span className="block text-xs text-[var(--text-muted)] mb-0.5">Total Queries</span>
          <span className="text-[var(--text-primary)] font-semibold">
            {status?.queries_total ?? 0}
          </span>
        </div>
        <div>
          <span className="block text-xs text-[var(--text-muted)] mb-0.5">Cache Hit Rate</span>
          <span className="text-[var(--text-primary)] font-semibold">
            {cacheHitRate}%
          </span>
        </div>
        <div>
          <span className="block text-xs text-[var(--text-muted)] mb-0.5">Host Overrides</span>
          <span className="text-[var(--text-primary)] font-semibold">
            {status?.total_hosts ?? 0}
          </span>
        </div>
        <div>
          <span className="block text-xs text-[var(--text-muted)] mb-0.5">Domain Overrides</span>
          <span className="text-[var(--text-primary)] font-semibold">
            {status?.total_domains ?? 0}
          </span>
        </div>
        <div>
          <span className="block text-xs text-[var(--text-muted)] mb-0.5">Access Lists</span>
          <span className="text-[var(--text-primary)] font-semibold">
            {status?.total_acls ?? 0}
          </span>
        </div>
      </div>

      <div className="flex gap-3">
        <button
          onClick={() => onAction("start")}
          disabled={!!actionLoading || !!status?.running}
          className={`px-4 py-2 text-white text-sm rounded-md flex items-center gap-2 ${
            status?.running
              ? "bg-green-600/30 text-green-400/50 cursor-not-allowed"
              : "bg-green-600 hover:bg-green-700 disabled:opacity-50"
          }`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          {actionLoading === "start" ? "Starting..." : "Start"}
        </button>
        <button
          onClick={() => onAction("stop")}
          disabled={!!actionLoading || !status?.running}
          className={`px-4 py-2 text-white text-sm rounded-md flex items-center gap-2 ${
            !status?.running
              ? "bg-red-600/30 text-red-400/50 cursor-not-allowed"
              : "bg-red-600 hover:bg-red-700 disabled:opacity-50"
          }`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
          </svg>
          {actionLoading === "stop" ? "Stopping..." : "Stop"}
        </button>
        <button
          onClick={() => onAction("restart")}
          disabled={!!actionLoading || !status?.running}
          className={`px-4 py-2 text-white text-sm rounded-md flex items-center gap-2 ${
            !status?.running
              ? "bg-yellow-600/30 text-yellow-400/50 cursor-not-allowed"
              : "bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50"
          }`}
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
          </svg>
          {actionLoading === "restart" ? "Restarting..." : "Restart"}
        </button>
      </div>
    </div>
  );
}
