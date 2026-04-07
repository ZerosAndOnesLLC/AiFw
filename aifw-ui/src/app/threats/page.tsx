"use client";

import { useState, useEffect, useCallback } from "react";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

interface IdsAlert {
  id: string;
  timestamp: string;
  signature_id: number | null;
  signature_msg: string;
  severity: number;
  src_ip: string;
  src_port: number | null;
  dst_ip: string;
  dst_port: number | null;
  protocol: string;
  action: string;
  acknowledged: boolean;
  payload_excerpt?: string;
}

function severityLabel(sev: number): string {
  if (sev === 1) return "critical";
  if (sev === 2) return "high";
  if (sev === 3) return "medium";
  return "info";
}

function severityColor(sev: number): { text: string; bg: string; border: string } {
  if (sev === 1) return { text: "text-red-400", bg: "bg-red-500/15", border: "border-red-500/30" };
  if (sev === 2) return { text: "text-orange-400", bg: "bg-orange-500/15", border: "border-orange-500/30" };
  if (sev === 3) return { text: "text-yellow-400", bg: "bg-yellow-500/15", border: "border-yellow-500/30" };
  return { text: "text-blue-400", bg: "bg-blue-500/15", border: "border-blue-500/30" };
}

function formatTime(iso: string): string {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

export default function ThreatsPage() {
  const [alerts, setAlerts] = useState<IdsAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "critical" | "high" | "medium" | "info">("all");
  const [acknowledging, setAcknowledging] = useState<string | null>(null);

  const fetchAlerts = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/ids/alerts?limit=200`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setAlerts(json.data || []);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 10_000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  const handleAcknowledge = async (id: string) => {
    setAcknowledging(id);
    try {
      await fetch(`${API}/api/v1/ids/alerts/${id}/acknowledge`, {
        method: "PUT", headers: authHeaders(),
      });
      await fetchAlerts();
    } catch { /* ignore */ }
    finally { setAcknowledging(null); }
  };

  const filtered = filter === "all" ? alerts : alerts.filter(a => severityLabel(a.severity) === filter);

  const counts = {
    total: alerts.length,
    critical: alerts.filter(a => a.severity === 1).length,
    high: alerts.filter(a => a.severity === 2).length,
    medium: alerts.filter(a => a.severity === 3).length,
    info: alerts.filter(a => a.severity >= 4).length,
    unacked: alerts.filter(a => !a.acknowledged).length,
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-[var(--text-muted)]">Loading threat data...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Threats</h1>
          <p className="text-sm text-[var(--text-muted)]">
            IDS/IPS alerts and threat detections — auto-refreshes every 10s
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-xs text-[var(--text-muted)]">Live</span>
        </div>
      </div>

      {/* WIP Banner */}
      <div className="bg-yellow-500/5 border border-yellow-500/30 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <div className="text-yellow-400 mt-0.5 flex-shrink-0">
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          </div>
          <div>
            <p className="text-sm font-medium text-yellow-400">Work in Progress</p>
            <p className="text-xs text-[var(--text-muted)] mt-1">
              The AI/ML threat detection module is experimental and disabled by default.
              This page shows IDS/IPS alerts from Suricata-compatible rule matching.
              AI-based detectors (port scan, DDoS, brute force, C2 beacon, DNS tunnel) will be added in future releases.
              AiFw works as a full-featured firewall without AI enabled.
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
          <button onClick={() => { setLoading(true); fetchAlerts(); }}
            className="ml-3 underline text-xs">Retry</button>
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "Total", count: counts.total, color: "text-[var(--text-primary)]", border: "border-[var(--border)]" },
          { label: "Critical", count: counts.critical, color: "text-red-400", border: "border-red-500/30" },
          { label: "High", count: counts.high, color: "text-orange-400", border: "border-orange-500/30" },
          { label: "Medium", count: counts.medium, color: "text-yellow-400", border: "border-yellow-500/30" },
          { label: "Info", count: counts.info, color: "text-blue-400", border: "border-blue-500/30" },
          { label: "Unacked", count: counts.unacked, color: "text-purple-400", border: "border-purple-500/30" },
        ].map(c => (
          <div key={c.label} className={`bg-[var(--bg-card)] border ${c.border} rounded-lg p-3 text-center`}>
            <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">{c.label}</div>
            <div className={`text-xl font-bold mt-1 ${c.color}`}>{c.count}</div>
          </div>
        ))}
      </div>

      {/* Filter tabs */}
      <div className="flex gap-1 bg-[var(--bg-card)] rounded-lg p-1 border border-[var(--border)] w-fit">
        {(["all", "critical", "high", "medium", "info"] as const).map(f => (
          <button key={f} onClick={() => setFilter(f)}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-all capitalize ${
              filter === f ? "bg-[var(--accent)] text-white" : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}>
            {f === "all" ? `All (${counts.total})` : f}
          </button>
        ))}
      </div>

      {/* Alerts table */}
      {filtered.length === 0 ? (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-12 text-center">
          <div className="text-4xl mb-4 text-green-500">&#x2714;</div>
          <p className="text-lg font-medium">No {filter === "all" ? "" : filter + " "}threats detected</p>
          <p className="text-sm text-[var(--text-muted)] mt-2">
            {alerts.length === 0
              ? "Enable IDS/IPS and configure rulesets to start detecting threats."
              : "No alerts match the current filter."}
          </p>
        </div>
      ) : (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm min-w-[800px]">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  {["Time", "Severity", "Signature", "Source", "Destination", "Proto", "Action", ""].map(h => (
                    <th key={h} className="text-left py-2.5 px-3 text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map(alert => {
                  const sev = severityColor(alert.severity);
                  return (
                    <tr key={alert.id} className={`border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors ${alert.acknowledged ? "opacity-50" : ""}`}>
                      <td className="py-2 px-3 text-xs text-[var(--text-muted)] font-mono whitespace-nowrap">
                        {formatTime(alert.timestamp)}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium uppercase tracking-wider ${sev.text} ${sev.bg} ${sev.border}`}>
                          {severityLabel(alert.severity)}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-xs max-w-xs">
                        <div className="font-medium truncate">{alert.signature_msg}</div>
                        {alert.signature_id && (
                          <div className="text-[10px] text-[var(--text-muted)] font-mono">SID:{alert.signature_id}</div>
                        )}
                      </td>
                      <td className="py-2 px-3 text-xs font-mono text-[var(--text-secondary)]">
                        {alert.src_ip}{alert.src_port ? `:${alert.src_port}` : ""}
                      </td>
                      <td className="py-2 px-3 text-xs font-mono text-[var(--text-secondary)]">
                        {alert.dst_ip}{alert.dst_port ? `:${alert.dst_port}` : ""}
                      </td>
                      <td className="py-2 px-3 text-xs uppercase text-cyan-400">{alert.protocol}</td>
                      <td className="py-2 px-3 text-xs">
                        <span className={alert.action === "drop" || alert.action === "reject" ? "text-red-400 font-medium" : "text-yellow-400"}>
                          {alert.action}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right">
                        {!alert.acknowledged && (
                          <button
                            onClick={() => handleAcknowledge(alert.id)}
                            disabled={acknowledging === alert.id}
                            className="text-[10px] px-2 py-1 rounded bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--accent)] transition-colors disabled:opacity-50"
                          >
                            {acknowledging === alert.id ? "..." : "Ack"}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="text-xs text-[var(--text-muted)] text-center">
        Showing {filtered.length} of {alerts.length} alerts
      </div>
    </div>
  );
}
