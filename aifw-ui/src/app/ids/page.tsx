"use client";

import { useState, useEffect, useCallback } from "react";
import Card from "@/components/Card";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

interface IdsStats {
  packets_inspected: number;
  alerts_total: number;
  drops_total: number;
  bytes_per_sec: number;
  active_flows: number;
  packets_per_sec: number;
  uptime_secs: number;
}

interface StatsResponse {
  stats: IdsStats;
  mode: string;
  severity_counts: [string, number][];
  top_signatures: [string, number][];
  top_sources: [string, number][];
  loaded_rules: number;
  enabled_rulesets: number;
  total_rulesets: number;
  running: boolean;
}

interface SectionFeedback {
  type: "success" | "error";
  message: string;
}

function FeedbackBanner({ feedback }: { feedback: SectionFeedback | null }) {
  if (!feedback) return null;
  const isError = feedback.type === "error";
  return (
    <div
      className={`p-3 text-sm rounded-md border ${
        isError
          ? "text-red-400 bg-red-500/10 border-red-500/20"
          : "text-green-400 bg-green-500/10 border-green-500/20"
      }`}
    >
      {feedback.message}
    </div>
  );
}

function formatNumber(n: number): string {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

const severityColors: Record<string, { bg: string; bar: string; text: string }> = {
  critical: { bg: "bg-red-500/20", bar: "bg-red-500", text: "text-red-400" },
  high: { bg: "bg-orange-500/20", bar: "bg-orange-500", text: "text-orange-400" },
  medium: { bg: "bg-yellow-500/20", bar: "bg-yellow-500", text: "text-yellow-400" },
  info: { bg: "bg-blue-500/20", bar: "bg-blue-500", text: "text-blue-400" },
};

const modeOptions = ["disabled", "ids", "ips"] as const;

export default function IdsDashboardPage() {
  const [data, setData] = useState<StatsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);
  const [modeChanging, setModeChanging] = useState(false);

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/ids/stats`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`Failed to fetch stats: ${res.status}`);
      const json = await res.json();
      setData(json.data || json);
    } catch (err: unknown) {
      if (loading) {
        const msg = err instanceof Error ? err.message : "Failed to load stats";
        setFeedback({ type: "error", message: msg });
        clearFeedback();
      }
    } finally {
      setLoading(false);
    }
  }, [loading, clearFeedback]);

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, [fetchStats]);

  async function handleModeChange(newMode: string) {
    setModeChanging(true);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/config`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ mode: newMode }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Failed to change mode: ${res.status}`);
      }
      setFeedback({ type: "success", message: `Mode changed to ${newMode.toUpperCase()}` });
      clearFeedback();
      await fetchStats();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to change mode";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setModeChanging(false);
    }
  }

  const stats = data?.stats;
  const severityCounts = data?.severity_counts || [];
  const topSignatures = data?.top_signatures || [];
  const topSources = data?.top_sources || [];

  const totalSeverity = severityCounts.reduce((s, [, c]) => s + c, 0) || 1;
  const maxSigCount = topSignatures.length > 0 ? topSignatures[0][1] : 1;
  const maxSrcCount = topSources.length > 0 ? topSources[0][1] : 1;
  const currentMode = data?.mode || "disabled";

  function formatUptime(secs: number): string {
    if (secs < 60) return `${secs}s`;
    if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    if (h < 24) return `${h}h ${m}m`;
    const d = Math.floor(h / 24);
    return `${d}d ${h % 24}h ${m}m`;
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-[var(--text-muted)]">Loading IDS stats...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Intrusion Detection</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Real-time network threat monitoring and prevention
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
          <span className="text-xs text-[var(--text-muted)]">Auto-refresh 5s</span>
        </div>
      </div>

      <FeedbackBanner feedback={feedback} />

      {/* Mode Toggle */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-medium">Engine Mode</h3>
            <p className="text-xs text-[var(--text-muted)] mt-0.5">
              IDS monitors and alerts, IPS actively blocks threats
            </p>
          </div>
          <div className="flex items-center gap-1 bg-[var(--bg-primary)] rounded-lg p-1 border border-[var(--border)]">
            {modeOptions.map((mode) => (
              <button
                key={mode}
                onClick={() => handleModeChange(mode)}
                disabled={modeChanging || currentMode === mode}
                className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all ${
                  currentMode === mode
                    ? mode === "disabled"
                      ? "bg-gray-600 text-white"
                      : mode === "ids"
                      ? "bg-blue-600 text-white"
                      : "bg-red-600 text-white"
                    : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                } disabled:opacity-50`}
              >
                {mode.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Engine Info */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium">Engine Overview</h3>
          <div className="flex items-center gap-1.5">
            <div
              className={`w-2 h-2 rounded-full ${
                data?.running ? "bg-green-500 animate-pulse" : "bg-gray-500"
              }`}
            />
            <span className="text-xs text-[var(--text-muted)]">
              {data?.running ? "Running" : "Stopped"}
            </span>
          </div>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <span className="text-[11px] text-[var(--text-muted)] uppercase tracking-wider">
              Engine
            </span>
            <p className="text-sm font-medium mt-0.5">AiFw IDS/IPS</p>
            <p className="text-[11px] text-[var(--text-muted)]">
              Suricata-compatible rule engine with Aho-Corasick prefilter,
              Sigma &amp; YARA support
            </p>
          </div>
          <div>
            <span className="text-[11px] text-[var(--text-muted)] uppercase tracking-wider">
              Loaded Rules
            </span>
            <p className="text-sm font-mono font-bold mt-0.5">
              {(data?.loaded_rules ?? 0).toLocaleString()}
            </p>
            <p className="text-[11px] text-[var(--text-muted)]">
              compiled &amp; active
            </p>
          </div>
          <div>
            <span className="text-[11px] text-[var(--text-muted)] uppercase tracking-wider">
              Rulesets
            </span>
            <p className="text-sm font-mono font-bold mt-0.5">
              {data?.enabled_rulesets ?? 0}{" "}
              <span className="text-[var(--text-muted)] font-normal">
                / {data?.total_rulesets ?? 0}
              </span>
            </p>
            <p className="text-[11px] text-[var(--text-muted)]">
              enabled / total
            </p>
          </div>
          <div>
            <span className="text-[11px] text-[var(--text-muted)] uppercase tracking-wider">
              Uptime
            </span>
            <p className="text-sm font-mono font-bold mt-0.5">
              {formatUptime(stats?.uptime_secs ?? 0)}
            </p>
            <p className="text-[11px] text-[var(--text-muted)]">
              {(stats?.bytes_per_sec ?? 0) > 0
                ? `${((stats?.bytes_per_sec ?? 0) / 1024).toFixed(1)} KB/s throughput`
                : "no traffic"}
            </p>
          </div>
        </div>
        <div className="mt-3 pt-3 border-t border-[var(--border)]">
          <div className="flex flex-wrap gap-2">
            {["Suricata Rules", "Sigma Rules", "YARA Rules", "Content Prefilter", "PCRE Matching", "Flow Tracking", "IP Reputation"].map(
              (cap) => (
                <span
                  key={cap}
                  className="text-[10px] px-2 py-0.5 rounded-full bg-[var(--bg-primary)] border border-[var(--border)] text-[var(--text-secondary)]"
                >
                  {cap}
                </span>
              )
            )}
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <Card
          title="Packets Inspected"
          value={formatNumber(stats?.packets_inspected ?? 0)}
          color="cyan"
          subtitle="total analyzed"
        />
        <Card
          title="Alerts Total"
          value={formatNumber(stats?.alerts_total ?? 0)}
          color="yellow"
          subtitle="signatures matched"
        />
        <Card
          title="Drops Total"
          value={formatNumber(stats?.drops_total ?? 0)}
          color="red"
          subtitle="packets dropped"
        />
        <Card
          title="Active Flows"
          value={formatNumber(stats?.active_flows ?? 0)}
          color="blue"
          subtitle="tracked connections"
        />
        <Card
          title="Packets/sec"
          value={formatNumber(stats?.packets_per_sec ?? 0)}
          color="green"
          subtitle="current throughput"
        />
      </div>

      {/* Severity Breakdown */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="text-sm font-medium mb-3">Alert Severity Breakdown</h3>
        {severityCounts.length === 0 ? (
          <p className="text-xs text-[var(--text-muted)]">No alerts recorded</p>
        ) : (
          <div className="space-y-2">
            {/* Stacked bar */}
            <div className="flex h-6 rounded-md overflow-hidden">
              {severityCounts.map(([severity, count]) => {
                const colors = severityColors[severity] || severityColors.info;
                const pct = (count / totalSeverity) * 100;
                if (pct === 0) return null;
                return (
                  <div
                    key={severity}
                    className={`${colors.bar} flex items-center justify-center transition-all`}
                    style={{ width: `${pct}%` }}
                    title={`${severity}: ${count}`}
                  >
                    {pct > 8 && (
                      <span className="text-[10px] font-medium text-white/90">
                        {count}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
            {/* Legend */}
            <div className="flex gap-4 flex-wrap">
              {severityCounts.map(([severity, count]) => {
                const colors = severityColors[severity] || severityColors.info;
                return (
                  <div key={severity} className="flex items-center gap-1.5">
                    <div className={`w-2.5 h-2.5 rounded-sm ${colors.bar}`} />
                    <span className="text-xs text-[var(--text-secondary)] capitalize">
                      {severity}
                    </span>
                    <span className={`text-xs font-mono ${colors.text}`}>
                      {count.toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Top Signatures + Top Sources */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top 10 Alerting Signatures */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
            <h3 className="text-sm font-medium">Top Alerting Signatures</h3>
            <span className="text-xs text-[var(--text-muted)]">{topSignatures.length} entries</span>
          </div>
          {topSignatures.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
              No signature alerts recorded
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                      Signature
                    </th>
                    <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-24">
                      Count
                    </th>
                    <th className="py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-32">
                      Bar
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topSignatures.map(([name, count], idx) => (
                    <tr
                      key={idx}
                      className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors"
                    >
                      <td className="py-2 px-3 text-xs text-[var(--text-primary)] truncate max-w-[300px]">
                        {name}
                      </td>
                      <td className="py-2 px-3 text-xs text-right font-mono text-[var(--text-secondary)]">
                        {count.toLocaleString()}
                      </td>
                      <td className="py-2 px-3">
                        <div className="w-full h-1.5 bg-[var(--bg-primary)] rounded-full">
                          <div
                            className="h-full rounded-full bg-orange-500 transition-all"
                            style={{ width: `${(count / maxSigCount) * 100}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top 10 Source IPs */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
            <h3 className="text-sm font-medium">Top Source IPs</h3>
            <span className="text-xs text-[var(--text-muted)]">{topSources.length} entries</span>
          </div>
          {topSources.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-[var(--text-muted)]">
              No source IP alerts recorded
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                      Source IP
                    </th>
                    <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-24">
                      Alerts
                    </th>
                    <th className="py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-32">
                      Bar
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {topSources.map(([ip, count], idx) => (
                    <tr
                      key={idx}
                      className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors"
                    >
                      <td className="py-2 px-3 text-xs font-mono text-[var(--text-primary)]">
                        {ip}
                      </td>
                      <td className="py-2 px-3 text-xs text-right font-mono text-[var(--text-secondary)]">
                        {count.toLocaleString()}
                      </td>
                      <td className="py-2 px-3">
                        <div className="w-full h-1.5 bg-[var(--bg-primary)] rounded-full">
                          <div
                            className="h-full rounded-full bg-red-500 transition-all"
                            style={{ width: `${(count / maxSrcCount) * 100}%` }}
                          />
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
