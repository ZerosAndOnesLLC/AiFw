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

      {/* Engine Control — prominent start/stop */}
      <div className={`rounded-lg border-2 p-5 ${
        currentMode === "disabled"
          ? "border-gray-500/30 bg-gray-500/5"
          : currentMode === "ids"
          ? "border-blue-500/30 bg-blue-500/5"
          : "border-red-500/30 bg-red-500/5"
      }`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center ${
              currentMode === "disabled"
                ? "bg-gray-600"
                : currentMode === "ids"
                ? "bg-blue-600"
                : "bg-red-600"
            }`}>
              {currentMode === "disabled" ? (
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5.636 5.636a9 9 0 1012.728 0M12 3v9" />
                </svg>
              ) : (
                <svg className="w-6 h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
              )}
            </div>
            <div>
              <h3 className="text-base font-semibold">
                {currentMode === "disabled"
                  ? "Engine Stopped"
                  : currentMode === "ids"
                  ? "IDS Running — Monitor Mode"
                  : "IPS Running — Active Blocking"}
              </h3>
              <p className="text-xs text-[var(--text-muted)] mt-0.5">
                {currentMode === "disabled"
                  ? "The intrusion detection engine is not running. Start it to begin monitoring network traffic."
                  : currentMode === "ids"
                  ? "Analyzing traffic and generating alerts. Threats are detected but not blocked."
                  : "Analyzing traffic and actively blocking threats. Malicious packets are dropped."}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {currentMode === "disabled" ? (
              <>
                <button
                  onClick={() => handleModeChange("ids")}
                  disabled={modeChanging}
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" /></svg>
                  {modeChanging ? "Starting..." : "Start IDS"}
                </button>
                <button
                  onClick={() => handleModeChange("ips")}
                  disabled={modeChanging}
                  className="px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" /></svg>
                  {modeChanging ? "Starting..." : "Start IPS"}
                </button>
              </>
            ) : (
              <>
                <button
                  onClick={() => handleModeChange(currentMode === "ids" ? "ips" : "ids")}
                  disabled={modeChanging}
                  className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors disabled:opacity-50 border ${
                    currentMode === "ids"
                      ? "border-red-500/30 text-red-400 hover:bg-red-500/10"
                      : "border-blue-500/30 text-blue-400 hover:bg-blue-500/10"
                  }`}
                >
                  {currentMode === "ids" ? "Switch to IPS" : "Switch to IDS"}
                </button>
                <button
                  onClick={() => handleModeChange("disabled")}
                  disabled={modeChanging}
                  className="px-4 py-2 bg-gray-600 hover:bg-gray-500 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                >
                  <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5.25 7.5A2.25 2.25 0 017.5 5.25h9a2.25 2.25 0 012.25 2.25v9a2.25 2.25 0 01-2.25 2.25h-9a2.25 2.25 0 01-2.25-2.25v-9z" /></svg>
                  {modeChanging ? "Stopping..." : "Stop"}
                </button>
              </>
            )}
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
