"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

interface StatusData {
  pf_running: boolean;
  pf_states: number;
  pf_rules: number;
  aifw_rules: number;
  aifw_active_rules: number;
  nat_rules: number;
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
}

interface MetricsData {
  pf_running: boolean;
  pf_states_count: number;
  pf_rules_count: number;
  pf_packets_in: number;
  pf_packets_out: number;
  pf_bytes_in: number;
  pf_bytes_out: number;
  aifw_rules_total: number;
  aifw_rules_active: number;
  aifw_nat_rules_total: number;
}

interface Connection {
  id: number;
  protocol: string;
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  state: string;
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
  age_secs: number;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

function Sparkline({ data, color, height = 40 }: { data: { value: number }[]; color: string; height?: number }) {
  if (data.length < 2) return null;
  const values = data.map((d) => d.value);
  const min = Math.min(...values);
  const max = Math.max(...values) || 1;
  const range = max - min || 1;
  const w = 200;

  const points = values
    .map((v, i) => `${(i / (values.length - 1)) * w},${height - ((v - min) / range) * (height - 4) - 2}`)
    .join(" ");

  const areaPoints = `0,${height} ${points} ${w},${height}`;

  return (
    <svg viewBox={`0 0 ${w} ${height}`} className="w-full" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill={`url(#grad-${color.replace("#", "")})`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function MiniBarChart({ data, color }: { data: { label: string; value: number }[]; color: string }) {
  const max = Math.max(...data.map((d) => d.value)) || 1;
  return (
    <div className="space-y-1.5">
      {data.map((d) => (
        <div key={d.label} className="flex items-center gap-2 text-xs">
          <span className="w-24 text-[var(--text-muted)] truncate font-mono">{d.label}</span>
          <div className="flex-1 bg-[var(--bg-primary)] rounded-full h-2 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${(d.value / max) * 100}%`, backgroundColor: color }}
            />
          </div>
          <span className="w-16 text-right text-[var(--text-secondary)]">{formatBytes(d.value)}</span>
        </div>
      ))}
    </div>
  );
}

async function apiFetch<T>(path: string): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  const res = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export default function Dashboard() {
  const [time, setTime] = useState(new Date());
  const [status, setStatus] = useState<StatusData | null>(null);
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // History for sparklines (store last 60 snapshots)
  const [packetsInHistory, setPacketsInHistory] = useState<{ value: number }[]>([]);
  const [packetsOutHistory, setPacketsOutHistory] = useState<{ value: number }[]>([]);
  const [bytesInHistory, setBytesInHistory] = useState<{ value: number }[]>([]);
  const [bytesOutHistory, setBytesOutHistory] = useState<{ value: number }[]>([]);
  const [statesHistory, setStatesHistory] = useState<{ value: number }[]>([]);
  const initialLoad = useRef(true);

  const fetchData = useCallback(async () => {
    try {
      const [statusRes, metricsRes, connsRes] = await Promise.all([
        apiFetch<StatusData>("/api/v1/status"),
        apiFetch<MetricsData>("/api/v1/metrics"),
        apiFetch<{ data: Connection[] }>("/api/v1/connections"),
      ]);

      setStatus(statusRes);
      setMetrics(metricsRes);
      setConnections(connsRes.data || []);
      setError(null);

      // Append to history (max 60 points)
      setPacketsInHistory((prev) => [...prev, { value: metricsRes.pf_packets_in }].slice(-60));
      setPacketsOutHistory((prev) => [...prev, { value: metricsRes.pf_packets_out }].slice(-60));
      setBytesInHistory((prev) => [...prev, { value: metricsRes.pf_bytes_in }].slice(-60));
      setBytesOutHistory((prev) => [...prev, { value: metricsRes.pf_bytes_out }].slice(-60));
      setStatesHistory((prev) => [...prev, { value: metricsRes.pf_states_count }].slice(-60));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch data");
    } finally {
      if (initialLoad.current) {
        setLoading(false);
        initialLoad.current = false;
      }
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Compute top talkers from connections
  const topTalkers = connections
    .reduce<{ label: string; value: number }[]>((acc, conn) => {
      const existing = acc.find((t) => t.label === conn.src_addr);
      const total = conn.bytes_in + conn.bytes_out;
      if (existing) {
        existing.value += total;
      } else {
        acc.push({ label: conn.src_addr, value: total });
      }
      return acc;
    }, [])
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[var(--text-muted)]">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {time.toLocaleDateString()} {time.toLocaleTimeString()} &middot; System Overview
          </p>
        </div>
        <div className="flex items-center gap-3">
          <StatusBadge status={status?.pf_running ? "running" : "down"} size="md" />
          <span className="text-sm text-[var(--text-secondary)]">
            pf {status?.pf_running ? "active" : "inactive"}
          </span>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card
          title="Rules"
          value={metrics?.aifw_rules_total ?? status?.aifw_rules ?? 0}
          color="blue"
          subtitle={`${metrics?.aifw_rules_active ?? status?.aifw_active_rules ?? 0} active`}
        />
        <Card
          title="Active Rules"
          value={metrics?.aifw_rules_active ?? status?.aifw_active_rules ?? 0}
          color="green"
        />
        <Card
          title="NAT Rules"
          value={metrics?.aifw_nat_rules_total ?? status?.nat_rules ?? 0}
          color="cyan"
        />
        <Card
          title="pf States"
          value={formatNumber(metrics?.pf_states_count ?? status?.pf_states ?? 0)}
          color="yellow"
          subtitle="active connections"
        />
        <Card
          title="Packets In"
          value={formatNumber(status?.packets_in ?? metrics?.pf_packets_in ?? 0)}
          color="cyan"
        />
        <Card
          title="Packets Out"
          value={formatNumber(status?.packets_out ?? metrics?.pf_packets_out ?? 0)}
          color="blue"
        />
      </div>

      {/* Bytes Cards */}
      <div className="grid grid-cols-2 md:grid-cols-2 gap-3">
        <Card
          title="Bytes In"
          value={formatBytes(status?.bytes_in ?? metrics?.pf_bytes_in ?? 0)}
          color="green"
        />
        <Card
          title="Bytes Out"
          value={formatBytes(status?.bytes_out ?? metrics?.pf_bytes_out ?? 0)}
          color="red"
        />
      </div>

      {/* Sparkline Charts Row */}
      {packetsInHistory.length >= 2 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Packets In/Out */}
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium">Packets In</h3>
              <span className="text-xs text-[var(--text-muted)]">Last {packetsInHistory.length} samples</span>
            </div>
            <Sparkline data={packetsInHistory} color="#22d3ee" height={60} />
            <div className="mt-2">
              <h3 className="text-sm font-medium mb-2">Packets Out</h3>
              <Sparkline data={packetsOutHistory} color="#3b82f6" height={40} />
            </div>
          </div>

          {/* Bytes In/Out */}
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium">Bytes In</h3>
              <span className="text-xs text-[var(--text-muted)]">Last {bytesInHistory.length} samples</span>
            </div>
            <Sparkline data={bytesInHistory} color="#22c55e" height={60} />
            <div className="mt-2">
              <h3 className="text-sm font-medium mb-2">Bytes Out</h3>
              <Sparkline data={bytesOutHistory} color="#ef4444" height={40} />
            </div>
          </div>
        </div>
      )}

      {/* Connection States Sparkline */}
      {statesHistory.length >= 2 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">pf States Over Time</h3>
            <span className="text-xs text-[var(--text-muted)]">
              current: {formatNumber(metrics?.pf_states_count ?? 0)}
            </span>
          </div>
          <Sparkline data={statesHistory} color="#a78bfa" height={60} />
        </div>
      )}

      {/* Top Talkers */}
      {topTalkers.length > 0 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Top Talkers (by bytes)</h3>
          <MiniBarChart data={topTalkers} color="#22d3ee" />
        </div>
      )}
    </div>
  );
}
