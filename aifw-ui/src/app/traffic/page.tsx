"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import Card from "@/components/Card";

interface MetricsData {
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
}

interface Connection {
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  protocol: string;
  packets_in: number;
  packets_out: number;
  bytes_in: number;
  bytes_out: number;
}

interface Talker {
  ip: string;
  bytes: number;
  connections: number;
}

interface PortEntry {
  port: number;
  connections: number;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
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

async function apiFetch<T>(path: string): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  const res = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export default function TrafficPage() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const initialLoad = useRef(true);

  const fetchData = useCallback(async () => {
    try {
      const [metricsRes, connsRes] = await Promise.all([
        apiFetch<MetricsData>("/api/v1/metrics"),
        apiFetch<{ data: Connection[] }>("/api/v1/connections"),
      ]);

      setMetrics(metricsRes);
      setConnections(connsRes.data || []);
      setError(null);
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

  // Compute top talkers: group by src_addr, sum bytes
  const topTalkers: Talker[] = connections
    .reduce<Talker[]>((acc, conn) => {
      const existing = acc.find((t) => t.ip === conn.src_addr);
      const totalBytes = conn.bytes_in + conn.bytes_out;
      if (existing) {
        existing.bytes += totalBytes;
        existing.connections += 1;
      } else {
        acc.push({ ip: conn.src_addr, bytes: totalBytes, connections: 1 });
      }
      return acc;
    }, [])
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  // Compute top ports: group by dst_port, count connections
  const topPorts: PortEntry[] = connections
    .reduce<PortEntry[]>((acc, conn) => {
      const existing = acc.find((p) => p.port === conn.dst_port);
      if (existing) {
        existing.connections += 1;
      } else {
        acc.push({ port: conn.dst_port, connections: 1 });
      }
      return acc;
    }, [])
    .sort((a, b) => b.connections - a.connections)
    .slice(0, 10);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[var(--text-muted)]">Loading traffic data...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Traffic Analytics</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Network traffic monitoring and bandwidth utilization &middot; auto-refreshing every 5s
        </p>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card
          title="Packets In"
          value={formatNumber(metrics?.packets_in ?? 0)}
          color="cyan"
        />
        <Card
          title="Packets Out"
          value={formatNumber(metrics?.packets_out ?? 0)}
          color="blue"
        />
        <Card
          title="Bytes In"
          value={formatBytes(metrics?.bytes_in ?? 0)}
          color="green"
        />
        <Card
          title="Bytes Out"
          value={formatBytes(metrics?.bytes_out ?? 0)}
          color="red"
        />
      </div>

      {/* Tables Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top Talkers (by total bytes)</h3>
          </div>
          {topTalkers.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No connection data</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">#</th>
                    <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">IP Address</th>
                    <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Bytes</th>
                    <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Conns</th>
                  </tr>
                </thead>
                <tbody>
                  {topTalkers.map((talker, i) => (
                    <tr key={talker.ip} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                      <td className="py-2 px-3 text-xs text-[var(--text-muted)]">{i + 1}</td>
                      <td className="py-2 px-3 font-mono text-xs">{talker.ip}</td>
                      <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{formatBytes(talker.bytes)}</td>
                      <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{talker.connections.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Top Destination Ports */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top Destination Ports (by connections)</h3>
          </div>
          {topPorts.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No connection data</div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">#</th>
                    <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Port</th>
                    <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Connections</th>
                  </tr>
                </thead>
                <tbody>
                  {topPorts.map((entry, i) => (
                    <tr key={entry.port} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                      <td className="py-2 px-3 text-xs text-[var(--text-muted)]">{i + 1}</td>
                      <td className="py-2 px-3 font-mono text-xs text-cyan-400">{entry.port}</td>
                      <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{entry.connections.toLocaleString()}</td>
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
