"use client";

import { useEffect, useState, useCallback, useRef } from "react";

interface InterfaceInfo {
  name: string;
  ipv4: string | null;
  status: string;
}

interface InterfaceStats {
  name: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  errors_in: number;
  errors_out: number;
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

interface TrafficPoint {
  time: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatRate(bytesPerSec: number): string {
  if (bytesPerSec >= 1e9) return `${(bytesPerSec / 1e9).toFixed(1)} Gbps`;
  if (bytesPerSec >= 1e6) return `${(bytesPerSec / 1e6).toFixed(1)} Mbps`;
  if (bytesPerSec >= 1e3) return `${(bytesPerSec / 1e3).toFixed(1)} Kbps`;
  return `${bytesPerSec.toFixed(0)} bps`;
}

function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

async function apiFetch<T>(path: string): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  const res = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

// Simple bar chart component
function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.min((value / max) * 100, 100) : 0;
  return (
    <div className="w-full h-2 bg-gray-700 rounded-full overflow-hidden">
      <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export default function TrafficPage() {
  const [interfaces, setInterfaces] = useState<InterfaceInfo[]>([]);
  const [selectedNic, setSelectedNic] = useState<string>("");
  const [stats, setStats] = useState<InterfaceStats | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [history, setHistory] = useState<TrafficPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const prevStats = useRef<InterfaceStats | null>(null);
  const [rateIn, setRateIn] = useState(0);
  const [rateOut, setRateOut] = useState(0);

  // Fetch interfaces on mount
  useEffect(() => {
    apiFetch<{ data: InterfaceInfo[] }>("/api/v1/interfaces")
      .then((res) => {
        const ifaces = res.data.filter((i) => i.status === "up");
        setInterfaces(ifaces);
        if (ifaces.length > 0 && !selectedNic) {
          setSelectedNic(ifaces[0].name);
        }
      })
      .catch(() => {});
  }, [selectedNic]);

  // Fetch per-interface stats
  const fetchData = useCallback(async () => {
    if (!selectedNic) return;
    try {
      const [statsRes, connsRes] = await Promise.all([
        apiFetch<{ data: InterfaceStats }>(`/api/v1/interfaces/${selectedNic}/stats`),
        apiFetch<{ data: Connection[] }>("/api/v1/connections"),
      ]);

      const newStats = statsRes.data;
      setStats(newStats);
      setConnections(connsRes.data || []);

      // Calculate rate from delta
      if (prevStats.current) {
        const deltaIn = Math.max(0, newStats.bytes_in - prevStats.current.bytes_in);
        const deltaOut = Math.max(0, newStats.bytes_out - prevStats.current.bytes_out);
        setRateIn(deltaIn / 5 * 8); // bits per second (5s interval)
        setRateOut(deltaOut / 5 * 8);
      }
      prevStats.current = newStats;

      // Add to history
      setHistory((prev) => {
        const point: TrafficPoint = {
          time: new Date().toLocaleTimeString(),
          bytes_in: newStats.bytes_in,
          bytes_out: newStats.bytes_out,
          packets_in: newStats.packets_in,
          packets_out: newStats.packets_out,
        };
        const updated = [...prev, point].slice(-60); // keep last 5 minutes
        return updated;
      });

      setError(null);
    } catch (err) {
      // Fallback to global metrics if per-interface not available
      try {
        const metricsRes = await apiFetch<{ pf_bytes_in: number; pf_bytes_out: number; pf_packets_in: number; pf_packets_out: number }>("/api/v1/metrics");
        const fallback: InterfaceStats = {
          name: selectedNic,
          bytes_in: metricsRes.pf_bytes_in || 0,
          bytes_out: metricsRes.pf_bytes_out || 0,
          packets_in: metricsRes.pf_packets_in || 0,
          packets_out: metricsRes.pf_packets_out || 0,
          errors_in: 0,
          errors_out: 0,
        };
        setStats(fallback);
        if (prevStats.current) {
          const deltaIn = Math.max(0, fallback.bytes_in - prevStats.current.bytes_in);
          const deltaOut = Math.max(0, fallback.bytes_out - prevStats.current.bytes_out);
          setRateIn(deltaIn / 5 * 8);
          setRateOut(deltaOut / 5 * 8);
        }
        prevStats.current = fallback;
        setError(null);
      } catch (e2) {
        setError(e2 instanceof Error ? e2.message : "Failed to fetch data");
      }
    } finally {
      setLoading(false);
    }
  }, [selectedNic]);

  useEffect(() => {
    setLoading(true);
    prevStats.current = null;
    setHistory([]);
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, [fetchData]);

  // Compute top talkers
  const topTalkers = connections
    .reduce<{ ip: string; bytes: number; connections: number }[]>((acc, conn) => {
      const existing = acc.find((t) => t.ip === conn.src_addr);
      const total = conn.bytes_in + conn.bytes_out;
      if (existing) { existing.bytes += total; existing.connections += 1; }
      else { acc.push({ ip: conn.src_addr, bytes: total, connections: 1 }); }
      return acc;
    }, [])
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 10);

  // Compute top ports
  const topPorts = connections
    .reduce<{ port: number; connections: number }[]>((acc, conn) => {
      const existing = acc.find((p) => p.port === conn.dst_port);
      if (existing) { existing.connections += 1; }
      else { acc.push({ port: conn.dst_port, connections: 1 }); }
      return acc;
    }, [])
    .sort((a, b) => b.connections - a.connections)
    .slice(0, 10);

  const maxTalkerBytes = topTalkers.length > 0 ? topTalkers[0].bytes : 1;
  const maxPortConns = topPorts.length > 0 ? topPorts[0].connections : 1;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header with NIC selector */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Traffic Analytics</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Per-interface traffic monitoring &middot; auto-refreshing every 5s
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-sm text-[var(--text-muted)]">Interface:</label>
          <select
            value={selectedNic}
            onChange={(e) => setSelectedNic(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500"
          >
            {interfaces.map((iface) => (
              <option key={iface.name} value={iface.name}>
                {iface.name} {iface.ipv4 ? `(${iface.ipv4})` : ""}
              </option>
            ))}
          </select>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">{error}</div>
      )}

      {/* Rate & Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">Rate In</div>
          <div className="text-lg font-bold text-green-400">{formatRate(rateIn)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">Rate Out</div>
          <div className="text-lg font-bold text-blue-400">{formatRate(rateOut)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">Total In</div>
          <div className="text-lg font-bold text-cyan-400">{formatBytes(stats?.bytes_in ?? 0)}</div>
          <div className="text-xs text-[var(--text-muted)]">{formatNumber(stats?.packets_in ?? 0)} pkts</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">Total Out</div>
          <div className="text-lg font-bold text-orange-400">{formatBytes(stats?.bytes_out ?? 0)}</div>
          <div className="text-xs text-[var(--text-muted)]">{formatNumber(stats?.packets_out ?? 0)} pkts</div>
        </div>
      </div>

      {/* Traffic History (text-based sparkline) */}
      {history.length > 1 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Traffic Rate History ({selectedNic})</h3>
          <div className="flex items-end gap-px h-24">
            {history.slice(1).map((point, i) => {
              const prev = history[i];
              const deltaIn = Math.max(0, point.bytes_in - prev.bytes_in);
              const deltaOut = Math.max(0, point.bytes_out - prev.bytes_out);
              const maxDelta = Math.max(...history.slice(1).map((p, j) => {
                const pr = history[j];
                return Math.max(0, p.bytes_in - pr.bytes_in) + Math.max(0, p.bytes_out - pr.bytes_out);
              }), 1);
              const totalDelta = deltaIn + deltaOut;
              const height = Math.max(2, (totalDelta / maxDelta) * 100);
              const inPct = totalDelta > 0 ? (deltaIn / totalDelta) * 100 : 50;
              return (
                <div key={i} className="flex-1 flex flex-col justify-end" title={`${point.time}\nIn: ${formatBytes(deltaIn)}/5s\nOut: ${formatBytes(deltaOut)}/5s`}>
                  <div className="w-full rounded-t-sm overflow-hidden" style={{ height: `${height}%` }}>
                    <div className="bg-green-500" style={{ height: `${inPct}%` }} />
                    <div className="bg-blue-500" style={{ height: `${100 - inPct}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex justify-between mt-1 text-xs text-[var(--text-muted)]">
            <span>{history[1]?.time}</span>
            <span className="flex gap-4">
              <span className="flex items-center gap-1"><span className="w-2 h-2 bg-green-500 rounded-full" />In</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 bg-blue-500 rounded-full" />Out</span>
            </span>
            <span>{history[history.length - 1]?.time}</span>
          </div>
        </div>
      )}

      {/* Tables Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top Talkers</h3>
          </div>
          {topTalkers.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No connection data</div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {topTalkers.map((talker, i) => (
                <div key={talker.ip} className="px-4 py-2 hover:bg-[var(--bg-card-hover)] transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs">{i + 1}. {talker.ip}</span>
                    <span className="text-xs text-[var(--text-secondary)]">{formatBytes(talker.bytes)} / {talker.connections} conn</span>
                  </div>
                  <MiniBar value={talker.bytes} max={maxTalkerBytes} color="bg-cyan-500" />
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Ports */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top Destination Ports</h3>
          </div>
          {topPorts.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No connection data</div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {topPorts.map((entry, i) => (
                <div key={entry.port} className="px-4 py-2 hover:bg-[var(--bg-card-hover)] transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-cyan-400">{i + 1}. Port {entry.port}</span>
                    <span className="text-xs text-[var(--text-secondary)]">{entry.connections} connections</span>
                  </div>
                  <MiniBar value={entry.connections} max={maxPortConns} color="bg-blue-500" />
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
