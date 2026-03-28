"use client";

import { useEffect, useState, useRef, useCallback } from "react";

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

interface Connection {
  protocol: string;
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  state: string;
  bytes_in: number;
  bytes_out: number;
}

interface WsMessage {
  type: string;
  status: StatusData;
  connections: Connection[];
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

function formatRate(bitsPerSec: number): string {
  if (bitsPerSec >= 1e9) return `${(bitsPerSec / 1e9).toFixed(1)} Gbps`;
  if (bitsPerSec >= 1e6) return `${(bitsPerSec / 1e6).toFixed(1)} Mbps`;
  if (bitsPerSec >= 1e3) return `${(bitsPerSec / 1e3).toFixed(1)} Kbps`;
  return `${bitsPerSec.toFixed(0)} bps`;
}

function Sparkline({ data, color, height = 40 }: { data: number[]; color: string; height?: number }) {
  if (data.length < 2) return null;
  const min = Math.min(...data);
  const max = Math.max(...data) || 1;
  const range = max - min || 1;
  const w = 200;
  const points = data
    .map((v, i) => `${(i / (data.length - 1)) * w},${height - ((v - min) / range) * (height - 4) - 2}`)
    .join(" ");
  const areaPoints = `0,${height} ${points} ${w},${height}`;

  return (
    <svg viewBox={`0 0 ${w} ${height}`} className="w-full" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`sg-${color.replace(/[^a-z0-9]/gi, "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill={`url(#sg-${color.replace(/[^a-z0-9]/gi, "")})`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function StatCard({ title, value, subtitle, color, sparkData }: {
  title: string; value: string | number; subtitle?: string; color: string; sparkData?: number[];
}) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 relative overflow-hidden">
      <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">{title}</div>
      <div className="text-xl font-bold" style={{ color }}>{value}</div>
      {subtitle && <div className="text-xs text-[var(--text-muted)] mt-0.5">{subtitle}</div>}
      {sparkData && sparkData.length > 2 && (
        <div className="mt-2 h-8">
          <Sparkline data={sparkData} color={color} height={32} />
        </div>
      )}
    </div>
  );
}

export default function Dashboard() {
  const [status, setStatus] = useState<StatusData | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // History for sparklines
  const [packetsInHist, setPacketsInHist] = useState<number[]>([]);
  const [packetsOutHist, setPacketsOutHist] = useState<number[]>([]);
  const [bytesInHist, setBytesInHist] = useState<number[]>([]);
  const [bytesOutHist, setBytesOutHist] = useState<number[]>([]);
  const [statesHist, setStatesHist] = useState<number[]>([]);

  // Rate calculation
  const prevStatus = useRef<StatusData | null>(null);
  const [rateIn, setRateIn] = useState(0);
  const [rateOut, setRateOut] = useState(0);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connectWs = useCallback(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/api/v1/ws`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      setWsConnected(true);
      setError(null);
    };

    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        if (msg.type === "status_update") {
          setStatus(msg.status);
          setConnections(msg.connections || []);

          // Calculate rates (2s interval)
          if (prevStatus.current) {
            const deltaIn = Math.max(0, msg.status.bytes_in - prevStatus.current.bytes_in);
            const deltaOut = Math.max(0, msg.status.bytes_out - prevStatus.current.bytes_out);
            setRateIn(deltaIn / 2 * 8);
            setRateOut(deltaOut / 2 * 8);
          }
          prevStatus.current = msg.status;

          // Append to history
          setPacketsInHist((p) => [...p, msg.status.packets_in].slice(-60));
          setPacketsOutHist((p) => [...p, msg.status.packets_out].slice(-60));
          setBytesInHist((p) => [...p, msg.status.bytes_in].slice(-60));
          setBytesOutHist((p) => [...p, msg.status.bytes_out].slice(-60));
          setStatesHist((p) => [...p, msg.status.pf_states].slice(-60));
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      setWsConnected(false);
      wsRef.current = null;
      // Reconnect after 3 seconds
      reconnectTimer.current = setTimeout(connectWs, 3000);
    };

    ws.onerror = () => {
      setError("WebSocket connection failed");
      ws.close();
    };
  }, []);

  useEffect(() => {
    connectWs();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connectWs]);

  // Top talkers from connections
  const topTalkers = connections
    .reduce<{ ip: string; bytes: number; conns: number }[]>((acc, c) => {
      const existing = acc.find((t) => t.ip === c.src_addr);
      const total = c.bytes_in + c.bytes_out;
      if (existing) { existing.bytes += total; existing.conns++; }
      else { acc.push({ ip: c.src_addr, bytes: total, conns: 1 }); }
      return acc;
    }, [])
    .sort((a, b) => b.bytes - a.bytes)
    .slice(0, 5);

  const maxTalkerBytes = topTalkers[0]?.bytes || 1;

  if (!status) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-[var(--text-muted)]">Connecting to firewall...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)]">Real-time firewall monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${wsConnected ? "bg-green-500" : "bg-red-500"}`} />
            <span className="text-xs text-[var(--text-muted)]">{wsConnected ? "Live" : "Reconnecting..."}</span>
          </div>
          <div className={`px-2 py-1 rounded text-xs font-medium ${
            status.pf_running ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"
          }`}>
            pf {status.pf_running ? "Active" : "Inactive"}
          </div>
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">{error}</div>
      )}

      {/* Rate Cards */}
      <div className="grid grid-cols-2 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">Throughput In</div>
          <div className="text-2xl font-bold text-green-400">{formatRate(rateIn)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider mb-1">Throughput Out</div>
          <div className="text-2xl font-bold text-blue-400">{formatRate(rateOut)}</div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard title="Rules" value={status.aifw_rules} subtitle={`${status.aifw_active_rules} active`} color="#3b82f6" />
        <StatCard title="NAT Rules" value={status.nat_rules} color="#8b5cf6" />
        <StatCard title="PF States" value={formatNumber(status.pf_states)} color="#06b6d4" sparkData={statesHist} />
        <StatCard title="PF Rules" value={status.pf_rules} color="#f59e0b" />
      </div>

      {/* Traffic Cards with Sparklines */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatCard title="Packets In" value={formatNumber(status.packets_in)} color="#22c55e" sparkData={packetsInHist} />
        <StatCard title="Packets Out" value={formatNumber(status.packets_out)} color="#3b82f6" sparkData={packetsOutHist} />
        <StatCard title="Bytes In" value={formatBytes(status.bytes_in)} color="#06b6d4" sparkData={bytesInHist} />
        <StatCard title="Bytes Out" value={formatBytes(status.bytes_out)} color="#f97316" sparkData={bytesOutHist} />
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top Talkers</h3>
          </div>
          {topTalkers.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No active connections</div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {topTalkers.map((t) => (
                <div key={t.ip} className="px-4 py-2.5 hover:bg-[var(--bg-card-hover)] transition-colors">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-xs">{t.ip}</span>
                    <span className="text-xs text-[var(--text-secondary)]">{formatBytes(t.bytes)} / {t.conns} conn</span>
                  </div>
                  <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-cyan-500" style={{ width: `${(t.bytes / maxTalkerBytes) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Active Connections Summary */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Active Connections ({connections.length})</h3>
          </div>
          {connections.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No active connections</div>
          ) : (
            <div className="overflow-y-auto max-h-64">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase tracking-wider font-medium">Proto</th>
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase tracking-wider font-medium">Source</th>
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase tracking-wider font-medium">Destination</th>
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase tracking-wider font-medium">State</th>
                  </tr>
                </thead>
                <tbody>
                  {connections.slice(0, 20).map((c, i) => (
                    <tr key={i} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)]">
                      <td className="py-1.5 px-3 uppercase text-cyan-400">{c.protocol}</td>
                      <td className="py-1.5 px-3 font-mono">{c.src_addr}:{c.src_port}</td>
                      <td className="py-1.5 px-3 font-mono">{c.dst_addr}:{c.dst_port}</td>
                      <td className="py-1.5 px-3 text-[var(--text-secondary)]">{c.state.split(":")[0]}</td>
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
