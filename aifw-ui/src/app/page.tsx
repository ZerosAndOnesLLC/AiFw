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

interface RatePoint {
  time: number;
  bpsIn: number;
  bpsOut: number;
  ppsIn: number;
  ppsOut: number;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatBps(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`;
  return `${bps.toFixed(0)} bps`;
}

function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatTime(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// Smooth area chart with gradient fill
function TrafficChart({ data, height = 160 }: { data: RatePoint[]; height?: number }) {
  if (data.length < 3) {
    return (
      <div className="flex items-center justify-center text-[var(--text-muted)] text-sm" style={{ height }}>
        Collecting data...
      </div>
    );
  }

  const w = 900;
  const h = height;
  const pad = { top: 10, right: 10, bottom: 25, left: 60 };
  const chartW = w - pad.left - pad.right;
  const chartH = h - pad.top - pad.bottom;

  const maxVal = Math.max(...data.map((d) => Math.max(d.bpsIn, d.bpsOut)), 1000);
  const scaleY = (v: number) => pad.top + chartH - (v / maxVal) * chartH;
  const scaleX = (i: number) => pad.left + (i / (data.length - 1)) * chartW;

  // Generate smooth path using cardinal spline
  const smoothPath = (points: { x: number; y: number }[]): string => {
    if (points.length < 2) return "";
    let d = `M ${points[0].x},${points[0].y}`;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[Math.max(0, i - 1)];
      const p1 = points[i];
      const p2 = points[i + 1];
      const p3 = points[Math.min(points.length - 1, i + 2)];
      const cp1x = p1.x + (p2.x - p0.x) / 6;
      const cp1y = p1.y + (p2.y - p0.y) / 6;
      const cp2x = p2.x - (p3.x - p1.x) / 6;
      const cp2y = p2.y - (p3.y - p1.y) / 6;
      d += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p2.x},${p2.y}`;
    }
    return d;
  };

  const inPoints = data.map((d, i) => ({ x: scaleX(i), y: scaleY(d.bpsIn) }));
  const outPoints = data.map((d, i) => ({ x: scaleX(i), y: scaleY(d.bpsOut) }));

  const inLine = smoothPath(inPoints);
  const outLine = smoothPath(outPoints);

  // Area paths (close to bottom)
  const baseline = pad.top + chartH;
  const inArea = `${inLine} L ${inPoints[inPoints.length - 1].x},${baseline} L ${inPoints[0].x},${baseline} Z`;
  const outArea = `${outLine} L ${outPoints[outPoints.length - 1].x},${baseline} L ${outPoints[0].x},${baseline} Z`;

  // Y-axis labels
  const yTicks = 5;
  const yLabels = Array.from({ length: yTicks + 1 }, (_, i) => {
    const val = (maxVal / yTicks) * i;
    return { y: scaleY(val), label: formatBps(val) };
  });

  // X-axis labels (show every ~30s)
  const xStep = Math.max(1, Math.floor(data.length / 6));
  const xLabels = data.filter((_, i) => i % xStep === 0 || i === data.length - 1)
    .map((d, idx) => ({
      x: scaleX(data.indexOf(d) >= 0 ? data.indexOf(d) : idx * xStep),
      label: formatTime(d.time),
    }));

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="gradIn" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#22c55e" stopOpacity="0.4" />
          <stop offset="100%" stopColor="#22c55e" stopOpacity="0.02" />
        </linearGradient>
        <linearGradient id="gradOut" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02" />
        </linearGradient>
      </defs>

      {/* Grid lines */}
      {yLabels.map((t, i) => (
        <g key={i}>
          <line x1={pad.left} y1={t.y} x2={w - pad.right} y2={t.y} stroke="#1e293b" strokeWidth="1" />
          <text x={pad.left - 5} y={t.y + 3} textAnchor="end" fill="#64748b" fontSize="10" fontFamily="monospace">{t.label}</text>
        </g>
      ))}

      {/* X-axis labels */}
      {xLabels.map((t, i) => (
        <text key={i} x={t.x} y={h - 5} textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="monospace">{t.label}</text>
      ))}

      {/* Area fills */}
      <path d={inArea} fill="url(#gradIn)" />
      <path d={outArea} fill="url(#gradOut)" />

      {/* Lines */}
      <path d={inLine} fill="none" stroke="#22c55e" strokeWidth="2" strokeLinejoin="round" />
      <path d={outLine} fill="none" stroke="#3b82f6" strokeWidth="2" strokeLinejoin="round" />

      {/* Current value dots */}
      {inPoints.length > 0 && (
        <circle cx={inPoints[inPoints.length - 1].x} cy={inPoints[inPoints.length - 1].y} r="3" fill="#22c55e" />
      )}
      {outPoints.length > 0 && (
        <circle cx={outPoints[outPoints.length - 1].x} cy={outPoints[outPoints.length - 1].y} r="3" fill="#3b82f6" />
      )}
    </svg>
  );
}

export default function Dashboard() {
  const [status, setStatus] = useState<StatusData | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rateHistory, setRateHistory] = useState<RatePoint[]>([]);
  const [currentRateIn, setCurrentRateIn] = useState(0);
  const [currentRateOut, setCurrentRateOut] = useState(0);
  const [currentPpsIn, setCurrentPpsIn] = useState(0);
  const [currentPpsOut, setCurrentPpsOut] = useState(0);
  const prevStatus = useRef<StatusData | null>(null);
  const prevTime = useRef<number>(0);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connectWs = useCallback(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws`);
    wsRef.current = ws;

    ws.onopen = () => { setWsConnected(true); setError(null); };
    ws.onmessage = (event) => {
      try {
        const msg: WsMessage = JSON.parse(event.data);
        if (msg.type !== "status_update") return;

        const now = Date.now();
        setStatus(msg.status);
        setConnections(msg.connections || []);

        if (prevStatus.current && prevTime.current) {
          const dtSec = (now - prevTime.current) / 1000;
          if (dtSec > 0 && dtSec < 10) {
            const bpsIn = Math.max(0, (msg.status.bytes_in - prevStatus.current.bytes_in) / dtSec * 8);
            const bpsOut = Math.max(0, (msg.status.bytes_out - prevStatus.current.bytes_out) / dtSec * 8);
            const ppsIn = Math.max(0, (msg.status.packets_in - prevStatus.current.packets_in) / dtSec);
            const ppsOut = Math.max(0, (msg.status.packets_out - prevStatus.current.packets_out) / dtSec);
            setCurrentRateIn(bpsIn);
            setCurrentRateOut(bpsOut);
            setCurrentPpsIn(ppsIn);
            setCurrentPpsOut(ppsOut);
            setRateHistory((prev) => [...prev, { time: now, bpsIn, bpsOut, ppsIn, ppsOut }].slice(-300));
          }
        }
        prevStatus.current = msg.status;
        prevTime.current = now;
      } catch { /* ignore */ }
    };
    ws.onclose = () => {
      setWsConnected(false);
      wsRef.current = null;
      reconnectTimer.current = setTimeout(connectWs, 3000);
    };
    ws.onerror = () => { setError("WebSocket connection failed"); ws.close(); };
  }, []);

  useEffect(() => {
    connectWs();
    return () => {
      if (wsRef.current) wsRef.current.close();
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
    };
  }, [connectWs]);

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
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Dashboard</h1>
          <p className="text-sm text-[var(--text-muted)]">Real-time firewall monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${wsConnected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
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

      {/* Throughput + Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 col-span-1">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">In</div>
          <div className="text-lg font-bold text-green-400">{formatBps(currentRateIn)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatNumber(currentPpsIn)} pps</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 col-span-1">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Out</div>
          <div className="text-lg font-bold text-blue-400">{formatBps(currentRateOut)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatNumber(currentPpsOut)} pps</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Rules</div>
          <div className="text-lg font-bold">{status.pf_rules}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{status.aifw_active_rules} managed</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">NAT</div>
          <div className="text-lg font-bold">{status.nat_rules}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">States</div>
          <div className="text-lg font-bold text-cyan-400">{formatNumber(status.pf_states)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider">Connections</div>
          <div className="text-lg font-bold">{connections.length}</div>
        </div>
      </div>

      {/* Traffic Graph */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium">Network Throughput</h3>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-[3px] bg-green-500 rounded-full inline-block" /> Inbound
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-[3px] bg-blue-500 rounded-full inline-block" /> Outbound
            </span>
          </div>
        </div>
        <TrafficChart data={rateHistory} height={180} />
      </div>

      {/* Totals */}
      <div className="grid grid-cols-4 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-center">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total In</div>
          <div className="text-sm font-bold text-green-400">{formatBytes(status.bytes_in)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatNumber(status.packets_in)} pkts</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-center">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total Out</div>
          <div className="text-sm font-bold text-blue-400">{formatBytes(status.bytes_out)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatNumber(status.packets_out)} pkts</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-center">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total Traffic</div>
          <div className="text-sm font-bold">{formatBytes(status.bytes_in + status.bytes_out)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-center">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total Packets</div>
          <div className="text-sm font-bold">{formatNumber(status.packets_in + status.packets_out)}</div>
        </div>
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
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs">{t.ip}</span>
                    <span className="text-xs text-[var(--text-secondary)]">{formatBytes(t.bytes)} · {t.conns} conn</span>
                  </div>
                  <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-cyan-500 transition-all duration-300" style={{ width: `${(t.bytes / maxTalkerBytes) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Connections */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Active Connections ({connections.length})</h3>
          </div>
          <div className="overflow-y-auto max-h-64">
            {connections.length === 0 ? (
              <div className="text-center py-8 text-[var(--text-muted)] text-sm">No active connections</div>
            ) : (
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[var(--border)]">
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[10px] font-medium">Proto</th>
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[10px] font-medium">Source</th>
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[10px] font-medium">Destination</th>
                    <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[10px] font-medium">State</th>
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
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
