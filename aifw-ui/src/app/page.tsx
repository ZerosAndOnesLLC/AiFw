"use client";

import { useEffect, useState } from "react";
import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

// Demo data for graphs (replaced by real API data in production)
function generateTimeSeries(points: number, base: number, variance: number) {
  return Array.from({ length: points }, (_, i) => ({
    time: new Date(Date.now() - (points - i) * 60000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    value: Math.max(0, base + (Math.random() - 0.5) * variance * 2),
  }));
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatRate(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(1)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`;
  return `${bps.toFixed(0)} bps`;
}

// Simple SVG sparkline component (no recharts dependency needed for this)
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
        <linearGradient id={`grad-${color}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill={`url(#grad-${color})`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// Mini bar chart
function MiniBarChart({ data, color }: { data: { label: string; value: number }[]; color: string }) {
  const max = Math.max(...data.map((d) => d.value)) || 1;
  return (
    <div className="space-y-1.5">
      {data.map((d) => (
        <div key={d.label} className="flex items-center gap-2 text-xs">
          <span className="w-16 text-[var(--text-muted)] truncate">{d.label}</span>
          <div className="flex-1 bg-[var(--bg-primary)] rounded-full h-2 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${(d.value / max) * 100}%`, backgroundColor: color }}
            />
          </div>
          <span className="w-12 text-right text-[var(--text-secondary)]">{d.value}</span>
        </div>
      ))}
    </div>
  );
}

export default function Dashboard() {
  const [time, setTime] = useState(new Date());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Demo metrics data
  const trafficIn = generateTimeSeries(60, 150, 80);
  const trafficOut = generateTimeSeries(60, 90, 50);
  const stateCount = generateTimeSeries(60, 2500, 500);
  const ppsIn = generateTimeSeries(60, 5000, 2000);
  const threatCount = generateTimeSeries(60, 3, 4);
  const connRate = generateTimeSeries(60, 45, 20);

  const protocolBreakdown = [
    { label: "TCP", value: 1847 },
    { label: "UDP", value: 623 },
    { label: "ICMP", value: 42 },
    { label: "Other", value: 8 },
  ];

  const topTalkers = [
    { label: "10.0.0.15", value: 8420 },
    { label: "10.0.0.22", value: 5120 },
    { label: "10.0.0.8", value: 3840 },
    { label: "10.0.0.45", value: 2560 },
    { label: "10.0.0.3", value: 1280 },
  ];

  const threatTypes = [
    { label: "Port Scan", value: 12 },
    { label: "Brute Force", value: 7 },
    { label: "DDoS", value: 3 },
    { label: "C2 Beacon", value: 1 },
    { label: "DNS Tunnel", value: 0 },
  ];

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
          <StatusBadge status="running" size="md" />
          <span className="text-sm text-[var(--text-secondary)]">pf active</span>
        </div>
      </div>

      {/* Key Metrics Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card title="States" value="2,520" color="cyan" subtitle="active connections" />
        <Card title="Rules" value="24" color="blue" subtitle="18 active" />
        <Card title="NAT Rules" value="6" color="green" />
        <Card title="Threats" value="3" color="red" subtitle="last hour" />
        <Card title="Bandwidth In" value={formatRate(156_000_000)} color="cyan" />
        <Card title="Bandwidth Out" value={formatRate(89_000_000)} color="blue" />
      </div>

      {/* Traffic Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Bandwidth */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Bandwidth (Mbps)</h3>
            <span className="text-xs text-[var(--text-muted)]">Last 60 min</span>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs text-[var(--text-secondary)]">
              <span className="w-2 h-2 rounded-full bg-cyan-400"></span> Inbound
              <span className="ml-3 w-2 h-2 rounded-full bg-blue-400"></span> Outbound
            </div>
            <Sparkline data={trafficIn} color="#22d3ee" height={60} />
            <Sparkline data={trafficOut} color="#3b82f6" height={40} />
          </div>
        </div>

        {/* Packets per Second */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Packets/sec</h3>
            <span className="text-xs text-[var(--text-muted)]">Last 60 min</span>
          </div>
          <Sparkline data={ppsIn} color="#a78bfa" height={80} />
          <div className="flex justify-between text-xs text-[var(--text-muted)] mt-1">
            <span>avg: 5,120 pps</span>
            <span>peak: 8,940 pps</span>
          </div>
        </div>
      </div>

      {/* Second Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Connection States */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Connection States</h3>
            <span className="text-xs text-[var(--text-muted)]">Last 60 min</span>
          </div>
          <Sparkline data={stateCount} color="#22c55e" height={60} />
          <div className="flex justify-between text-xs text-[var(--text-muted)] mt-1">
            <span>current: 2,520</span>
            <span>peak: 3,210</span>
          </div>
        </div>

        {/* New Connections/sec */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">New Connections/sec</h3>
            <span className="text-xs text-[var(--text-muted)]">Last 60 min</span>
          </div>
          <Sparkline data={connRate} color="#f59e0b" height={60} />
          <div className="flex justify-between text-xs text-[var(--text-muted)] mt-1">
            <span>avg: 45/s</span>
            <span>peak: 72/s</span>
          </div>
        </div>

        {/* Threat Detections */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Threat Detections</h3>
            <span className="text-xs text-[var(--text-muted)]">Last 60 min</span>
          </div>
          <Sparkline data={threatCount} color="#ef4444" height={60} />
          <div className="flex justify-between text-xs text-[var(--text-muted)] mt-1">
            <span>total: 23</span>
            <span>blocked: 19</span>
          </div>
        </div>
      </div>

      {/* Breakdown Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Protocol Breakdown */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Protocol Distribution</h3>
          <MiniBarChart data={protocolBreakdown} color="#3b82f6" />
        </div>

        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Top Talkers (connections)</h3>
          <MiniBarChart data={topTalkers} color="#22d3ee" />
        </div>

        {/* Threat Breakdown */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Threats by Type (24h)</h3>
          <MiniBarChart data={threatTypes} color="#ef4444" />
        </div>
      </div>

      {/* System Health Row */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
        <Card title="pf Rules (kernel)" value="42" color="blue" />
        <Card title="Queues" value="4" color="green" subtitle="CoDel active" />
        <Card title="Rate Limits" value="3" color="yellow" subtitle="2 overloaded" />
        <Card title="VPN Tunnels" value="2" color="cyan" subtitle="1 WireGuard, 1 IPsec" />
      </div>
    </div>
  );
}
