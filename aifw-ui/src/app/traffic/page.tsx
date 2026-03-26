"use client";

import { useState, useMemo } from "react";
import Card from "@/components/Card";

type TimeRange = "5m" | "1h" | "24h" | "7d" | "30d";

const timeRangeConfig: Record<TimeRange, { label: string; points: number; interval: string }> = {
  "5m": { label: "5m", points: 30, interval: "10s" },
  "1h": { label: "1h", points: 60, interval: "1m" },
  "24h": { label: "24h", points: 96, interval: "15m" },
  "7d": { label: "7d", points: 84, interval: "2h" },
  "30d": { label: "30d", points: 90, interval: "8h" },
};

function generateTimeSeries(points: number, base: number, variance: number): { value: number }[] {
  return Array.from({ length: points }, () => ({
    value: Math.max(0, base + (Math.random() - 0.5) * variance * 2),
  }));
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
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

function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toFixed(0);
}

function Sparkline({
  data,
  color,
  secondaryData,
  secondaryColor,
  height = 40,
  id,
}: {
  data: { value: number }[];
  color: string;
  secondaryData?: { value: number }[];
  secondaryColor?: string;
  height?: number;
  id: string;
}) {
  if (data.length < 2) return null;
  const allValues = [
    ...data.map((d) => d.value),
    ...(secondaryData?.map((d) => d.value) || []),
  ];
  const min = Math.min(...allValues);
  const max = Math.max(...allValues) || 1;
  const range = max - min || 1;
  const w = 300;

  function toPoints(values: number[]): string {
    return values
      .map((v, i) => `${(i / (values.length - 1)) * w},${height - ((v - min) / range) * (height - 4) - 2}`)
      .join(" ");
  }

  const points = toPoints(data.map((d) => d.value));
  const areaPoints = `0,${height} ${points} ${w},${height}`;

  const secondaryPoints = secondaryData ? toPoints(secondaryData.map((d) => d.value)) : null;
  const secondaryAreaPoints = secondaryPoints ? `0,${height} ${secondaryPoints} ${w},${height}` : null;

  return (
    <svg viewBox={`0 0 ${w} ${height}`} className="w-full" preserveAspectRatio="none">
      <defs>
        <linearGradient id={`grad-${id}-primary`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
        {secondaryColor && (
          <linearGradient id={`grad-${id}-secondary`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={secondaryColor} stopOpacity="0.2" />
            <stop offset="100%" stopColor={secondaryColor} stopOpacity="0.02" />
          </linearGradient>
        )}
      </defs>
      <polygon points={areaPoints} fill={`url(#grad-${id}-primary)`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
      {secondaryPoints && secondaryAreaPoints && secondaryColor && (
        <>
          <polygon points={secondaryAreaPoints} fill={`url(#grad-${id}-secondary)`} />
          <polyline points={secondaryPoints} fill="none" stroke={secondaryColor} strokeWidth="1.5" strokeLinejoin="round" />
        </>
      )}
    </svg>
  );
}

interface Talker {
  ip: string;
  bytes: number;
  packets: number;
  connections: number;
}

interface PortEntry {
  port: number;
  protocol: string;
  service: string;
  connections: number;
  bytes: number;
}

const demoTalkers: Talker[] = [
  { ip: "10.0.0.15", bytes: 4_820_000_000, packets: 3_210_000, connections: 842 },
  { ip: "10.0.0.22", bytes: 2_910_000_000, packets: 1_940_000, connections: 512 },
  { ip: "10.0.0.8", bytes: 1_840_000_000, packets: 1_230_000, connections: 384 },
  { ip: "203.0.113.42", bytes: 1_320_000_000, packets: 880_000, connections: 256 },
  { ip: "10.0.0.45", bytes: 980_000_000, packets: 653_000, connections: 198 },
  { ip: "198.51.100.17", bytes: 720_000_000, packets: 480_000, connections: 145 },
  { ip: "10.0.0.3", bytes: 540_000_000, packets: 360_000, connections: 112 },
  { ip: "192.0.2.88", bytes: 410_000_000, packets: 273_000, connections: 89 },
  { ip: "10.0.0.100", bytes: 290_000_000, packets: 193_000, connections: 67 },
  { ip: "10.0.0.51", bytes: 180_000_000, packets: 120_000, connections: 45 },
];

const demoPorts: PortEntry[] = [
  { port: 443, protocol: "TCP", service: "HTTPS", connections: 1847, bytes: 5_200_000_000 },
  { port: 80, protocol: "TCP", service: "HTTP", connections: 623, bytes: 1_800_000_000 },
  { port: 53, protocol: "UDP", service: "DNS", connections: 412, bytes: 82_000_000 },
  { port: 22, protocol: "TCP", service: "SSH", connections: 89, bytes: 340_000_000 },
  { port: 993, protocol: "TCP", service: "IMAPS", connections: 67, bytes: 120_000_000 },
  { port: 8080, protocol: "TCP", service: "HTTP-ALT", connections: 54, bytes: 95_000_000 },
  { port: 3306, protocol: "TCP", service: "MySQL", connections: 42, bytes: 280_000_000 },
  { port: 5432, protocol: "TCP", service: "PostgreSQL", connections: 38, bytes: 250_000_000 },
  { port: 6379, protocol: "TCP", service: "Redis", connections: 31, bytes: 45_000_000 },
  { port: 123, protocol: "UDP", service: "NTP", connections: 24, bytes: 1_200_000 },
];

const protocolBreakdown = [
  { label: "TCP", value: 73.2, color: "#3b82f6", count: 2690 },
  { label: "UDP", value: 18.4, color: "#22d3ee", count: 676 },
  { label: "ICMP", value: 5.8, color: "#a78bfa", count: 213 },
  { label: "GRE", value: 1.6, color: "#f59e0b", count: 59 },
  { label: "Other", value: 1.0, color: "#6b7280", count: 37 },
];

export default function TrafficPage() {
  const [timeRange, setTimeRange] = useState<TimeRange>("1h");

  const config = timeRangeConfig[timeRange];

  const bandwidthIn = useMemo(() => generateTimeSeries(config.points, 156_000_000, 80_000_000), [config.points]);
  const bandwidthOut = useMemo(() => generateTimeSeries(config.points, 89_000_000, 50_000_000), [config.points]);
  const packetsPerSec = useMemo(() => generateTimeSeries(config.points, 5200, 2000), [config.points]);
  const cumulativeBytes = useMemo(() => {
    let acc = 0;
    return Array.from({ length: config.points }, () => {
      acc += 50_000_000 + Math.random() * 30_000_000;
      return { value: acc };
    });
  }, [config.points]);

  const avgBwIn = bandwidthIn.reduce((a, b) => a + b.value, 0) / bandwidthIn.length;
  const avgBwOut = bandwidthOut.reduce((a, b) => a + b.value, 0) / bandwidthOut.length;
  const peakPps = Math.max(...packetsPerSec.map((d) => d.value));
  const totalBytes = cumulativeBytes[cumulativeBytes.length - 1]?.value || 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Traffic Analytics</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Network traffic monitoring, protocol analysis, and bandwidth utilization
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card title="Avg Bandwidth In" value={formatRate(avgBwIn)} color="cyan" subtitle="current average" />
        <Card title="Avg Bandwidth Out" value={formatRate(avgBwOut)} color="blue" subtitle="current average" />
        <Card title="Peak Packets/sec" value={formatNumber(peakPps)} color="yellow" subtitle="in selected range" />
        <Card title="Total Transferred" value={formatBytes(totalBytes)} color="green" subtitle="in selected range" />
      </div>

      {/* Time Range Selector */}
      <div className="flex items-center gap-1 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-1 w-fit">
        {(Object.keys(timeRangeConfig) as TimeRange[]).map((range) => (
          <button
            key={range}
            onClick={() => setTimeRange(range)}
            className={`px-4 py-1.5 text-xs font-medium rounded-md transition-colors ${
              timeRange === range
                ? "bg-[var(--accent)] text-white"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)]"
            }`}
          >
            {timeRangeConfig[range].label}
          </button>
        ))}
        <span className="text-[10px] text-[var(--text-muted)] ml-2 mr-1">interval: {config.interval}</span>
      </div>

      {/* Bandwidth Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Bandwidth In/Out</h3>
            <div className="flex items-center gap-3 text-xs text-[var(--text-secondary)]">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyan-400"></span>Inbound</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-400"></span>Outbound</span>
            </div>
          </div>
          <Sparkline data={bandwidthIn} color="#22d3ee" secondaryData={bandwidthOut} secondaryColor="#3b82f6" height={100} id="bw" />
          <div className="flex justify-between text-xs text-[var(--text-muted)] mt-2">
            <span>avg in: {formatRate(avgBwIn)}</span>
            <span>avg out: {formatRate(avgBwOut)}</span>
          </div>
        </div>

        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Packets/sec</h3>
            <span className="text-xs text-[var(--text-muted)]">Last {config.label}</span>
          </div>
          <Sparkline data={packetsPerSec} color="#a78bfa" height={100} id="pps" />
          <div className="flex justify-between text-xs text-[var(--text-muted)] mt-2">
            <span>avg: {formatNumber(packetsPerSec.reduce((a, b) => a + b.value, 0) / packetsPerSec.length)} pps</span>
            <span>peak: {formatNumber(peakPps)} pps</span>
          </div>
        </div>
      </div>

      {/* Cumulative Bytes + Protocol Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Bytes Transferred (cumulative)</h3>
            <span className="text-xs text-[var(--text-muted)]">{formatBytes(totalBytes)} total</span>
          </div>
          <Sparkline data={cumulativeBytes} color="#22c55e" height={80} id="bytes" />
        </div>

        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium">Protocol Breakdown</h3>
            <span className="text-xs text-[var(--text-muted)]">{protocolBreakdown.reduce((a, b) => a + b.count, 0).toLocaleString()} total</span>
          </div>
          <div className="space-y-3 mt-2">
            {protocolBreakdown.map((proto) => (
              <div key={proto.label} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-[var(--text-secondary)] font-medium">{proto.label}</span>
                  <span className="text-[var(--text-muted)]">{proto.value}% ({proto.count.toLocaleString()})</span>
                </div>
                <div className="w-full bg-[var(--bg-primary)] rounded-full h-2 overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{ width: `${proto.value}%`, backgroundColor: proto.color }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tables Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top 10 Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top 10 Talkers</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">#</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">IP Address</th>
                  <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Bytes</th>
                  <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Packets</th>
                  <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Conns</th>
                </tr>
              </thead>
              <tbody>
                {demoTalkers.map((talker, i) => (
                  <tr key={talker.ip} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                    <td className="py-2 px-3 text-xs text-[var(--text-muted)]">{i + 1}</td>
                    <td className="py-2 px-3 font-mono text-xs">{talker.ip}</td>
                    <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{formatBytes(talker.bytes)}</td>
                    <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{formatNumber(talker.packets)}</td>
                    <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{talker.connections.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Top 10 Destination Ports */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">Top 10 Destination Ports</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Port</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Proto</th>
                  <th className="text-left py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Service</th>
                  <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Conns</th>
                  <th className="text-right py-2.5 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Bytes</th>
                </tr>
              </thead>
              <tbody>
                {demoPorts.map((port) => (
                  <tr key={port.port} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                    <td className="py-2 px-3 font-mono text-xs text-cyan-400">{port.port}</td>
                    <td className="py-2 px-3 text-xs text-[var(--text-secondary)]">{port.protocol}</td>
                    <td className="py-2 px-3 text-xs">{port.service}</td>
                    <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{port.connections.toLocaleString()}</td>
                    <td className="py-2 px-3 text-xs text-right text-[var(--text-secondary)]">{formatBytes(port.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
