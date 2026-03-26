"use client";

import { useState } from "react";
import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

type ThreatType = "port_scan" | "ddos" | "brute_force" | "c2_beacon" | "dns_tunnel";

interface Threat {
  id: string;
  time: string;
  type: ThreatType;
  sourceIp: string;
  score: number;
  action: string;
  description: string;
}

function severityColor(score: number): string {
  if (score > 0.9) return "#ef4444";
  if (score > 0.7) return "#f97316";
  if (score > 0.4) return "#eab308";
  return "#6b7280";
}

function severityLabel(score: number): string {
  if (score > 0.9) return "critical";
  if (score > 0.7) return "high";
  if (score > 0.4) return "medium";
  return "low";
}

const threatTypeLabels: Record<ThreatType, string> = {
  port_scan: "Port Scan",
  ddos: "DDoS",
  brute_force: "Brute Force",
  c2_beacon: "C2 Beacon",
  dns_tunnel: "DNS Tunnel",
};

const threatTypeColors: Record<ThreatType, string> = {
  port_scan: "text-blue-400",
  ddos: "text-red-400",
  brute_force: "text-orange-400",
  c2_beacon: "text-purple-400",
  dns_tunnel: "text-cyan-400",
};

// Generate timeline data for sparkline
function generateThreatTimeline(points: number): { value: number }[] {
  return Array.from({ length: points }, () => ({
    value: Math.floor(Math.random() * 8),
  }));
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
        <linearGradient id={`grad-threat-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <polygon points={areaPoints} fill={`url(#grad-threat-${color.replace("#", "")})`} />
      <polyline points={points} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// Demo data
const demoThreats: Threat[] = [
  { id: "t-001", time: "14:32:08", type: "ddos", sourceIp: "203.0.113.42", score: 0.96, action: "blocked", description: "SYN flood detected, 45k pps from single source" },
  { id: "t-002", time: "14:28:15", type: "port_scan", sourceIp: "198.51.100.17", score: 0.82, action: "blocked", description: "Sequential port scan on ports 1-1024, 380 ports hit in 12s" },
  { id: "t-003", time: "14:21:44", type: "brute_force", sourceIp: "192.0.2.88", score: 0.91, action: "blocked", description: "SSH brute force, 142 failed attempts in 60 seconds" },
  { id: "t-004", time: "14:15:22", type: "c2_beacon", sourceIp: "10.0.0.45", score: 0.95, action: "blocked", description: "Periodic HTTPS beacon to known C2 domain (every 30s interval)" },
  { id: "t-005", time: "14:09:11", type: "dns_tunnel", sourceIp: "10.0.0.22", score: 0.73, action: "flagged", description: "High-entropy TXT queries to suspicious subdomain pattern" },
  { id: "t-006", time: "13:58:33", type: "port_scan", sourceIp: "203.0.113.100", score: 0.65, action: "flagged", description: "Slow scan on common service ports, 12 ports over 5 minutes" },
  { id: "t-007", time: "13:45:07", type: "brute_force", sourceIp: "198.51.100.55", score: 0.88, action: "blocked", description: "HTTP basic auth brute force against admin panel, 89 attempts" },
  { id: "t-008", time: "13:32:19", type: "ddos", sourceIp: "203.0.113.200", score: 0.78, action: "rate_limited", description: "UDP amplification attempt on port 53, 12k pps" },
  { id: "t-009", time: "13:18:45", type: "port_scan", sourceIp: "192.0.2.33", score: 0.45, action: "logged", description: "Partial scan of well-known ports from known scanner" },
  { id: "t-010", time: "13:05:02", type: "c2_beacon", sourceIp: "10.0.0.18", score: 0.92, action: "blocked", description: "DNS-based C2 communication via encoded subdomains" },
  { id: "t-011", time: "12:52:38", type: "dns_tunnel", sourceIp: "10.0.0.31", score: 0.68, action: "flagged", description: "Unusual volume of CNAME queries to single domain" },
  { id: "t-012", time: "12:41:14", type: "brute_force", sourceIp: "198.51.100.77", score: 0.35, action: "logged", description: "Low-rate credential stuffing attempts against SMTP" },
  { id: "t-013", time: "12:30:55", type: "ddos", sourceIp: "203.0.113.150", score: 0.94, action: "blocked", description: "HTTP GET flood targeting /api endpoint, 8.2k rps" },
  { id: "t-014", time: "12:18:22", type: "port_scan", sourceIp: "198.51.100.200", score: 0.52, action: "flagged", description: "XMAS scan on ports 80,443,8080,8443" },
  { id: "t-015", time: "12:05:09", type: "c2_beacon", sourceIp: "10.0.0.52", score: 0.87, action: "blocked", description: "Cobalt Strike beacon pattern detected over HTTPS" },
];

const timelineData = generateThreatTimeline(48);

export default function ThreatsPage() {
  const [filter, setFilter] = useState<ThreatType | "all">("all");

  const totalThreats = demoThreats.length;
  const blockedCount = demoThreats.filter((t) => t.action === "blocked").length;
  const activeBlocks = 8;
  const detectionRate = 97.3;

  const filteredThreats = filter === "all" ? demoThreats : demoThreats.filter((t) => t.type === filter);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">AI Threat Detection</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Real-time threat analysis and automated response powered by ML models
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <Card title="Total Threats" value={totalThreats} color="red" subtitle="last 24 hours" />
        <Card title="Blocked" value={blockedCount} color="green" subtitle={`${((blockedCount / totalThreats) * 100).toFixed(0)}% auto-blocked`} />
        <Card title="Active Blocks" value={activeBlocks} color="yellow" subtitle="IP addresses" />
        <Card title="Detection Rate" value={`${detectionRate}%`} color="cyan" subtitle="ML model accuracy" />
      </div>

      {/* Threat Timeline */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium">Threat Timeline</h3>
          <span className="text-xs text-[var(--text-muted)]">Last 24 hours</span>
        </div>
        <Sparkline data={timelineData} color="#ef4444" height={60} />
        <div className="flex justify-between text-xs text-[var(--text-muted)] mt-1">
          <span>24h ago</span>
          <span>total: {totalThreats} detections</span>
          <span>now</span>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="flex items-center gap-1 bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-1 w-fit">
        {(["all", "port_scan", "ddos", "brute_force", "c2_beacon", "dns_tunnel"] as const).map((type) => (
          <button
            key={type}
            onClick={() => setFilter(type)}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              filter === type
                ? "bg-[var(--accent)] text-white"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--bg-card-hover)]"
            }`}
          >
            {type === "all" ? "All" : threatTypeLabels[type]}
          </button>
        ))}
      </div>

      {/* Threats Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)]">
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Time</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Type</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Source IP</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Score</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Severity</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Action</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Description</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.map((threat) => (
                <tr key={threat.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                  <td className="py-2.5 px-3 text-[var(--text-secondary)] font-mono text-xs">{threat.time}</td>
                  <td className="py-2.5 px-3">
                    <span className={`font-medium text-xs ${threatTypeColors[threat.type]}`}>
                      {threatTypeLabels[threat.type]}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-mono text-xs">{threat.sourceIp}</td>
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-2">
                      <div className="w-12 bg-[var(--bg-primary)] rounded-full h-1.5 overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${threat.score * 100}%`,
                            backgroundColor: severityColor(threat.score),
                          }}
                        />
                      </div>
                      <span className="font-mono text-xs" style={{ color: severityColor(threat.score) }}>
                        {threat.score.toFixed(2)}
                      </span>
                    </div>
                  </td>
                  <td className="py-2.5 px-3">
                    <span
                      className="text-[10px] px-1.5 py-0.5 rounded border font-medium uppercase tracking-wider"
                      style={{
                        color: severityColor(threat.score),
                        borderColor: `${severityColor(threat.score)}40`,
                        backgroundColor: `${severityColor(threat.score)}15`,
                      }}
                    >
                      {severityLabel(threat.score)}
                    </span>
                  </td>
                  <td className="py-2.5 px-3">
                    <StatusBadge status={threat.action === "blocked" ? "block" : threat.action === "rate_limited" ? "degraded" : threat.action === "flagged" ? "backup" : "unknown"} />
                  </td>
                  <td className="py-2.5 px-3 text-xs text-[var(--text-secondary)] max-w-xs truncate">{threat.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
