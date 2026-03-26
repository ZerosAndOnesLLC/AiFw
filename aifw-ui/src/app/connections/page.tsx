"use client";

import { useEffect, useState, useCallback } from "react";
import Card from "@/components/Card";
import DataTable from "@/components/DataTable";
import StatusBadge from "@/components/StatusBadge";

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

function generateDemoConnections(): Connection[] {
  return [
    { id: 1, protocol: "tcp", src_addr: "10.0.0.15", src_port: 52481, dst_addr: "93.184.216.34", dst_port: 443, state: "ESTABLISHED", packets_in: 1284, packets_out: 987, bytes_in: 1_843_200, bytes_out: 245_760, age_secs: 342 },
    { id: 2, protocol: "tcp", src_addr: "10.0.0.22", src_port: 48920, dst_addr: "172.217.14.206", dst_port: 443, state: "ESTABLISHED", packets_in: 3420, packets_out: 2180, bytes_in: 5_242_880, bytes_out: 524_288, age_secs: 1205 },
    { id: 3, protocol: "udp", src_addr: "10.0.0.5", src_port: 53, dst_addr: "8.8.8.8", dst_port: 53, state: "SINGLE", packets_in: 42, packets_out: 42, bytes_in: 5_376, bytes_out: 2_688, age_secs: 3 },
    { id: 4, protocol: "tcp", src_addr: "10.0.0.8", src_port: 60112, dst_addr: "151.101.1.140", dst_port: 443, state: "ESTABLISHED", packets_in: 892, packets_out: 654, bytes_in: 1_048_576, bytes_out: 131_072, age_secs: 89 },
    { id: 5, protocol: "tcp", src_addr: "192.168.1.100", src_port: 22, dst_addr: "10.0.0.5", dst_port: 22, state: "ESTABLISHED", packets_in: 15230, packets_out: 14890, bytes_in: 2_097_152, bytes_out: 1_572_864, age_secs: 7823 },
    { id: 6, protocol: "udp", src_addr: "10.0.0.15", src_port: 41022, dst_addr: "10.0.0.1", dst_port: 53, state: "SINGLE", packets_in: 1, packets_out: 1, bytes_in: 128, bytes_out: 64, age_secs: 1 },
    { id: 7, protocol: "tcp", src_addr: "10.0.0.45", src_port: 55340, dst_addr: "52.84.150.40", dst_port: 443, state: "TIME_WAIT", packets_in: 24, packets_out: 18, bytes_in: 3_072, bytes_out: 1_536, age_secs: 45 },
    { id: 8, protocol: "icmp", src_addr: "10.0.0.3", src_port: 0, dst_addr: "10.0.0.1", dst_port: 0, state: "SINGLE", packets_in: 4, packets_out: 4, bytes_in: 256, bytes_out: 256, age_secs: 2 },
    { id: 9, protocol: "tcp", src_addr: "10.0.0.22", src_port: 49210, dst_addr: "140.82.114.4", dst_port: 443, state: "ESTABLISHED", packets_in: 560, packets_out: 420, bytes_in: 786_432, bytes_out: 262_144, age_secs: 156 },
    { id: 10, protocol: "tcp", src_addr: "10.0.0.15", src_port: 53100, dst_addr: "104.16.249.249", dst_port: 80, state: "FIN_WAIT_2", packets_in: 12, packets_out: 10, bytes_in: 8_192, bytes_out: 2_048, age_secs: 28 },
    { id: 11, protocol: "udp", src_addr: "10.0.0.8", src_port: 51200, dst_addr: "1.1.1.1", dst_port: 53, state: "SINGLE", packets_in: 1, packets_out: 1, bytes_in: 96, bytes_out: 48, age_secs: 0 },
    { id: 12, protocol: "tcp", src_addr: "10.0.0.45", src_port: 38400, dst_addr: "198.51.100.22", dst_port: 3306, state: "ESTABLISHED", packets_in: 8450, packets_out: 6200, bytes_in: 10_485_760, bytes_out: 1_048_576, age_secs: 4520 },
    { id: 13, protocol: "tcp", src_addr: "10.0.0.3", src_port: 44892, dst_addr: "10.0.0.5", dst_port: 5432, state: "ESTABLISHED", packets_in: 2340, packets_out: 1890, bytes_in: 3_145_728, bytes_out: 524_288, age_secs: 2890 },
    { id: 14, protocol: "udp", src_addr: "10.0.0.22", src_port: 60100, dst_addr: "10.0.0.5", dst_port: 123, state: "SINGLE", packets_in: 1, packets_out: 1, bytes_in: 76, bytes_out: 76, age_secs: 14 },
    { id: 15, protocol: "tcp", src_addr: "10.0.0.15", src_port: 59800, dst_addr: "35.186.224.25", dst_port: 443, state: "SYN_SENT", packets_in: 0, packets_out: 1, bytes_in: 0, bytes_out: 64, age_secs: 0 },
  ];
}

function formatBytes(bytes: number): string {
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(1)} GB`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatDuration(secs: number): string {
  if (secs >= 86400) {
    const d = Math.floor(secs / 86400);
    const h = Math.floor((secs % 86400) / 3600);
    return `${d}d ${h}h`;
  }
  if (secs >= 3600) {
    const h = Math.floor(secs / 3600);
    const m = Math.floor((secs % 3600) / 60);
    return `${h}h ${m}m`;
  }
  if (secs >= 60) {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}m ${s}s`;
  }
  return `${secs}s`;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return String(n);
}

export default function ConnectionsPage() {
  const [connections, setConnections] = useState<Connection[]>(generateDemoConnections);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const refresh = useCallback(() => {
    // In production, this would call api.listConnections()
    // For demo, add slight randomization to simulate live data
    setConnections((prev) =>
      prev.map((c) => ({
        ...c,
        age_secs: c.age_secs + 5,
        packets_in: c.packets_in + Math.floor(Math.random() * 10),
        packets_out: c.packets_out + Math.floor(Math.random() * 8),
        bytes_in: c.bytes_in + Math.floor(Math.random() * 4096),
        bytes_out: c.bytes_out + Math.floor(Math.random() * 2048),
      }))
    );
    setLastRefresh(new Date());
  }, []);

  useEffect(() => {
    const interval = setInterval(refresh, 5000);
    return () => clearInterval(interval);
  }, [refresh]);

  // Protocol breakdown
  const protocolCounts = connections.reduce<Record<string, number>>((acc, c) => {
    acc[c.protocol] = (acc[c.protocol] || 0) + 1;
    return acc;
  }, {});

  const totalBytesIn = connections.reduce((sum, c) => sum + c.bytes_in, 0);
  const totalBytesOut = connections.reduce((sum, c) => sum + c.bytes_out, 0);
  const totalPacketsIn = connections.reduce((sum, c) => sum + c.packets_in, 0);
  const totalPacketsOut = connections.reduce((sum, c) => sum + c.packets_out, 0);

  const columns = [
    {
      key: "protocol",
      label: "Proto",
      className: "w-16",
      render: (row: Connection) => {
        const colors: Record<string, string> = {
          tcp: "text-blue-400",
          udp: "text-purple-400",
          icmp: "text-cyan-400",
        };
        return (
          <span className={`font-mono text-xs font-medium uppercase ${colors[row.protocol] || "text-[var(--text-secondary)]"}`}>
            {row.protocol}
          </span>
        );
      },
    },
    {
      key: "source",
      label: "Source",
      render: (row: Connection) => (
        <span className="font-mono text-xs">
          {row.src_addr}<span className="text-[var(--text-muted)]">:{row.src_port}</span>
        </span>
      ),
    },
    {
      key: "destination",
      label: "Destination",
      render: (row: Connection) => (
        <span className="font-mono text-xs">
          {row.dst_addr}<span className="text-[var(--text-muted)]">:{row.dst_port}</span>
        </span>
      ),
    },
    {
      key: "state",
      label: "State",
      className: "w-28",
      render: (row: Connection) => <StatusBadge status={row.state} size="sm" />,
    },
    {
      key: "age_secs",
      label: "Age",
      className: "w-20",
      render: (row: Connection) => (
        <span className="text-xs text-[var(--text-secondary)] font-mono">{formatDuration(row.age_secs)}</span>
      ),
    },
    {
      key: "packets",
      label: "Pkts In/Out",
      className: "w-28",
      render: (row: Connection) => (
        <span className="text-xs font-mono">
          <span className="text-green-400">{formatNumber(row.packets_in)}</span>
          <span className="text-[var(--text-muted)]"> / </span>
          <span className="text-blue-400">{formatNumber(row.packets_out)}</span>
        </span>
      ),
    },
    {
      key: "bytes",
      label: "Bytes In/Out",
      className: "w-32",
      render: (row: Connection) => (
        <span className="text-xs font-mono">
          <span className="text-green-400">{formatBytes(row.bytes_in)}</span>
          <span className="text-[var(--text-muted)]"> / </span>
          <span className="text-blue-400">{formatBytes(row.bytes_out)}</span>
        </span>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Live Connections</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {connections.length} active connections &middot; auto-refreshing every 5s
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-[var(--text-muted)]">
            Last update: {lastRefresh.toLocaleTimeString()}
          </span>
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-xs text-green-400 font-medium">Live</span>
          </div>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card title="Total" value={connections.length} color="blue" subtitle="connections" />
        <Card title="TCP" value={protocolCounts["tcp"] || 0} color="blue" subtitle={`${Math.round(((protocolCounts["tcp"] || 0) / connections.length) * 100)}%`} />
        <Card title="UDP" value={protocolCounts["udp"] || 0} color="cyan" subtitle={`${Math.round(((protocolCounts["udp"] || 0) / connections.length) * 100)}%`} />
        <Card title="ICMP" value={protocolCounts["icmp"] || 0} color="yellow" subtitle={`${Math.round(((protocolCounts["icmp"] || 0) / connections.length) * 100)}%`} />
        <Card
          title="Traffic In"
          value={formatBytes(totalBytesIn)}
          color="green"
          subtitle={`${formatNumber(totalPacketsIn)} pkts`}
        />
        <Card
          title="Traffic Out"
          value={formatBytes(totalBytesOut)}
          color="red"
          subtitle={`${formatNumber(totalPacketsOut)} pkts`}
        />
      </div>

      {/* Connections Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <DataTable<Record<string, unknown>>
          columns={columns as { key: string; label: string; render?: (row: Record<string, unknown>) => React.ReactNode; className?: string }[]}
          data={connections as unknown as Record<string, unknown>[]}
          keyField="id"
          emptyMessage="No active connections"
        />
      </div>
    </div>
  );
}
