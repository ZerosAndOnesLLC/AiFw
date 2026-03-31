"use client";

import { useState } from "react";
import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";
import { useWs } from "@/context/WsContext";

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

type SortKey = "protocol" | "src_addr" | "dst_addr" | "state" | "age_secs" | "packets" | "bytes";
type SortDir = "asc" | "desc";

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

async function apiFetch<T>(path: string): Promise<T> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  const res = await fetch(path, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

function SortHeader({
  label,
  sortKey,
  currentSort,
  currentDir,
  onSort,
  className,
}: {
  label: string;
  sortKey: SortKey;
  currentSort: SortKey;
  currentDir: SortDir;
  onSort: (key: SortKey) => void;
  className?: string;
}) {
  const active = currentSort === sortKey;
  return (
    <th
      className={`py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider cursor-pointer hover:text-[var(--text-secondary)] select-none ${className || "text-left"}`}
      onClick={() => onSort(sortKey)}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active && (
          <span className="text-[var(--text-secondary)]">{currentDir === "asc" ? "\u25B2" : "\u25BC"}</span>
        )}
      </span>
    </th>
  );
}

export default function ConnectionsPage() {
  const ws = useWs();
  const connections = (ws.connections as unknown) as Connection[];
  const loading = !ws.connected && connections.length === 0;
  const error: string | null = null;
  const [sortKey, setSortKey] = useState<SortKey>("bytes");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  const sortedConnections = [...connections].sort((a, b) => {
    const mul = sortDir === "asc" ? 1 : -1;
    switch (sortKey) {
      case "protocol":
        return mul * a.protocol.localeCompare(b.protocol);
      case "src_addr":
        return mul * a.src_addr.localeCompare(b.src_addr);
      case "dst_addr":
        return mul * a.dst_addr.localeCompare(b.dst_addr);
      case "state":
        return mul * a.state.localeCompare(b.state);
      case "age_secs":
        return mul * (a.age_secs - b.age_secs);
      case "packets":
        return mul * ((a.packets_in + a.packets_out) - (b.packets_in + b.packets_out));
      case "bytes":
        return mul * ((a.bytes_in + a.bytes_out) - (b.bytes_in + b.bytes_out));
      default:
        return 0;
    }
  });

  // Protocol breakdown
  const protocolCounts = connections.reduce<Record<string, number>>((acc, c) => {
    acc[c.protocol] = (acc[c.protocol] || 0) + 1;
    return acc;
  }, {});

  const totalBytesIn = connections.reduce((sum, c) => sum + c.bytes_in, 0);
  const totalBytesOut = connections.reduce((sum, c) => sum + c.bytes_out, 0);
  const totalPacketsIn = connections.reduce((sum, c) => sum + c.packets_in, 0);
  const totalPacketsOut = connections.reduce((sum, c) => sum + c.packets_out, 0);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[var(--text-muted)]">Loading connections...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Live Connections</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {connections.length} active connections
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500"></span>
            </span>
            <span className="text-xs text-green-400 font-medium">Live</span>
          </div>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <Card title="Total" value={connections.length} color="blue" subtitle="connections" />
        <Card title="TCP" value={protocolCounts["tcp"] || 0} color="blue" subtitle={connections.length ? `${Math.round(((protocolCounts["tcp"] || 0) / connections.length) * 100)}%` : "0%"} />
        <Card title="UDP" value={protocolCounts["udp"] || 0} color="cyan" subtitle={connections.length ? `${Math.round(((protocolCounts["udp"] || 0) / connections.length) * 100)}%` : "0%"} />
        <Card title="ICMP" value={protocolCounts["icmp"] || 0} color="yellow" subtitle={connections.length ? `${Math.round(((protocolCounts["icmp"] || 0) / connections.length) * 100)}%` : "0%"} />
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
        {sortedConnections.length === 0 ? (
          <div className="text-center py-12 text-[var(--text-muted)]">No active connections</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <SortHeader label="Proto" sortKey="protocol" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} className="w-16 text-left" />
                  <SortHeader label="Source" sortKey="src_addr" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} />
                  <SortHeader label="Destination" sortKey="dst_addr" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} />
                  <SortHeader label="State" sortKey="state" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} className="w-28 text-left" />
                  <SortHeader label="Age" sortKey="age_secs" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} className="w-20 text-left" />
                  <SortHeader label="Pkts In/Out" sortKey="packets" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} className="w-28 text-left" />
                  <SortHeader label="Bytes In/Out" sortKey="bytes" currentSort={sortKey} currentDir={sortDir} onSort={handleSort} className="w-32 text-left" />
                </tr>
              </thead>
              <tbody>
                {sortedConnections.map((conn) => {
                  const colors: Record<string, string> = {
                    tcp: "text-blue-400",
                    udp: "text-purple-400",
                    icmp: "text-cyan-400",
                  };
                  return (
                    <tr key={conn.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                      <td className="py-2.5 px-3 w-16">
                        <span className={`font-mono text-xs font-medium uppercase ${colors[conn.protocol] || "text-[var(--text-secondary)]"}`}>
                          {conn.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs">
                          {conn.src_addr}<span className="text-[var(--text-muted)]">:{conn.src_port}</span>
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-xs">
                          {conn.dst_addr}<span className="text-[var(--text-muted)]">:{conn.dst_port}</span>
                        </span>
                      </td>
                      <td className="py-2.5 px-3 w-28">
                        <StatusBadge status={conn.state} size="sm" />
                      </td>
                      <td className="py-2.5 px-3 w-20">
                        <span className="text-xs text-[var(--text-secondary)] font-mono">{formatDuration(conn.age_secs)}</span>
                      </td>
                      <td className="py-2.5 px-3 w-28">
                        <span className="text-xs font-mono">
                          <span className="text-green-400">{formatNumber(conn.packets_in)}</span>
                          <span className="text-[var(--text-muted)]"> / </span>
                          <span className="text-blue-400">{formatNumber(conn.packets_out)}</span>
                        </span>
                      </td>
                      <td className="py-2.5 px-3 w-32">
                        <span className="text-xs font-mono">
                          <span className="text-green-400">{formatBytes(conn.bytes_in)}</span>
                          <span className="text-[var(--text-muted)]"> / </span>
                          <span className="text-blue-400">{formatBytes(conn.bytes_out)}</span>
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
