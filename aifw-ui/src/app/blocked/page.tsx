"use client";

import { useState, useMemo } from "react";
import { useWs } from "@/context/WsContext";

interface BlockedEntry {
  timestamp: string;
  action: string;
  direction: string;
  interface: string;
  protocol: string;
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
}

const TIME_PERIODS = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "12h", hours: 12 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "All", hours: 0 },
];

function parseTimestamp(ts: string): number {
  // Format: "2026-04-01T13:09:28.475326"
  const d = new Date(ts);
  return isNaN(d.getTime()) ? 0 : d.getTime();
}

function formatTime(ts: string): string {
  const d = new Date(ts);
  if (isNaN(d.getTime())) return ts;
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  if (sameDay) return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

export default function BlockedTrafficPage() {
  const ws = useWs();
  const allEntries = (ws.blocked as unknown) as BlockedEntry[];
  const loading = !ws.connected;
  const [filterProto, setFilterProto] = useState<string>("all");
  const [filterIface, setFilterIface] = useState<string>("all");
  const [timePeriod, setTimePeriod] = useState(24);

  // Time-filtered entries
  const entries = useMemo(() => {
    if (timePeriod === 0) return allEntries;
    const cutoff = Date.now() - timePeriod * 3600_000;
    return allEntries.filter(e => parseTimestamp(e.timestamp) >= cutoff);
  }, [allEntries, timePeriod]);

  // Aggregate stats from time-filtered entries
  const stats = useMemo(() => {
    const bySource: Record<string, { count: number; lastSeen: string }> = {};
    const byPort: Record<string, number> = {};
    const byProto: Record<string, number> = {};
    const byIface: Record<string, number> = {};

    for (const e of entries) {
      if (!bySource[e.src_addr]) bySource[e.src_addr] = { count: 0, lastSeen: e.timestamp };
      bySource[e.src_addr].count++;
      if (e.dst_port > 0) byPort[`${e.dst_port}/${e.protocol}`] = (byPort[`${e.dst_port}/${e.protocol}`] || 0) + 1;
      byProto[e.protocol || "other"] = (byProto[e.protocol || "other"] || 0) + 1;
      if (e.interface) byIface[e.interface] = (byIface[e.interface] || 0) + 1;
    }

    const topSources = Object.entries(bySource)
      .map(([ip, d]) => ({ ip, count: d.count, lastSeen: d.lastSeen }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    const topPorts = Object.entries(byPort)
      .map(([port, count]) => ({ port, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    return { topSources, topPorts, byProto, byIface, total: entries.length };
  }, [entries]);

  const filtered = useMemo(() => {
    return entries.filter(e => {
      if (filterProto !== "all" && e.protocol !== filterProto) return false;
      if (filterIface !== "all" && e.interface !== filterIface) return false;
      return true;
    });
  }, [entries, filterProto, filterIface]);

  const interfaces = useMemo(() => [...new Set(entries.map(e => e.interface).filter(Boolean))], [entries]);
  const protocols = useMemo(() => {
    const seen = new Set(entries.map(e => e.protocol).filter(Boolean));
    for (const p of ["tcp", "udp", "icmp"]) seen.add(p);
    return [...seen];
  }, [entries]);

  const maxSourceCount = stats.topSources[0]?.count || 1;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Blocked Traffic</h1>
          <p className="text-sm text-gray-400">
            Non-accepted connections rejected by firewall policy &middot; {stats.total} events
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Time period selector */}
          <div className="flex items-center bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            {TIME_PERIODS.map(tp => (
              <button key={tp.label} onClick={() => setTimePeriod(tp.hours)}
                className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${timePeriod === tp.hours ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white hover:bg-gray-700"}`}>
                {tp.label}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-xs text-gray-500">{ws.connected ? "Live" : "..."}</span>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
          <div className="text-[10px] text-gray-500 uppercase">Total Blocked</div>
          <div className="text-2xl font-bold text-red-400">{stats.total}</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
          <div className="text-[10px] text-gray-500 uppercase">Unique Sources</div>
          <div className="text-2xl font-bold text-amber-400">{stats.topSources.length}</div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
          <div className="text-[10px] text-gray-500 uppercase">TCP / UDP</div>
          <div className="text-lg font-bold">
            <span className="text-blue-400">{stats.byProto["tcp"] || 0}</span>
            <span className="text-gray-600 mx-1">/</span>
            <span className="text-purple-400">{stats.byProto["udp"] || 0}</span>
          </div>
        </div>
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-3">
          <div className="text-[10px] text-gray-500 uppercase">ICMP</div>
          <div className="text-2xl font-bold text-cyan-400">{stats.byProto["icmp"] || 0}</div>
        </div>
      </div>

      {/* Top Offenders + Top Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
            <h3 className="text-sm font-medium text-red-400">Top Offenders</h3>
            <span className="text-[10px] text-gray-500">by block count</span>
          </div>
          {stats.topSources.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-sm">No blocked traffic detected</div>
          ) : (
            <div className="divide-y divide-gray-700/50">
              {stats.topSources.map((s, i) => (
                <div key={s.ip} className="px-4 py-2 hover:bg-gray-700/30">
                  <div className="flex items-center justify-between mb-1">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-gray-600 w-4">{i + 1}.</span>
                      <span className="font-mono text-xs text-white">{s.ip}</span>
                    </div>
                    <span className="text-xs text-red-400 font-medium">{s.count} blocks</span>
                  </div>
                  <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-gradient-to-r from-red-500 to-orange-500 transition-all" style={{ width: `${(s.count / maxSourceCount) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
            <h3 className="text-sm font-medium text-amber-400">Targeted Ports</h3>
            <span className="text-[10px] text-gray-500">most probed</span>
          </div>
          {stats.topPorts.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-sm">No port data</div>
          ) : (
            <div className="divide-y divide-gray-700/50">
              {stats.topPorts.map(p => {
                const [port, proto] = p.port.split('/');
                return (
                  <div key={p.port} className="px-4 py-1.5 hover:bg-gray-700/30 flex items-center gap-3">
                    <span className={`uppercase text-[10px] font-bold w-7 ${proto === "tcp" ? "text-blue-400" : proto === "udp" ? "text-purple-400" : "text-gray-400"}`}>{proto}</span>
                    <span className="font-mono text-xs text-amber-400 w-14 text-right">{port}</span>
                    <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                      <div className="h-full rounded-full bg-amber-500 transition-all" style={{ width: `${(p.count / (stats.topPorts[0]?.count || 1)) * 100}%` }} />
                    </div>
                    <span className="text-[10px] text-gray-400 w-8 text-right">{p.count}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3">
        <span className="text-xs text-gray-500">Filter:</span>
        <select value={filterProto} onChange={(e) => setFilterProto(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-white">
          <option value="all">All Protocols</option>
          {protocols.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
        </select>
        <select value={filterIface} onChange={(e) => setFilterIface(e.target.value)}
          className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-white">
          <option value="all">All Interfaces</option>
          {interfaces.map(i => <option key={i} value={i}>{i}</option>)}
        </select>
        <span className="text-[10px] text-gray-600 ml-auto">{filtered.length} entries</span>
      </div>

      {/* Event Log Table */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-gray-800">
              <tr className="border-b border-gray-700">
                <th className="text-left py-2 px-3 text-[10px] text-gray-500 uppercase">Time</th>
                <th className="text-left py-2 px-3 text-[10px] text-gray-500 uppercase">Interface</th>
                <th className="text-left py-2 px-3 text-[10px] text-gray-500 uppercase">Proto</th>
                <th className="text-left py-2 px-3 text-[10px] text-gray-500 uppercase">Source</th>
                <th className="text-left py-2 px-3 text-[10px] text-gray-500 uppercase">Destination</th>
                <th className="text-left py-2 px-3 text-[10px] text-gray-500 uppercase">Direction</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} className="text-center py-8 text-gray-500">Loading...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={6} className="text-center py-8 text-gray-500">No blocked traffic — your network is clean</td></tr>
              ) : filtered.map((e, i) => (
                <tr key={i} className="border-b border-gray-700/30 hover:bg-gray-700/20">
                  <td className="py-1.5 px-3 text-gray-500 font-mono text-[10px]">{formatTime(e.timestamp)}</td>
                  <td className="py-1.5 px-3 text-gray-400">{e.interface}</td>
                  <td className="py-1.5 px-3">
                    <span className={`uppercase font-bold ${e.protocol === "tcp" ? "text-blue-400" : e.protocol === "udp" ? "text-purple-400" : e.protocol === "icmp" ? "text-cyan-400" : "text-gray-400"}`}>{e.protocol}</span>
                  </td>
                  <td className="py-1.5 px-3 font-mono text-red-400">{e.src_addr}{e.src_port > 0 ? `:${e.src_port}` : ""}</td>
                  <td className="py-1.5 px-3 font-mono text-gray-300">{e.dst_addr}{e.dst_port > 0 ? `:${e.dst_port}` : ""}</td>
                  <td className="py-1.5 px-3 text-gray-500">{e.direction}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* AI Analysis placeholder */}
      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-3 text-xs text-gray-500 flex items-center gap-2">
        <svg className="w-4 h-4 text-purple-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
        </svg>
        AI threat analysis will be integrated here — automatic pattern detection, IP reputation scoring, and automated blocking recommendations.
      </div>
    </div>
  );
}
