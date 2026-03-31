"use client";

import { useEffect, useState, useMemo } from "react";
import { useWs } from "@/context/WsContext";

function formatBytes(b: number): string {
  if (b >= 1e9) return `${(b/1e9).toFixed(1)} GB`; if (b >= 1e6) return `${(b/1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB`; return `${b} B`;
}
function formatBps(b: number): string {
  if (b >= 1e6) return `${(b/1e6).toFixed(1)} Mbps`; if (b >= 1e3) return `${(b/1e3).toFixed(1)} Kbps`;
  return `${b.toFixed(0)} bps`;
}

type Conn = { src_addr: string; dst_addr: string; src_port: number; dst_port: number; protocol: string; bytes_in: number; bytes_out: number; state: string };
type Iface = { name: string; bytes_in: number; bytes_out: number; role?: string };

interface HostNode {
  ip: string;
  bytes: number;
  conns: number;
  protocols: Set<string>;
}

export default function NatFlowsPage() {
  const ws = useWs();
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [prevBytes, setPrevBytes] = useState<Record<string, { in: number; out: number }>>({});
  const [rates, setRates] = useState<Record<string, { in: number; out: number }>>({});

  const ifaces = ws.interfaces as Iface[];
  const connections = ws.connections as Conn[];

  const wanIface = ifaces.find(i => i.role === "WAN") || ifaces[0];
  const lanIfaces = ifaces.filter(i => i.role !== "WAN" && i.name !== wanIface?.name);

  // Calculate per-interface rates
  useEffect(() => {
    if (!ifaces.length) return;
    const newRates: Record<string, { in: number; out: number }> = {};
    for (const iface of ifaces) {
      const prev = prevBytes[iface.name];
      if (prev) {
        newRates[iface.name] = {
          in: Math.max(0, (iface.bytes_in - prev.in) * 8),
          out: Math.max(0, (iface.bytes_out - prev.out) * 8),
        };
      }
    }
    setPrevBytes(Object.fromEntries(ifaces.map(i => [i.name, { in: i.bytes_in, out: i.bytes_out }])));
    if (Object.keys(newRates).length > 0) setRates(newRates);
  }, [ws.status]);

  // Group connections by LAN host
  const lanHosts = useMemo(() => {
    const hosts: Record<string, HostNode> = {};
    const lanNets = lanIfaces.map(i => {
      // Simple: any IP that isn't the WAN interface IP
      return i.name;
    });
    for (const c of connections) {
      // Source is typically the LAN host for outbound traffic
      const ip = c.src_addr;
      if (!hosts[ip]) hosts[ip] = { ip, bytes: 0, conns: 0, protocols: new Set() };
      hosts[ip].bytes += (c.bytes_in || 0) + (c.bytes_out || 0);
      hosts[ip].conns++;
      hosts[ip].protocols.add(c.protocol);
    }
    return Object.values(hosts).sort((a, b) => b.bytes - a.bytes).slice(0, 20);
  }, [connections, lanIfaces]);

  const maxHostBytes = lanHosts[0]?.bytes || 1;
  const selectedConns = selectedHost ? connections.filter(c => c.src_addr === selectedHost || c.dst_addr === selectedHost) : [];

  // Pipe thickness helper (1-12px based on rate)
  const pipeWidth = (bps: number) => Math.max(2, Math.min(14, Math.log2(Math.max(bps, 1)) / 3));

  const wanRate = rates[wanIface?.name || ""] || { in: 0, out: 0 };
  const totalLanRate = lanIfaces.reduce((s, i) => {
    const r = rates[i.name] || { in: 0, out: 0 };
    return { in: s.in + r.in, out: s.out + r.out };
  }, { in: 0, out: 0 });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">NAT Traffic Flows</h1>
          <p className="text-sm text-[var(--text-muted)]">Live network topology with traffic visualization</p>
        </div>
        <div className="flex items-center gap-1.5">
          <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
          <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "Disconnected"}</span>
        </div>
      </div>

      {/* Flow Topology */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-center justify-between gap-4">
          {/* Internet */}
          <div className="flex-shrink-0 w-32 text-center">
            <div className="w-16 h-16 mx-auto rounded-full bg-gradient-to-br from-blue-600 to-blue-800 flex items-center justify-center shadow-lg shadow-blue-500/20 border-2 border-blue-500/30">
              <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
              </svg>
            </div>
            <p className="text-xs font-medium text-white mt-2">Internet</p>
          </div>

          {/* WAN Pipe */}
          <div className="flex-1 relative py-4">
            <div className="relative h-8 flex items-center">
              {/* Animated pipe */}
              <div className="w-full rounded-full overflow-hidden relative" style={{ height: `${pipeWidth(wanRate.in + wanRate.out)}px`, background: 'rgba(59,130,246,0.15)' }}>
                <div className="absolute inset-0 bg-gradient-to-r from-blue-500/60 via-blue-400/30 to-blue-500/60 animate-pulse" />
              </div>
            </div>
            <div className="flex justify-between text-[10px] text-gray-500 mt-1">
              <span className="text-green-400">{formatBps(wanRate.in)} in</span>
              <span className="text-blue-400">{formatBps(wanRate.out)} out</span>
            </div>
          </div>

          {/* WAN Interface */}
          <div className="flex-shrink-0 w-24 text-center">
            <div className="w-12 h-12 mx-auto rounded-lg bg-blue-500/20 border border-blue-500/40 flex items-center justify-center">
              <span className="text-[10px] font-bold text-blue-400">{wanIface?.name || "?"}</span>
            </div>
            <p className="text-[10px] text-blue-400 mt-1">WAN</p>
          </div>

          {/* Firewall */}
          <div className="flex-shrink-0 w-28 text-center">
            <div className="w-16 h-16 mx-auto rounded-xl bg-gradient-to-br from-amber-500/20 to-red-500/20 border-2 border-amber-500/30 flex items-center justify-center">
              <svg className="w-8 h-8 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <p className="text-xs font-medium text-amber-400 mt-2">AiFw</p>
            <p className="text-[10px] text-gray-500">{connections.length} states</p>
          </div>

          {/* LAN Pipe */}
          <div className="flex-1 relative py-4">
            <div className="relative h-8 flex items-center">
              <div className="w-full rounded-full overflow-hidden relative" style={{ height: `${pipeWidth(totalLanRate.in + totalLanRate.out)}px`, background: 'rgba(34,197,94,0.15)' }}>
                <div className="absolute inset-0 bg-gradient-to-r from-green-500/60 via-green-400/30 to-green-500/60 animate-pulse" />
              </div>
            </div>
            <div className="flex justify-between text-[10px] text-gray-500 mt-1">
              <span className="text-green-400">{formatBps(totalLanRate.in)} in</span>
              <span className="text-blue-400">{formatBps(totalLanRate.out)} out</span>
            </div>
          </div>

          {/* LAN Interfaces */}
          <div className="flex-shrink-0 w-24 text-center">
            {lanIfaces.length > 0 ? lanIfaces.map(i => (
              <div key={i.name} className="mb-2">
                <div className="w-12 h-12 mx-auto rounded-lg bg-emerald-500/20 border border-emerald-500/40 flex items-center justify-center">
                  <span className="text-[10px] font-bold text-emerald-400">{i.name}</span>
                </div>
                <p className="text-[10px] text-emerald-400 mt-1">{i.role || "LAN"}</p>
              </div>
            )) : (
              <div className="w-12 h-12 mx-auto rounded-lg bg-gray-700 border border-gray-600 flex items-center justify-center">
                <span className="text-[10px] text-gray-500">?</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Active Hosts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
            <h3 className="text-sm font-medium">Active Hosts</h3>
            <span className="text-[10px] text-gray-500">{lanHosts.length} hosts</span>
          </div>
          <div className="max-h-96 overflow-y-auto divide-y divide-gray-700/50">
            {lanHosts.map(host => (
              <button key={host.ip} onClick={() => setSelectedHost(selectedHost === host.ip ? null : host.ip)}
                className={`w-full px-4 py-2.5 text-left hover:bg-gray-700/30 transition-colors ${selectedHost === host.ip ? "bg-blue-500/10 border-l-2 border-blue-500" : ""}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs text-white">{host.ip}</span>
                  <span className="text-[10px] text-gray-400">{host.conns} conn · {formatBytes(host.bytes)}</span>
                </div>
                <div className="w-full h-1 bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all" style={{ width: `${(host.bytes / maxHostBytes) * 100}%` }} />
                </div>
                <div className="flex gap-1 mt-1">
                  {[...host.protocols].map(p => (
                    <span key={p} className={`text-[9px] px-1 rounded ${p === "tcp" ? "bg-blue-500/20 text-blue-400" : p === "udp" ? "bg-purple-500/20 text-purple-400" : "bg-gray-600 text-gray-400"}`}>{p}</span>
                  ))}
                </div>
              </button>
            ))}
            {lanHosts.length === 0 && <div className="text-center py-8 text-gray-500 text-sm">No active hosts</div>}
          </div>
        </div>

        {/* Selected Host Details */}
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-700">
            <h3 className="text-sm font-medium">{selectedHost ? `Connections — ${selectedHost}` : "Host Details"}</h3>
          </div>
          {selectedHost ? (
            <div className="max-h-96 overflow-y-auto divide-y divide-gray-700/50">
              {selectedConns.map((c, i) => (
                <div key={i} className="px-4 py-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className={`uppercase text-[10px] font-bold ${c.protocol === "tcp" ? "text-blue-400" : "text-purple-400"}`}>{c.protocol}</span>
                    <span className="font-mono text-gray-300">{c.src_addr}:{c.src_port}</span>
                    <svg className="w-3 h-3 text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                    <span className="font-mono text-gray-300">{c.dst_addr}:{c.dst_port}</span>
                    <span className="ml-auto text-gray-500">{c.state}</span>
                  </div>
                  {(c.bytes_in > 0 || c.bytes_out > 0) && (
                    <div className="text-[10px] text-gray-500 mt-0.5">
                      In: {formatBytes(c.bytes_in)} · Out: {formatBytes(c.bytes_out)}
                    </div>
                  )}
                </div>
              ))}
              {selectedConns.length === 0 && <div className="text-center py-8 text-gray-500 text-sm">No connections</div>}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500 text-sm">
              Click a host to view its connections
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
