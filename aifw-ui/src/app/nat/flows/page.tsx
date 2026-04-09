"use client";

import { useEffect, useState, useMemo, useRef } from "react";
import { useWs } from "@/context/WsContext";

function formatBytes(b: number): string {
  if (b >= 1e9) return `${(b/1e9).toFixed(1)} GB`; if (b >= 1e6) return `${(b/1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB`; return `${b} B`;
}
function formatBps(b: number): string {
  if (b >= 1e9) return `${(b/1e9).toFixed(1)} Gbps`; if (b >= 1e6) return `${(b/1e6).toFixed(1)} Mbps`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} Kbps`; return `${b.toFixed(0)} bps`;
}

type Conn = { src_addr: string; dst_addr: string; src_port: number; dst_port: number; protocol: string; bytes_in: number; bytes_out: number; state: string };
type Iface = { name: string; bytes_in: number; bytes_out: number; role?: string };

/** Vertical pipe: left=inbound(green), right=outbound(blue), width scales with throughput */
function VPipe({ rateIn, rateOut, height = 60 }: { rateIn: number; rateOut: number; height?: number }) {
  const total = rateIn + rateOut;
  // Width: 6px min, logarithmic scale up to 56px
  const width = Math.max(6, Math.min(56, total > 0 ? 6 + Math.log10(Math.max(total, 1)) * 6 : 6));
  const inFrac = total > 0 ? rateIn / total : 0.5;
  const inW = Math.max(2, width * inFrac);
  const outW = Math.max(2, width * (1 - inFrac));
  // Opacity: brighter when more traffic
  const intensity = Math.min(1, total > 0 ? 0.3 + Math.log10(Math.max(total, 1)) / 10 : 0.2);

  return (
    <div className="flex justify-center" style={{ height }}>
      {/* Inbound (green) — left half, flows downward */}
      <div className="relative overflow-hidden rounded-l-sm" style={{ width: `${inW}px`, height: "100%" }}>
        <div className="absolute inset-0" style={{ backgroundColor: `rgba(34,197,94,${intensity * 0.3})` }} />
        {rateIn > 0 && (
          <div className="absolute inset-0" style={{
            background: `repeating-linear-gradient(180deg, transparent, transparent 6px, rgba(34,197,94,${intensity}) 6px, rgba(34,197,94,${intensity}) 12px)`,
            animation: "flowDown 0.6s linear infinite",
          }} />
        )}
      </div>
      {/* Outbound (blue) — right half, flows upward */}
      <div className="relative overflow-hidden rounded-r-sm" style={{ width: `${outW}px`, height: "100%" }}>
        <div className="absolute inset-0" style={{ backgroundColor: `rgba(59,130,246,${intensity * 0.3})` }} />
        {rateOut > 0 && (
          <div className="absolute inset-0" style={{
            background: `repeating-linear-gradient(0deg, transparent, transparent 6px, rgba(59,130,246,${intensity}) 6px, rgba(59,130,246,${intensity}) 12px)`,
            animation: "flowUp 0.6s linear infinite",
          }} />
        )}
      </div>
    </div>
  );
}

export default function NatFlowsPage() {
  const ws = useWs();
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const prevBytes = useRef<Record<string, { in: number; out: number }>>({});
  const [rates, setRates] = useState<Record<string, { in: number; out: number }>>({});

  const ifaces = ws.interfaces as Iface[];
  const connections = ws.connections as Conn[];

  const wanIface = ifaces.find(i => i.role === "WAN") || ifaces[0];
  const lanIfaces = ifaces.filter(i => i.name !== wanIface?.name);

  useEffect(() => {
    if (!ifaces.length) return;
    const newRates: Record<string, { in: number; out: number }> = {};
    for (const iface of ifaces) {
      const prev = prevBytes.current[iface.name];
      if (prev) {
        newRates[iface.name] = {
          in: Math.max(0, (iface.bytes_in - prev.in) * 8),
          out: Math.max(0, (iface.bytes_out - prev.out) * 8),
        };
      }
    }
    prevBytes.current = Object.fromEntries(ifaces.map(i => [i.name, { in: i.bytes_in, out: i.bytes_out }]));
    if (Object.keys(newRates).length > 0) setRates(newRates);
  }, [ws.status, ifaces]);

  const lanHosts = useMemo(() => {
    const hosts: Record<string, { ip: string; bytes: number; conns: number; protocols: Set<string> }> = {};
    for (const c of connections) {
      const ip = c.src_addr;
      if (!hosts[ip]) hosts[ip] = { ip, bytes: 0, conns: 0, protocols: new Set() };
      hosts[ip].bytes += (c.bytes_in || 0) + (c.bytes_out || 0);
      hosts[ip].conns++;
      hosts[ip].protocols.add(c.protocol);
    }
    return Object.values(hosts).sort((a, b) => b.bytes - a.bytes).slice(0, 20);
  }, [connections]);

  const maxHostBytes = lanHosts[0]?.bytes || 1;
  const selectedConns = selectedHost ? connections.filter(c => c.src_addr === selectedHost || c.dst_addr === selectedHost) : [];
  const wanRate = rates[wanIface?.name || ""] || { in: 0, out: 0 };

  return (
    <div className="space-y-4">
      <style jsx global>{`
        @keyframes flowDown { from { background-position-y: 0; } to { background-position-y: 12px; } }
        @keyframes flowUp { from { background-position-y: 0; } to { background-position-y: -12px; } }
      `}</style>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">NAT Traffic Flows</h1>
          <p className="text-sm text-[var(--text-muted)]">Live vertical topology — traffic flows top to bottom</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-3 text-[10px]">
            <span className="flex items-center gap-1"><span className="w-2 h-3 bg-emerald-500/50 rounded-sm inline-block" /> In</span>
            <span className="flex items-center gap-1"><span className="w-2 h-3 bg-blue-500/50 rounded-sm inline-block" /> Out</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
          </div>
        </div>
      </div>

      {/* ═══ Vertical Topology ═══ */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex flex-col items-center">

          {/* ☁ Internet */}
          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-600 to-indigo-800 flex items-center justify-center shadow-xl shadow-blue-500/20 border-2 border-blue-400/30">
            <svg className="w-9 h-9 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
            </svg>
          </div>
          <p className="text-xs font-medium text-white mt-1.5">Internet</p>

          {/* WAN pipe */}
          <div className="my-1 flex flex-col items-center">
            <VPipe rateIn={wanRate.in} rateOut={wanRate.out} height={50} />
            <div className="flex gap-3 mt-0.5 text-[9px]">
              <span className="text-emerald-400">{formatBps(wanRate.in)}</span>
              <span className="text-blue-400">{formatBps(wanRate.out)}</span>
            </div>
          </div>

          {/* WAN interface badge */}
          <div className="px-4 py-1.5 rounded-lg bg-blue-500/15 border border-blue-500/30 text-center">
            <span className="text-xs font-bold text-blue-400">{wanIface?.name || "?"}</span>
            <span className="text-[10px] text-blue-300/60 ml-1.5">WAN</span>
          </div>

          {/* Short pipe to firewall */}
          <div className="my-0.5">
            <VPipe rateIn={wanRate.in} rateOut={wanRate.out} height={20} />
          </div>

          {/* 🛡 Firewall */}
          <div className="w-24 h-24 rounded-2xl bg-gradient-to-br from-amber-500/20 to-red-500/15 border-2 border-amber-500/30 flex flex-col items-center justify-center shadow-lg shadow-amber-500/10">
            <svg className="w-8 h-8 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="text-[10px] font-bold text-amber-400 mt-0.5">AiFw</p>
          </div>
          <p className="text-[10px] text-gray-500 mt-1">{connections.length} active states</p>

          {/* Fan-out pipes to LAN interfaces */}
          <div className="mt-2 w-full">
            {lanIfaces.length === 0 ? (
              <div className="text-center text-gray-600 text-xs py-4">No LAN interfaces detected</div>
            ) : (
              <div className={`grid gap-4 ${lanIfaces.length === 1 ? "grid-cols-1 max-w-xs mx-auto" : lanIfaces.length <= 3 ? `grid-cols-${lanIfaces.length}` : "grid-cols-2 md:grid-cols-3 lg:grid-cols-4"}`}
                style={{ gridTemplateColumns: `repeat(${Math.min(lanIfaces.length, 5)}, minmax(0, 1fr))` }}>
                {lanIfaces.map(iface => {
                  const r = rates[iface.name] || { in: 0, out: 0 };
                  // Find hosts connected via this interface (simplified: show proportional hosts)
                  const ifaceHostCount = Math.max(1, Math.ceil(lanHosts.length / lanIfaces.length));
                  return (
                    <div key={iface.name} className="flex flex-col items-center">
                      {/* Pipe from FW to LAN — swap in/out:
                          interface "out" = data going down to LAN clients (green/inbound from their perspective)
                          interface "in"  = data going up from LAN clients (blue/outbound from their perspective) */}
                      <VPipe rateIn={r.out} rateOut={r.in} height={40} />
                      <div className="flex gap-2 mt-0.5 text-[9px]">
                        <span className="text-emerald-400">{formatBps(r.out)}</span>
                        <span className="text-blue-400">{formatBps(r.in)}</span>
                      </div>

                      {/* Interface badge */}
                      <div className="mt-1 px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-center">
                        <span className="text-xs font-bold text-emerald-400">{iface.name}</span>
                        <span className="text-[10px] text-emerald-300/60 ml-1">{iface.role || "LAN"}</span>
                      </div>

                      {/* Pipe to hosts */}
                      <div className="mt-0.5">
                        <VPipe rateIn={r.out} rateOut={r.in} height={30} />
                      </div>

                      {/* Host bubbles */}
                      <div className="mt-1 flex flex-wrap justify-center gap-1 max-w-[160px]">
                        {lanHosts.slice(0, 4).map(h => (
                          <button key={h.ip} onClick={() => setSelectedHost(selectedHost === h.ip ? null : h.ip)}
                            className={`px-1.5 py-0.5 rounded-full text-[8px] font-mono transition-colors border ${
                              selectedHost === h.ip
                                ? "bg-cyan-500/20 border-cyan-500/40 text-cyan-400"
                                : "bg-gray-700/50 border-gray-600/50 text-gray-400 hover:text-white hover:border-gray-500"
                            }`}>
                            {h.ip.split('.').slice(-2).join('.')}
                          </button>
                        ))}
                        {lanHosts.length > 4 && <span className="text-[8px] text-gray-600 px-1">+{lanHosts.length - 4}</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Host Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
            <h3 className="text-sm font-medium">Active Hosts</h3>
            <span className="text-[10px] text-gray-500">{lanHosts.length} hosts</span>
          </div>
          <div className="max-h-80 overflow-y-auto divide-y divide-gray-700/50">
            {lanHosts.map(host => (
              <button key={host.ip} onClick={() => setSelectedHost(selectedHost === host.ip ? null : host.ip)}
                className={`w-full px-4 py-2 text-left hover:bg-gray-700/30 transition-colors ${selectedHost === host.ip ? "bg-blue-500/10 border-l-2 border-blue-500" : ""}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-xs text-white">{host.ip}</span>
                  <span className="text-[10px] text-gray-400">{host.conns} conn · {formatBytes(host.bytes)}</span>
                </div>
                <div className="w-full h-1 bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all" style={{ width: `${(host.bytes / maxHostBytes) * 100}%` }} />
                </div>
              </button>
            ))}
            {lanHosts.length === 0 && <div className="text-center py-6 text-gray-500 text-sm">No active hosts</div>}
          </div>
        </div>

        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-700">
            <h3 className="text-sm font-medium">{selectedHost ? `Connections — ${selectedHost}` : "Select a host"}</h3>
          </div>
          {selectedHost ? (
            <div className="max-h-80 overflow-y-auto divide-y divide-gray-700/50">
              {selectedConns.map((c, i) => (
                <div key={i} className="px-4 py-2 text-xs">
                  <div className="flex items-center gap-2">
                    <span className={`uppercase text-[10px] font-bold ${c.protocol === "tcp" ? "text-blue-400" : "text-purple-400"}`}>{c.protocol}</span>
                    <span className="font-mono text-gray-300">{c.src_addr}:{c.src_port}</span>
                    <svg className="w-3 h-3 text-gray-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                    <span className="font-mono text-gray-300">{c.dst_addr}:{c.dst_port}</span>
                    <span className="ml-auto text-gray-500">{c.state}</span>
                  </div>
                  {(c.bytes_in > 0 || c.bytes_out > 0) && (
                    <div className="text-[10px] text-gray-500 mt-0.5">
                      <span className="text-emerald-400">In: {formatBytes(c.bytes_in)}</span> · <span className="text-blue-400">Out: {formatBytes(c.bytes_out)}</span>
                    </div>
                  )}
                </div>
              ))}
              {selectedConns.length === 0 && <div className="text-center py-6 text-gray-500 text-sm">No connections</div>}
            </div>
          ) : (
            <div className="text-center py-10 text-gray-500 text-sm">Click a host in the topology or list to view connections</div>
          )}
        </div>
      </div>
    </div>
  );
}
