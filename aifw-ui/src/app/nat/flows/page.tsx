"use client";

import { useEffect, useState, useMemo, useRef } from "react";
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

/** Animated dual-direction pipe: top=inbound(green), bottom=outbound(blue) */
function FlowPipe({ rateIn, rateOut, vertical = false }: { rateIn: number; rateOut: number; vertical?: boolean }) {
  const maxRate = 1e9; // 1Gbps = full pipe
  const total = rateIn + rateOut;
  // Pipe thickness: 4px minimum, scales logarithmically up to 28px
  const thickness = Math.max(4, Math.min(28, total > 0 ? 4 + Math.log10(Math.max(total, 1)) * 3 : 4));
  const inFrac = total > 0 ? rateIn / total : 0.5;
  const outFrac = 1 - inFrac;
  const inH = Math.max(1, thickness * inFrac);
  const outH = Math.max(1, thickness * outFrac);

  const cls = vertical ? "h-full flex flex-col items-center" : "w-full flex flex-col justify-center";
  const pipeCls = vertical ? "w-full" : "";

  return (
    <div className={cls}>
      {/* Inbound (green) — top/left */}
      <div
        className={`relative overflow-hidden rounded-t-sm ${pipeCls}`}
        style={vertical ? { height: "50%", width: `${thickness}px` } : { height: `${inH}px`, width: "100%" }}
      >
        <div className="absolute inset-0 bg-emerald-900/40" />
        {rateIn > 0 && (
          <div
            className="absolute inset-0"
            style={{
              background: `repeating-linear-gradient(${vertical ? "180deg" : "90deg"}, transparent, transparent 8px, rgba(34,197,94,0.5) 8px, rgba(34,197,94,0.5) 16px)`,
              animation: `flowRight 0.8s linear infinite`,
            }}
          />
        )}
      </div>
      {/* Outbound (blue) — bottom/right */}
      <div
        className={`relative overflow-hidden rounded-b-sm ${pipeCls}`}
        style={vertical ? { height: "50%", width: `${thickness}px` } : { height: `${outH}px`, width: "100%" }}
      >
        <div className="absolute inset-0 bg-blue-900/40" />
        {rateOut > 0 && (
          <div
            className="absolute inset-0"
            style={{
              background: `repeating-linear-gradient(${vertical ? "0deg" : "270deg"}, transparent, transparent 8px, rgba(59,130,246,0.5) 8px, rgba(59,130,246,0.5) 16px)`,
              animation: `flowLeft 0.8s linear infinite`,
            }}
          />
        )}
      </div>
      {/* Rate labels */}
      {!vertical && (
        <div className="flex justify-between mt-0.5 text-[9px] px-1">
          <span className="text-emerald-400">{formatBps(rateIn)}</span>
          <span className="text-blue-400">{formatBps(rateOut)}</span>
        </div>
      )}
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

  // Calculate per-interface rates
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

  // Group connections by LAN host
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
      {/* CSS animations for flowing pipes */}
      <style jsx global>{`
        @keyframes flowRight { from { background-position-x: 0; } to { background-position-x: 16px; } }
        @keyframes flowLeft { from { background-position-x: 0; } to { background-position-x: -16px; } }
      `}</style>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">NAT Traffic Flows</h1>
          <p className="text-sm text-[var(--text-muted)]">Live network topology with animated traffic visualization</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-[10px]">
            <span className="flex items-center gap-1"><span className="w-3 h-2 bg-emerald-500/50 rounded-sm inline-block" /> Inbound</span>
            <span className="flex items-center gap-1"><span className="w-3 h-2 bg-blue-500/50 rounded-sm inline-block" /> Outbound</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
          </div>
        </div>
      </div>

      {/* Topology */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 overflow-x-auto">
        <div className="min-w-[700px] flex items-stretch gap-0">
          {/* Internet Node */}
          <div className="flex-shrink-0 w-28 flex flex-col items-center justify-center">
            <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-600 to-blue-800 flex items-center justify-center shadow-lg shadow-blue-500/20 border-2 border-blue-500/30">
              <svg className="w-7 h-7 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
              </svg>
            </div>
            <p className="text-xs font-medium text-white mt-2">Internet</p>
          </div>

          {/* WAN Pipe */}
          <div className="flex-1 min-w-[80px] flex flex-col justify-center px-1">
            <FlowPipe rateIn={wanRate.in} rateOut={wanRate.out} />
          </div>

          {/* WAN Interface */}
          <div className="flex-shrink-0 w-20 flex flex-col items-center justify-center">
            <div className="w-14 h-14 rounded-lg bg-blue-500/15 border border-blue-500/40 flex flex-col items-center justify-center">
              <span className="text-[10px] font-bold text-blue-400">{wanIface?.name || "?"}</span>
              <span className="text-[8px] text-blue-300/60">WAN</span>
            </div>
          </div>

          {/* WAN→FW Pipe (short) */}
          <div className="flex-shrink-0 w-8 flex flex-col justify-center">
            <FlowPipe rateIn={wanRate.in} rateOut={wanRate.out} />
          </div>

          {/* Firewall Node */}
          <div className="flex-shrink-0 w-24 flex flex-col items-center justify-center">
            <div className="w-16 h-16 rounded-xl bg-gradient-to-br from-amber-500/20 to-red-500/20 border-2 border-amber-500/30 flex items-center justify-center">
              <svg className="w-7 h-7 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <p className="text-xs font-bold text-amber-400 mt-1">AiFw</p>
            <p className="text-[10px] text-gray-500">{connections.length} states</p>
          </div>

          {/* FW → LAN fan-out */}
          <div className="flex-1 min-w-[120px] flex flex-col justify-center gap-1 px-1">
            {lanIfaces.length === 0 ? (
              <div className="text-center text-gray-600 text-[10px]">No LAN</div>
            ) : (
              lanIfaces.map(iface => {
                const r = rates[iface.name] || { in: 0, out: 0 };
                return (
                  <div key={iface.name} className="flex items-center gap-1">
                    <div className="flex-1">
                      <FlowPipe rateIn={r.in} rateOut={r.out} />
                    </div>
                    <div className="flex-shrink-0 w-16">
                      <div className="w-12 h-10 rounded-lg bg-emerald-500/15 border border-emerald-500/40 flex flex-col items-center justify-center mx-auto">
                        <span className="text-[9px] font-bold text-emerald-400">{iface.name}</span>
                        <span className="text-[7px] text-emerald-300/60">{iface.role || "LAN"}</span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Hosts column */}
          <div className="flex-shrink-0 w-20 flex flex-col items-center justify-center gap-1">
            {lanHosts.slice(0, Math.min(lanIfaces.length * 3, 6)).map(h => (
              <button key={h.ip} onClick={() => setSelectedHost(selectedHost === h.ip ? null : h.ip)}
                className={`w-full px-1 py-0.5 rounded text-[8px] font-mono transition-colors ${selectedHost === h.ip ? "bg-cyan-500/20 text-cyan-400" : "text-gray-500 hover:text-gray-300"}`}>
                {h.ip.split('.').slice(-2).join('.')}
              </button>
            ))}
            {lanHosts.length > 6 && <span className="text-[8px] text-gray-600">+{lanHosts.length - 6} more</span>}
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
                      <span className="text-emerald-400">In: {formatBytes(c.bytes_in)}</span> · <span className="text-blue-400">Out: {formatBytes(c.bytes_out)}</span>
                    </div>
                  )}
                </div>
              ))}
              {selectedConns.length === 0 && <div className="text-center py-8 text-gray-500 text-sm">No connections</div>}
            </div>
          ) : (
            <div className="text-center py-12 text-gray-500 text-sm">Click a host to view its connections</div>
          )}
        </div>
      </div>
    </div>
  );
}
