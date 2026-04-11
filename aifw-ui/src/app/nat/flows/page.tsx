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

function isPrivateIp(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

type Conn = { src_addr: string; dst_addr: string; src_port: number; dst_port: number; protocol: string; bytes_in: number; bytes_out: number; state: string };
type Iface = { name: string; bytes_in: number; bytes_out: number; role?: string; address?: string; subnet?: string };

function getSubnet24(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4) return ip;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

/** Animated vertical pipe using SVG: green=in (down), blue=out (up), width scales with throughput */
function VPipe({ rateIn, rateOut, height = 60 }: { rateIn: number; rateOut: number; height?: number }) {
  const inW = Math.max(3, rateIn > 0 ? 3 + Math.log10(Math.max(rateIn, 1)) * 2 : 3);
  const outW = Math.max(3, rateOut > 0 ? 3 + Math.log10(Math.max(rateOut, 1)) * 2 : 3);
  const totalW = inW + outW + 8; // gap between pipes
  const inA = Math.min(0.85, rateIn > 0 ? 0.35 + Math.log10(Math.max(rateIn, 1)) / 8 : 0.1);
  const outA = Math.min(0.85, rateOut > 0 ? 0.35 + Math.log10(Math.max(rateOut, 1)) / 8 : 0.1);
  const svgW = Math.max(40, totalW + 16);
  const cx = svgW / 2;
  const gap = 3;
  return (
    <svg viewBox={`0 0 ${svgW} ${height}`} style={{ width: svgW, height }} className="block mx-auto">
      {/* Glow */}
      <line x1={cx} y1={0} x2={cx} y2={height} stroke="rgba(100,200,150,0.04)" strokeWidth={totalW + 10} strokeLinecap="round" />
      {/* Inbound (green, left) — flows down */}
      <line x1={cx - gap} y1={0} x2={cx - gap} y2={height} stroke="rgba(51,65,85,0.4)" strokeWidth={inW + 2} strokeLinecap="round" />
      <line x1={cx - gap} y1={0} x2={cx - gap} y2={height} stroke={`rgba(34,197,94,${Math.max(0.15, inA)})`}
        strokeWidth={inW} strokeDasharray="5 7" strokeLinecap="round">
        {rateIn > 0 && <animate attributeName="stroke-dashoffset" from="0" to="-12" dur="0.5s" repeatCount="indefinite" />}
      </line>
      {/* Outbound (blue, right) — flows up */}
      <line x1={cx + gap} y1={0} x2={cx + gap} y2={height} stroke="rgba(51,65,85,0.4)" strokeWidth={outW + 2} strokeLinecap="round" />
      <line x1={cx + gap} y1={0} x2={cx + gap} y2={height} stroke={`rgba(59,130,246,${Math.max(0.15, outA)})`}
        strokeWidth={outW} strokeDasharray="5 7" strokeLinecap="round">
        {rateOut > 0 && <animate attributeName="stroke-dashoffset" from="0" to="12" dur="0.5s" repeatCount="indefinite" />}
      </line>
    </svg>
  );
}

/** SVG animated pipe — green(in) + blue(out) as two parallel Bezier paths.
 *  Width scales with throughput. In flows downward, out flows upward. */
function SvgPipe({ pathIn, pathOut, rateIn, rateOut }: { pathIn: string; pathOut: string; rateIn: number; rateOut: number; id: string }) {
  const total = rateIn + rateOut;
  // Scale width with throughput — same log curve as VPipe
  const width = Math.max(4, Math.min(28, total > 0 ? 4 + Math.log10(Math.max(total, 1)) * 3 : 4));
  const inW = Math.max(3, rateIn > 0 ? 3 + Math.log10(Math.max(rateIn, 1)) * 1.5 : 3);
  const outW = Math.max(3, rateOut > 0 ? 3 + Math.log10(Math.max(rateOut, 1)) * 1.5 : 3);
  const inA = Math.min(0.85, rateIn > 0 ? 0.35 + Math.log10(Math.max(rateIn, 1)) / 8 : 0);
  const outA = Math.min(0.85, rateOut > 0 ? 0.35 + Math.log10(Math.max(rateOut, 1)) / 8 : 0);
  return (
    <g>
      {/* Soft glow */}
      <path d={pathIn} fill="none" stroke="rgba(100,200,150,0.03)" strokeWidth={width + 8} strokeLinecap="round" />
      {/* Pipe backgrounds */}
      <path d={pathIn} fill="none" stroke="rgba(51,65,85,0.4)" strokeWidth={inW + 2} strokeLinecap="round" />
      <path d={pathOut} fill="none" stroke="rgba(51,65,85,0.4)" strokeWidth={outW + 2} strokeLinecap="round" />
      {/* Inbound (green) — dashes flow downward (negative offset = toward subnets) */}
      <path d={pathIn} fill="none" stroke={`rgba(34,197,94,${Math.max(0.2, inA)})`}
        strokeWidth={inW} strokeDasharray="5 7" strokeLinecap="round">
        {rateIn > 0 && <animate attributeName="stroke-dashoffset" from="0" to="-12" dur="0.5s" repeatCount="indefinite" />}
      </path>
      {/* Outbound (blue) — dashes flow upward (positive offset = toward firewall) */}
      <path d={pathOut} fill="none" stroke={`rgba(59,130,246,${Math.max(0.2, outA)})`}
        strokeWidth={outW} strokeDasharray="5 7" strokeLinecap="round">
        {rateOut > 0 && <animate attributeName="stroke-dashoffset" from="0" to="12" dur="0.5s" repeatCount="indefinite" />}
      </path>
    </g>
  );
}

export default function NatFlowsPage() {
  const ws = useWs();
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const [groupBySubnet, setGroupBySubnet] = useState(true);
  const prevBytes = useRef<Record<string, { in: number; out: number }>>({});
  const [rates, setRates] = useState<Record<string, { in: number; out: number }>>({});
  const prevSubnetBytes = useRef<Record<string, { in: number; out: number }>>({});
  const [subnetLiveRates, setSubnetLiveRates] = useState<Record<string, { in: number; out: number }>>({});

  const ifaces = ws.interfaces as Iface[];
  const connections = ws.connections as Conn[];

  const wanIfaces = ifaces.filter(i => i.role === "WAN");
  // If no role assigned yet, treat the first interface as WAN
  if (wanIfaces.length === 0 && ifaces.length > 0) wanIfaces.push(ifaces[0]);
  const wanNames = new Set(wanIfaces.map(i => i.name));
  const lanIfaces = ifaces.filter(i => !wanNames.has(i.name));

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

  // Compute per-subnet live rates from connection byte totals
  useEffect(() => {
    if (!connections.length) return;
    const subnets: Record<string, { in: number; out: number }> = {};
    for (const c of connections) {
      if (!isPrivateIp(c.src_addr)) continue;
      const sn = getSubnet24(c.src_addr);
      if (!subnets[sn]) subnets[sn] = { in: 0, out: 0 };
      subnets[sn].in += c.bytes_out || 0;   // bytes FROM dst (server→client) = downstream to client
      subnets[sn].out += c.bytes_in || 0;   // bytes FROM src (client→server) = upstream from client
    }
    const prev = prevSubnetBytes.current;
    const newRates: Record<string, { in: number; out: number }> = {};
    for (const [sn, cur] of Object.entries(subnets)) {
      if (prev[sn]) {
        newRates[sn] = {
          in: Math.max(0, (cur.in - prev[sn].in) * 8),
          out: Math.max(0, (cur.out - prev[sn].out) * 8),
        };
      }
    }
    prevSubnetBytes.current = subnets;
    if (Object.keys(newRates).length > 0) setSubnetLiveRates(newRates);
  }, [ws.status, connections]);

  // Only include private (LAN) IPs as hosts
  const lanHosts = useMemo(() => {
    const hosts: Record<string, { ip: string; bytes: number; conns: number; protocols: Set<string> }> = {};
    for (const c of connections) {
      const ip = c.src_addr;
      if (!isPrivateIp(ip)) continue;
      if (!hosts[ip]) hosts[ip] = { ip, bytes: 0, conns: 0, protocols: new Set() };
      hosts[ip].bytes += (c.bytes_in || 0) + (c.bytes_out || 0);
      hosts[ip].conns++;
      hosts[ip].protocols.add(c.protocol);
    }
    return Object.values(hosts).sort((a, b) => b.bytes - a.bytes).slice(0, 30);
  }, [connections]);

  const lanSubnets = useMemo(() => {
    const subnets: Record<string, { subnet: string; bytes: number; conns: number; hosts: typeof lanHosts }> = {};
    for (const h of lanHosts) {
      const subnet = getSubnet24(h.ip);
      if (!subnets[subnet]) subnets[subnet] = { subnet, bytes: 0, conns: 0, hosts: [] };
      subnets[subnet].bytes += h.bytes;
      subnets[subnet].conns += h.conns;
      subnets[subnet].hosts.push(h);
    }
    return Object.values(subnets).sort((a, b) => b.bytes - a.bytes);
  }, [lanHosts]);

  const displayItems = groupBySubnet ? lanSubnets : lanHosts.map(h => ({ subnet: h.ip, bytes: h.bytes, conns: h.conns, hosts: [h] }));
  const maxItemBytes = displayItems[0]?.bytes || 1;
  const maxHostBytes = lanHosts[0]?.bytes || 1;

  const selectedConns = selectedHost
    ? connections.filter(c => {
        if (groupBySubnet && selectedHost.endsWith("/24")) {
          const prefix = selectedHost.replace(".0/24", ".");
          return c.src_addr.startsWith(prefix) || c.dst_addr.startsWith(prefix);
        }
        return c.src_addr === selectedHost || c.dst_addr === selectedHost;
      })
    : [];

  // Aggregate WAN rate across all WAN interfaces
  const wanRate = wanIfaces.reduce((acc, i) => {
    const r = rates[i.name] || { in: 0, out: 0 };
    return { in: acc.in + r.in, out: acc.out + r.out };
  }, { in: 0, out: 0 });

  // Per-subnet rates from connection byte deltas (accurate per-subnet)
  const sRates = displayItems.map(sn => {
    if (groupBySubnet) {
      // Sum live rates for all subnets that roll up to this group
      return subnetLiveRates[sn.subnet] || { in: 0, out: 0 };
    }
    // Individual host mode — use the host's subnet rate as approximation
    return subnetLiveRates[getSubnet24(sn.subnet)] || { in: 0, out: 0 };
  });

  // Map subnets to their parent LAN interface by matching subnet prefix
  const ifaceSubnets = useMemo(() => {
    const map: Record<string, typeof displayItems> = {};
    for (const iface of lanIfaces) {
      map[iface.name] = [];
    }
    for (const item of displayItems) {
      // Match subnet to interface by checking if the subnet falls within the interface's subnet
      const itemPrefix = item.subnet.split(".").slice(0, 3).join(".");
      let matched = false;
      for (const iface of lanIfaces) {
        if (iface.subnet) {
          const ifPrefix = iface.subnet.split(".").slice(0, 3).join(".");
          if (itemPrefix === ifPrefix) {
            map[iface.name].push(item);
            matched = true;
            break;
          }
        }
      }
      if (!matched) {
        // Fall back: assign to first LAN interface with items, or first LAN iface
        const fallback = lanIfaces[0]?.name;
        if (fallback && map[fallback]) map[fallback].push(item);
      }
    }
    return map;
  }, [displayItems, lanIfaces]);

  // SVG topology layout
  const svgW = 800;
  const fwY = 0; // firewall bottom edge in SVG coordinates
  const subnetY = 120; // top of subnet cards
  const subnetCardW = 160;
  const subnetGap = 16;
  const totalSubnetsW = displayItems.length * subnetCardW + (displayItems.length - 1) * subnetGap;
  const startX = Math.max(0, (svgW - totalSubnetsW) / 2);

  return (
    <div className="space-y-4">
      <style jsx global>{`
        @keyframes flowDown { from { background-position-y: 0; } to { background-position-y: 12px; } }
        @keyframes flowUp { from { background-position-y: 0; } to { background-position-y: -12px; } }
      `}</style>

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">NAT Traffic Flows</h1>
          <p className="text-sm text-[var(--text-muted)]">Live network topology — traffic flows top to bottom</p>
        </div>
        <div className="flex items-center gap-4">
          <label className="flex items-center gap-2 text-xs cursor-pointer">
            <input type="checkbox" checked={groupBySubnet} onChange={e => { setGroupBySubnet(e.target.checked); setSelectedHost(null); }}
              className="rounded border-gray-600" />
            <span className="text-[var(--text-secondary)]">Group by /24</span>
          </label>
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
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <div className="flex flex-col items-center">

          {/* Internet */}
          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-blue-600 to-indigo-800 flex items-center justify-center shadow-xl shadow-blue-500/20 border-2 border-blue-400/30">
            <svg className="w-9 h-9 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9" />
            </svg>
          </div>
          <p className="text-xs font-medium text-white mt-1.5">Internet</p>

          {/* WAN interfaces — each gets its own pipe from Internet to AiFw */}
          <div className="flex justify-center gap-6 my-1">
            {wanIfaces.map(wan => {
              const wr = rates[wan.name] || { in: 0, out: 0 };
              return (
                <div key={wan.name} className="flex flex-col items-center">
                  <VPipe rateIn={wr.in} rateOut={wr.out} height={32} />
                  <div className="px-3 py-1 rounded-lg bg-blue-500/15 border border-blue-500/30 text-center">
                    <span className="text-xs font-bold text-blue-400">{wan.name}</span>
                    <span className="text-[10px] text-blue-300/60 ml-1">WAN</span>
                    {wan.address && <span className="text-[9px] text-gray-500 ml-1">{wan.address}</span>}
                  </div>
                  <div className="flex gap-2 mt-0.5 text-[9px]">
                    <span className="text-emerald-400">{formatBps(wr.in)}</span>
                    <span className="text-blue-400">{formatBps(wr.out)}</span>
                  </div>
                  <VPipe rateIn={wr.in} rateOut={wr.out} height={16} />
                </div>
              );
            })}
          </div>

          {/* Firewall */}
          <div className="w-28 h-28 rounded-2xl bg-gradient-to-br from-amber-500/20 to-red-500/15 border-2 border-amber-500/30 flex flex-col items-center justify-center shadow-lg shadow-amber-500/10">
            <svg className="w-9 h-9 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            <p className="text-[10px] font-bold text-amber-400 mt-0.5">AiFw</p>
            <p className="text-[8px] text-gray-500">{connections.length} states</p>
          </div>

          {/* Per-interface columns: each LAN/WG interface gets its own pipe + fan-out */}
          <div className="flex justify-center gap-8 mt-1 flex-wrap">
            {lanIfaces.map(iface => {
              const ifRate = rates[iface.name] || { in: 0, out: 0 };
              const items = ifaceSubnets[iface.name] || [];
              const isWg = iface.name.startsWith("wg");
              const ifSubnetsW = items.length * subnetCardW + Math.max(0, items.length - 1) * subnetGap;
              const ifSvgW = Math.max(300, ifSubnetsW + 40);
              return (
                <div key={iface.name} className="flex flex-col items-center">
                  {/* Pipe from firewall */}
                  <VPipe rateIn={ifRate.out} rateOut={ifRate.in} height={16} />

                  {/* Interface badge */}
                  <div className={`px-3 py-1.5 rounded-lg border text-center ${
                    isWg ? "bg-purple-500/15 border-purple-500/30" : "bg-emerald-500/15 border-emerald-500/30"
                  }`}>
                    <span className={`text-xs font-bold ${isWg ? "text-purple-400" : "text-emerald-400"}`}>{iface.name}</span>
                    <span className={`text-[10px] ml-1 ${isWg ? "text-purple-300/60" : "text-emerald-300/60"}`}>{iface.role || (isWg ? "VPN" : "LAN")}</span>
                    {iface.subnet && <span className="text-[9px] text-gray-500 ml-1.5">{iface.subnet}</span>}
                  </div>

                  {/* Fan-out to subnets */}
                  {items.length > 0 ? (
                    <div className="mt-1">
                      <div style={{ width: ifSvgW }}>
                        <svg viewBox={`0 0 ${ifSvgW} ${subnetY + 10}`} className="w-full"
                          preserveAspectRatio="xMidYMid meet" style={{ height: subnetY + 10 }}>
                          {items.map((sn, idx) => {
                            const cx = ifSvgW / 2;
                            const ifStartX = (ifSvgW - ifSubnetsW) / 2;
                            const ax = ifStartX + idx * (subnetCardW + subnetGap) + subnetCardW / 2;
                            const gap = 4;
                            const pathIn  = `M ${cx - gap},${fwY} C ${cx - gap},${subnetY * 0.4} ${ax - gap},${subnetY * 0.5} ${ax - gap},${subnetY}`;
                            const pathOut = `M ${cx + gap},${fwY} C ${cx + gap},${subnetY * 0.4} ${ax + gap},${subnetY * 0.5} ${ax + gap},${subnetY}`;
                            const sr = (groupBySubnet ? subnetLiveRates[sn.subnet] : subnetLiveRates[getSubnet24(sn.subnet)]) || { in: 0, out: 0 };
                            return (
                              <SvgPipe key={sn.subnet} id={`pipe-${iface.name}-${idx}`} pathIn={pathIn} pathOut={pathOut}
                                rateIn={sr.in} rateOut={sr.out} />
                            );
                          })}
                        </svg>
                        <div className="flex justify-center gap-4 flex-wrap" style={{ marginTop: -4 }}>
                          {items.map(sn => {
                            const sr = (groupBySubnet ? subnetLiveRates[sn.subnet] : subnetLiveRates[getSubnet24(sn.subnet)]) || { in: 0, out: 0 };
                            const isSelected = selectedHost === sn.subnet;
                            return (
                              <button key={sn.subnet}
                                onClick={() => setSelectedHost(isSelected ? null : sn.subnet)}
                                className={`flex flex-col items-center p-3 rounded-xl border-2 transition-all duration-200 min-w-[140px] max-w-[180px] ${
                                  isSelected
                                    ? "bg-cyan-500/10 border-cyan-500/50 shadow-lg shadow-cyan-500/10"
                                    : "bg-[var(--bg-primary)] border-[var(--border)] hover:border-gray-500 hover:bg-gray-700/30"
                                }`}
                              >
                                <div className={`w-8 h-8 rounded-lg flex items-center justify-center mb-1.5 ${isSelected ? "bg-cyan-500/20" : "bg-gray-700/50"}`}>
                                  <svg className={`w-4 h-4 ${isSelected ? "text-cyan-400" : "text-gray-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                    {isWg
                                      ? <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                                      : <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
                                    }
                                  </svg>
                                </div>
                                <span className={`text-[11px] font-mono font-bold ${isSelected ? "text-cyan-400" : "text-white"}`}>{sn.subnet}</span>
                                <div className="flex gap-2 mt-1 text-[9px]">
                                  <span className="text-emerald-400">{formatBps(sr.in)}</span>
                                  <span className="text-blue-400">{formatBps(sr.out)}</span>
                                </div>
                                <span className="text-[9px] text-gray-500 mt-0.5">{sn.hosts.length} host{sn.hosts.length !== 1 ? "s" : ""} · {sn.conns} conn</span>
                                <span className="text-[9px] text-gray-500">{formatBytes(sn.bytes)}</span>
                                <div className="w-full h-1 bg-gray-700 rounded-full mt-1.5 overflow-hidden">
                                  <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all"
                                    style={{ width: `${Math.max(2, (sn.bytes / maxItemBytes) * 100)}%` }} />
                                </div>
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-[10px] text-gray-600 mt-3">No active hosts</div>
                  )}
                </div>
              );
            })}
          </div>
          {lanIfaces.length === 0 && (
            <div className="text-center text-gray-600 text-xs py-6 mt-2">No LAN interfaces</div>
          )}
        </div>
      </div>

      {/* Host / Subnet Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
            <h3 className="text-sm font-medium">{groupBySubnet ? "Subnets" : "Active Hosts"}</h3>
            <span className="text-[10px] text-gray-500">{groupBySubnet ? `${lanSubnets.length} subnet${lanSubnets.length !== 1 ? "s" : ""} · ${lanHosts.length} hosts` : `${lanHosts.length} hosts`}</span>
          </div>
          <div className="max-h-80 overflow-y-auto divide-y divide-[var(--border)]">
            {groupBySubnet ? (
              lanSubnets.map(sn => (
                <button key={sn.subnet} onClick={() => setSelectedHost(selectedHost === sn.subnet ? null : sn.subnet)}
                  className={`w-full px-4 py-2.5 text-left hover:bg-gray-700/30 transition-colors ${selectedHost === sn.subnet ? "bg-cyan-500/5 border-l-2 border-cyan-500" : ""}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-white">{sn.subnet}</span>
                    <span className="text-[10px] text-gray-400">{sn.hosts.length} host{sn.hosts.length !== 1 ? "s" : ""} · {sn.conns} conn · {formatBytes(sn.bytes)}</span>
                  </div>
                  <div className="w-full h-1 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all" style={{ width: `${(sn.bytes / maxItemBytes) * 100}%` }} />
                  </div>
                  {selectedHost === sn.subnet && (
                    <div className="mt-2 flex flex-wrap gap-1">
                      {sn.hosts.map(h => (
                        <span key={h.ip} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-gray-700/50 text-gray-400">
                          .{h.ip.split(".")[3]} — {formatBytes(h.bytes)}
                        </span>
                      ))}
                    </div>
                  )}
                </button>
              ))
            ) : (
              lanHosts.map(host => (
                <button key={host.ip} onClick={() => setSelectedHost(selectedHost === host.ip ? null : host.ip)}
                  className={`w-full px-4 py-2.5 text-left hover:bg-gray-700/30 transition-colors ${selectedHost === host.ip ? "bg-cyan-500/5 border-l-2 border-cyan-500" : ""}`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-mono text-xs text-white">{host.ip}</span>
                    <span className="text-[10px] text-gray-400">{host.conns} conn · {formatBytes(host.bytes)}</span>
                  </div>
                  <div className="w-full h-1 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 transition-all" style={{ width: `${(host.bytes / maxHostBytes) * 100}%` }} />
                  </div>
                </button>
              ))
            )}
            {lanHosts.length === 0 && <div className="text-center py-6 text-gray-500 text-sm">No active hosts</div>}
          </div>
        </div>

        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]">
            <h3 className="text-sm font-medium">{selectedHost ? `Connections — ${selectedHost}` : "Select a host"}</h3>
          </div>
          {selectedHost ? (
            <div className="max-h-80 overflow-y-auto divide-y divide-[var(--border)]">
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
            <div className="text-center py-10 text-gray-500 text-sm">Click a subnet in the topology or list to view connections</div>
          )}
        </div>
      </div>
    </div>
  );
}
