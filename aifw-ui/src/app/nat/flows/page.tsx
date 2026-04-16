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

/* ────────────────────────── Pipe geometry helpers ──────────────────────────
 *
 * Pipes are rendered as "water under pressure":
 *   1. A solid colored body (no dashed line) = continuous fluid.
 *   2. A thin white highlight stream that flows along the top of the body,
 *      simulating light glinting off the surface. Animation speed scales
 *      with throughput — heavy traffic = fast water.
 *   3. An ambient halo whose opacity rises with the flow rate, so busy
 *      pipes feel hot/bright and idle ones fade.
 *
 * Colors from the AiFw logo:
 *   Inbound  = ocean water blue (#0ea5e9, sky-500) — the shield
 *   Outbound = flame red       (#ef4444, red-500)  — the flame
 *
 * Pipe width is fixed — flow rate is conveyed by highlight animation
 * speed and halo brightness, not by stroke thickness.
 */
const PIPE_IN = "14, 165, 233";   // sky-500 (#0ea5e9) — ocean water blue
const PIPE_OUT = "239, 68, 68";   // red-500 (#ef4444) — flame red
const PIPE_W = 10;                // fixed pipe thickness (px)

/** Fixed pipe stroke width. The `bps` arg is kept for call-site
 *  compatibility; throughput is now conveyed by animation speed and
 *  halo intensity, not thickness. */
function rateWidth(_bps: number): number { return PIPE_W; }

/** bps → stroke alpha. Idle pipes are faint, heavy traffic is opaque. */
function rateAlpha(bps: number): number {
  if (bps <= 0) return 0.12;
  const lg = Math.log10(Math.max(bps, 1));
  return Math.min(0.95, 0.3 + (lg - 2) / 10);
}

/** Animated vertical pipe — blue=in (down), red=out (up). */
function VPipe({ rateIn, rateOut, height = 60 }: { rateIn: number; rateOut: number; height?: number }) {
  const inW = rateWidth(rateIn);
  const outW = rateWidth(rateOut);
  const inA = rateAlpha(rateIn);
  const outA = rateAlpha(rateOut);
  const totalW = inW + outW + 4;
  const svgW = Math.max(40, totalW + 16);
  const cx = svgW / 2;
  // Tight separation — pipes sit just next to each other so the card
  // background isn't visible as a "third line" between them.
  const gap = (inW + outW) / 2 * 0.55;
  return (
    <svg viewBox={`0 0 ${svgW} ${height}`} style={{ width: svgW, height }} className="block mx-auto">
      {/* Ambient glow — subtle halo around both pipes */}
      <line x1={cx} y1={0} x2={cx} y2={height} stroke={`rgba(${PIPE_IN},0.05)`} strokeWidth={totalW + 10} strokeLinecap="round" />
      {/* Inbound (blue, left) */}
      <line x1={cx - gap} y1={0} x2={cx - gap} y2={height} stroke={`rgba(${PIPE_IN},${inA})`}
        strokeWidth={inW} strokeDasharray="5 7" strokeLinecap="round">
        {rateIn > 0 && <animate attributeName="stroke-dashoffset" from="0" to="-12" dur="0.5s" repeatCount="indefinite" />}
      </line>
      {/* Outbound (red, right) */}
      <line x1={cx + gap} y1={0} x2={cx + gap} y2={height} stroke={`rgba(${PIPE_OUT},${outA})`}
        strokeWidth={outW} strokeDasharray="5 7" strokeLinecap="round">
        {rateOut > 0 && <animate attributeName="stroke-dashoffset" from="0" to="12" dur="0.5s" repeatCount="indefinite" />}
      </line>
    </svg>
  );
}

/**
 * SVG animated bezier pipe pair. Inbound blue (down), outbound red (up).
 *
 * Callers pass the centerline geometry (x1,y1 → x2,y2 with bezier
 * control-point Y values cy1, cy2). Each stream is drawn offset to its
 * own side of the centerline; the offset is derived from that stream's
 * own stroke width, so the two pipes always abut with a fixed visible
 * gap between them and expand outward as their rates grow — they never
 * overlap, and they never drift apart.
 */
const PIPE_SEP = 2; // px gap kept between the two streams at all times

/** Animation duration in seconds: faster when busier, clamped so idle
 *  pipes aren't stuck on a 10-second crawl and 10 Gbps doesn't blur. */
function flowDur(bps: number): string {
  if (bps <= 0) return "2s";
  const lg = Math.log10(Math.max(bps, 1));
  // 1 Kbps (lg=3) → ~1.5s ; 1 Mbps (lg=6) → ~0.6s ; 1 Gbps (lg=9) → ~0.22s
  const d = Math.max(0.2, 1.8 - (lg - 2) * 0.22);
  return `${d.toFixed(2)}s`;
}

function SvgPipe({ x1, y1, x2, y2, cy1, cy2, rateIn, rateOut }:
  { x1: number; y1: number; x2: number; y2: number; cy1: number; cy2: number; rateIn: number; rateOut: number; id?: string }) {
  const inW = rateWidth(rateIn);
  const outW = rateWidth(rateOut);
  const inA = rateAlpha(rateIn);
  const outA = rateAlpha(rateOut);
  const inDx = inW / 2 + PIPE_SEP / 2;
  const outDx = outW / 2 + PIPE_SEP / 2;
  const pathIn  = `M ${x1 - inDx},${y1} C ${x1 - inDx},${cy1} ${x2 - inDx},${cy2} ${x2 - inDx},${y2}`;
  const pathOut = `M ${x1 + outDx},${y1} C ${x1 + outDx},${cy1} ${x2 + outDx},${cy2} ${x2 + outDx},${y2}`;
  // Highlight stripes — thin, bright, travel along the flow direction.
  const hlInW  = Math.max(1, inW * 0.22);
  const hlOutW = Math.max(1, outW * 0.22);
  const hlInA  = Math.min(0.55, 0.15 + inA * 0.5);
  const hlOutA = Math.min(0.55, 0.15 + outA * 0.5);
  return (
    <g>
      {/* Rate-scaled colored halo — brightens as traffic ramps up */}
      <path d={pathIn}  fill="none" stroke={`rgba(${PIPE_IN},${0.04 + inA * 0.14})`}   strokeWidth={inW + 14}  strokeLinecap="round" />
      <path d={pathOut} fill="none" stroke={`rgba(${PIPE_OUT},${0.04 + outA * 0.14})`} strokeWidth={outW + 14} strokeLinecap="round" />
      {/* Main fluid body — solid colored stroke, reads as continuous water */}
      <path d={pathIn}  fill="none" stroke={`rgba(${PIPE_IN},${inA})`}   strokeWidth={inW}  strokeLinecap="round" />
      <path d={pathOut} fill="none" stroke={`rgba(${PIPE_OUT},${outA})`} strokeWidth={outW} strokeLinecap="round" />
      {/* Inbound (blue) highlight — bright streaks running along the top */}
      <path d={pathIn} fill="none" stroke={`rgba(255,255,255,${hlInA})`}
        strokeWidth={hlInW} strokeDasharray="10 22" strokeLinecap="round">
        {rateIn > 0 && <animate attributeName="stroke-dashoffset" from="0" to="-32" dur={flowDur(rateIn)} repeatCount="indefinite" />}
      </path>
      {/* Outbound (red) highlight — bright streaks running along the top */}
      <path d={pathOut} fill="none" stroke={`rgba(255,255,255,${hlOutA})`}
        strokeWidth={hlOutW} strokeDasharray="10 22" strokeLinecap="round">
        {rateOut > 0 && <animate attributeName="stroke-dashoffset" from="0" to="32" dur={flowDur(rateOut)} repeatCount="indefinite" />}
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
  const subnetY = 110; // top of subnet cards
  const subnetCardW = 120; // compact card width — dense layout
  const subnetGap = 10;
  const lanColPad = 24; // horizontal slack per interface column
  const lanColMin = 200; // floor per column even when it holds zero subnets
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
            <span className="flex items-center gap-1"><span className="w-2 h-3 bg-blue-600/90 rounded-sm inline-block" /> In</span>
            <span className="flex items-center gap-1"><span className="w-2 h-3 bg-red-500/90 rounded-sm inline-block" /> Out</span>
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

          {/* WAN: Internet → fan-out → badges → fan-in → Firewall */}
          {(() => {
            const wanColW = 200;
            const wanGap = 32;
            const totalWanW = wanIfaces.length * wanColW + Math.max(0, wanIfaces.length - 1) * wanGap;
            const wanFanW = Math.max(400, totalWanW + 40);
            const fanDownH = 70;
            const fanUpH = 60;
            return (
              <>
                {/* Fan-out from Internet to WAN interfaces */}
                <div className="w-full mt-1 overflow-x-auto">
                  <div className="min-w-fit mx-auto" style={{ width: wanFanW }}>
                    <svg viewBox={`0 0 ${wanFanW} ${fanDownH}`} className="w-full" preserveAspectRatio="xMidYMid meet" style={{ height: fanDownH }}>
                      {wanIfaces.map((wan, idx) => {
                        const cx = wanFanW / 2;
                        const sx = (wanFanW - totalWanW) / 2;
                        const ax = sx + idx * (wanColW + wanGap) + wanColW / 2;
                        const wr = rates[wan.name] || { in: 0, out: 0 };
                        return <SvgPipe key={wan.name} id={`inet-${wan.name}`}
                          x1={cx} y1={0} x2={ax} y2={fanDownH}
                          cy1={fanDownH * 0.4} cy2={fanDownH * 0.5}
                          rateIn={wr.in} rateOut={wr.out} />;
                      })}
                    </svg>
                  </div>
                </div>
                {/* WAN badges — fixed-width columns matching SVG */}
                <div className="flex justify-center" style={{ gap: wanGap }}>
                  {wanIfaces.map(wan => {
                    const wr = rates[wan.name] || { in: 0, out: 0 };
                    return (
                      <div key={wan.name} className="flex flex-col items-center" style={{ width: wanColW }}>
                        <div className="px-3 py-1 rounded-lg bg-blue-500/15 border border-blue-500/30 text-center">
                          <span className="text-xs font-bold text-blue-400">{wan.name}</span>
                          <span className="text-[10px] text-blue-300/60 ml-1">WAN</span>
                          {wan.address && <span className="text-[9px] text-gray-500 ml-1">{wan.address}</span>}
                        </div>
                        <div className="flex gap-2 mt-0.5 text-[9px]">
                          <span className="text-blue-400">{formatBps(wr.in)}</span>
                          <span className="text-red-400">{formatBps(wr.out)}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
                {/* Fan-in from WAN interfaces to Firewall */}
                <div className="w-full overflow-x-auto">
                  <div className="min-w-fit mx-auto" style={{ width: wanFanW }}>
                    <svg viewBox={`0 0 ${wanFanW} ${fanUpH}`} className="w-full" preserveAspectRatio="xMidYMid meet" style={{ height: fanUpH }}>
                      {wanIfaces.map((wan, idx) => {
                        const cx = wanFanW / 2;
                        const sx = (wanFanW - totalWanW) / 2;
                        const ax = sx + idx * (wanColW + wanGap) + wanColW / 2;
                        const wr = rates[wan.name] || { in: 0, out: 0 };
                        return <SvgPipe key={wan.name} id={`wan-fw-${wan.name}`}
                          x1={ax} y1={0} x2={cx} y2={fanUpH}
                          cy1={fanUpH * 0.5} cy2={fanUpH * 0.6}
                          rateIn={wr.in} rateOut={wr.out} />;
                      })}
                    </svg>
                  </div>
                </div>
              </>
            );
          })()}

          {/* Firewall — uses the AiFw sidebar logo so this node matches the
              brand mark shown in the top-left. */}
          <div className="w-28 h-28 rounded-2xl bg-[var(--bg-primary)] border-2 border-[var(--border)] flex flex-col items-center justify-center shadow-lg shadow-black/40 px-2">
            {/* eslint-disable-next-line @next/next/no-img-element */}
            <img
              src="/logo-sidebar.png"
              alt="AiFw"
              className="h-10 w-auto object-contain opacity-95"
            />
            <p className="text-[8px] text-gray-500 mt-1">{connections.length} states</p>
          </div>

          {/* SVG fan-out from AiFw to LAN/WG interfaces + interface columns */}
          {lanIfaces.length > 0 && (() => {
            // Each interface column auto-sizes to hold its own subnet grid.
            // No more fixed 200px columns that overflow when 2+ subnets exist.
            const lanGap = 24;
            const perIfaceColW = lanIfaces.map(iface => {
              const items = ifaceSubnets[iface.name] || [];
              const gridW = items.length === 0
                ? 0
                : items.length * subnetCardW + (items.length - 1) * subnetGap;
              return Math.max(lanColMin, gridW + lanColPad);
            });
            const totalLanW = perIfaceColW.reduce((a, b) => a + b, 0)
              + Math.max(0, lanIfaces.length - 1) * lanGap;
            const fanSvgW = Math.max(400, totalLanW + 40);
            const fanH = 80;
            // Precompute column centers for fan-out pipes.
            const lanStartX = (fanSvgW - totalLanW) / 2;
            const colCenters = perIfaceColW.map((_, idx) => {
              const before = perIfaceColW.slice(0, idx).reduce((a, b) => a + b, 0)
                + idx * lanGap;
              return lanStartX + before + perIfaceColW[idx] / 2;
            });
            return (
              <>
                <div className="w-full mt-1 overflow-x-auto">
                  <div className="min-w-fit mx-auto" style={{ width: fanSvgW }}>
                    <svg viewBox={`0 0 ${fanSvgW} ${fanH}`} className="w-full" preserveAspectRatio="xMidYMid meet" style={{ height: fanH }}>
                      {lanIfaces.map((iface, idx) => {
                        const cx = fanSvgW / 2;
                        const ax = colCenters[idx];
                        const ifRate = rates[iface.name] || { in: 0, out: 0 };
                        return (
                          <SvgPipe key={iface.name} id={`fw-${iface.name}`}
                            x1={cx} y1={0} x2={ax} y2={fanH}
                            cy1={fanH * 0.4} cy2={fanH * 0.5}
                            rateIn={ifRate.out} rateOut={ifRate.in} />
                        );
                      })}
                    </svg>
                  </div>
                </div>
                {/* Interface columns — each auto-sized to its subnet grid. */}
                <div className="flex flex-wrap justify-center items-start" style={{ gap: lanGap }}>
                  {lanIfaces.map((iface, idx) => {
                    const ifRate = rates[iface.name] || { in: 0, out: 0 };
                    const items = ifaceSubnets[iface.name] || [];
                    const isWg = iface.name.startsWith("wg");
                    const ifSubnetsW = items.length === 0
                      ? 0
                      : items.length * subnetCardW + (items.length - 1) * subnetGap;
                    const columnW = perIfaceColW[idx];
                    const ifSvgW = Math.max(columnW, ifSubnetsW + 20);
                    return (
                      <div key={iface.name} className="flex flex-col items-center" style={{ width: columnW }}>
                        {/* Interface badge */}
                        <div className={`px-3 py-1.5 rounded-lg border text-center ${
                          isWg ? "bg-purple-500/15 border-purple-500/30" : "bg-emerald-500/15 border-emerald-500/30"
                        }`}>
                          <span className={`text-xs font-bold ${isWg ? "text-purple-400" : "text-emerald-400"}`}>{iface.name}</span>
                          <span className={`text-[10px] ml-1 ${isWg ? "text-purple-300/60" : "text-emerald-300/60"}`}>{iface.role || (isWg ? "VPN" : "LAN")}</span>
                          {iface.subnet && <span className="text-[9px] text-gray-500 ml-1.5">{iface.subnet}</span>}
                        </div>
                        <div className="flex gap-2 mt-0.5 text-[9px]">
                          <span className="text-blue-400">{formatBps(ifRate.out)}</span>
                          <span className="text-red-400">{formatBps(ifRate.in)}</span>
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
                            const sr = (groupBySubnet ? subnetLiveRates[sn.subnet] : subnetLiveRates[getSubnet24(sn.subnet)]) || { in: 0, out: 0 };
                            return (
                              <SvgPipe key={sn.subnet} id={`pipe-${iface.name}-${idx}`}
                                x1={cx} y1={fwY} x2={ax} y2={subnetY}
                                cy1={subnetY * 0.4} cy2={subnetY * 0.5}
                                rateIn={sr.in} rateOut={sr.out} />
                            );
                          })}
                        </svg>
                        <div
                          className="flex justify-center items-start flex-wrap"
                          style={{ marginTop: -4, gap: subnetGap, width: ifSvgW }}
                        >
                          {items.map(sn => {
                            const sr = (groupBySubnet ? subnetLiveRates[sn.subnet] : subnetLiveRates[getSubnet24(sn.subnet)]) || { in: 0, out: 0 };
                            const isSelected = selectedHost === sn.subnet;
                            return (
                              <button key={sn.subnet}
                                onClick={() => setSelectedHost(isSelected ? null : sn.subnet)}
                                className={`flex flex-col items-center px-2 py-2 rounded-lg border transition-all duration-200 ${
                                  isSelected
                                    ? "bg-cyan-500/10 border-cyan-500/50 shadow-lg shadow-cyan-500/10"
                                    : "bg-[var(--bg-primary)] border-[var(--border)] hover:border-gray-500 hover:bg-gray-700/30"
                                }`}
                                style={{ width: subnetCardW }}
                              >
                                <div className="flex items-center gap-1.5 w-full justify-center">
                                  <div className={`w-5 h-5 rounded flex items-center justify-center flex-shrink-0 ${isSelected ? "bg-cyan-500/20" : "bg-gray-700/50"}`}>
                                    <svg className={`w-3 h-3 ${isSelected ? "text-cyan-400" : "text-gray-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                      {isWg
                                        ? <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
                                        : <path strokeLinecap="round" strokeLinejoin="round" d="M8.288 15.038a5.25 5.25 0 017.424 0M5.106 11.856c3.807-3.808 9.98-3.808 13.788 0M1.924 8.674c5.565-5.565 14.587-5.565 20.152 0M12.53 18.22l-.53.53-.53-.53a.75.75 0 011.06 0z" />
                                      }
                                    </svg>
                                  </div>
                                  <span className={`text-[10px] font-mono font-bold truncate ${isSelected ? "text-cyan-400" : "text-white"}`}>{sn.subnet}</span>
                                </div>
                                <div className="flex gap-1.5 mt-1 text-[9px] leading-none">
                                  <span className="text-blue-400">{formatBps(sr.in)}</span>
                                  <span className="text-red-400">{formatBps(sr.out)}</span>
                                </div>
                                <div className="flex justify-between w-full mt-0.5 text-[8px] text-gray-500 leading-none">
                                  <span>{sn.hosts.length}h · {sn.conns}c</span>
                                  <span>{formatBytes(sn.bytes)}</span>
                                </div>
                                <div className="w-full h-0.5 bg-gray-700 rounded-full mt-1 overflow-hidden">
                                  <div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all"
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
              </>
            );
          })()}
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
                    <div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all" style={{ width: `${(sn.bytes / maxItemBytes) * 100}%` }} />
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
                    <div className="h-full rounded-full bg-gradient-to-r from-blue-600 to-blue-400 transition-all" style={{ width: `${(host.bytes / maxHostBytes) * 100}%` }} />
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
                      <span className="text-blue-400">In: {formatBytes(c.bytes_in)}</span> · <span className="text-red-400">Out: {formatBytes(c.bytes_out)}</span>
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
