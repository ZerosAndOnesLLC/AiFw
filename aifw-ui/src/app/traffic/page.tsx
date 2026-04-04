"use client";

import { useEffect, useState, useRef, useMemo } from "react";
import { useWs } from "@/context/WsContext";

interface RatePoint { time: number; bpsIn: number; bpsOut: number; }

function formatBytes(b: number): string {
  if (b >= 1e12) return `${(b/1e12).toFixed(2)} TB`; if (b >= 1e9) return `${(b/1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b/1e6).toFixed(1)} MB`; if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB`;
  return `${b} B`;
}
function formatBps(b: number): string {
  if (b >= 1e9) return `${(b/1e9).toFixed(2)} Gbps`; if (b >= 1e6) return `${(b/1e6).toFixed(1)} Mbps`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} Kbps`; return `${b.toFixed(0)} bps`;
}
function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n/1e6).toFixed(1)}M`; if (n >= 1e3) return `${(n/1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

const MAX_POINTS = 300;
const portNames: Record<number, string> = {
  20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",67:"dhcp",68:"dhcp",
  80:"http",110:"pop3",123:"ntp",143:"imap",161:"snmp",443:"https",445:"smb",465:"smtps",
  514:"syslog",587:"submission",636:"ldaps",853:"dot",993:"imaps",995:"pop3s",1194:"openvpn",
  1433:"mssql",1723:"pptp",3306:"mysql",3389:"rdp",5060:"sip",5432:"postgres",5900:"vnc",
  6379:"redis",8080:"http-alt",8443:"https-alt",27017:"mongodb",51820:"wireguard",
};

const IFACE_COLORS: Record<number, { stroke: string; fill: string; label: string }> = {
  0: { stroke: "#22c55e", fill: "#22c55e", label: "green" },
  1: { stroke: "#3b82f6", fill: "#3b82f6", label: "blue" },
  2: { stroke: "#f59e0b", fill: "#f59e0b", label: "amber" },
  3: { stroke: "#a855f7", fill: "#a855f7", label: "purple" },
  4: { stroke: "#ef4444", fill: "#ef4444", label: "red" },
  5: { stroke: "#06b6d4", fill: "#06b6d4", label: "cyan" },
};

function TrafficChart({ data, height = 180, color = "#22c55e" }: { data: RatePoint[]; height?: number; color?: string }) {
  if (data.length < 3) return (
    <div className="flex items-center justify-center text-[var(--text-muted)] text-sm" style={{height}}>
      <div className="text-center"><div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-2"/>Collecting...</div>
    </div>
  );
  const w=900,h2=height,pad={top:8,right:8,bottom:4,left:55};
  const cW=w-pad.left-pad.right,cH=h2-pad.top-pad.bottom,ppx=cW/MAX_POINTS;
  const maxV=Math.max(...data.map(d=>Math.max(d.bpsIn,d.bpsOut)),1000);
  const sY=(v:number)=>pad.top+cH-(v/maxV)*cH;
  const sX=pad.left+cW-data.length*ppx;
  const smooth=(pts:{x:number;y:number}[])=>{
    if(pts.length<2)return"";let d=`M ${pts[0].x},${pts[0].y}`;
    for(let i=0;i<pts.length-1;i++){const p0=pts[Math.max(0,i-1)],p1=pts[i],p2=pts[i+1],p3=pts[Math.min(pts.length-1,i+2)];
    d+=` C ${p1.x+(p2.x-p0.x)/6},${p1.y+(p2.y-p0.y)/6} ${p2.x-(p3.x-p1.x)/6},${p2.y-(p3.y-p1.y)/6} ${p2.x},${p2.y}`;}return d;
  };
  const inP=data.map((d,i)=>({x:sX+i*ppx,y:sY(d.bpsIn)})),outP=data.map((d,i)=>({x:sX+i*ppx,y:sY(d.bpsOut)}));
  const inL=smooth(inP),outL=smooth(outP),bl=pad.top+cH;
  const inA=`${inL} L ${inP[inP.length-1].x},${bl} L ${inP[0].x},${bl} Z`;
  const outA=`${outL} L ${outP[outP.length-1].x},${bl} L ${outP[0].x},${bl} Z`;
  const yT=3,yL=Array.from({length:yT+1},(_,i)=>({y:sY((maxV/yT)*i),label:formatBps((maxV/yT)*i)}));
  const uid = `tc${color.replace('#','')}`;
  return (
    <svg viewBox={`0 0 ${w} ${h2}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id={`${uid}In`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity="0.4"/><stop offset="100%" stopColor={color} stopOpacity="0.02"/></linearGradient>
        <linearGradient id={`${uid}Out`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35"/><stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02"/></linearGradient>
        <clipPath id={`${uid}c`}><rect x={pad.left} y={pad.top} width={cW} height={cH}/></clipPath>
      </defs>
      {yL.map((t,i)=>(<g key={i}><line x1={pad.left} y1={t.y} x2={w-pad.right} y2={t.y} stroke="#1e293b"/><text x={pad.left-4} y={t.y+3} textAnchor="end" fill="#64748b" fontSize="9" fontFamily="monospace">{t.label}</text></g>))}
      <g clipPath={`url(#${uid}c)`}>
        <path d={inA} fill={`url(#${uid}In)`}/><path d={outA} fill={`url(#${uid}Out)`}/>
        <path d={inL} fill="none" stroke={color} strokeWidth="1.5"/><path d={outL} fill="none" stroke="#3b82f6" strokeWidth="1.5"/>
        <circle cx={inP[inP.length-1].x} cy={inP[inP.length-1].y} r="2.5" fill={color}/>
        <circle cx={outP[outP.length-1].x} cy={outP[outP.length-1].y} r="2.5" fill="#3b82f6"/>
      </g>
    </svg>
  );
}

type IfaceData = { name: string; bytes_in: number; bytes_out: number; packets_in: number; packets_out: number; role?: string };

export default function TrafficPage() {
  const ws = useWs();
  const [selectedNics, setSelectedNics] = useState<Set<string>>(() => {
    if (typeof window === "undefined") return new Set();
    const saved = localStorage.getItem("aifw_traffic_nics");
    return saved ? new Set(JSON.parse(saved)) : new Set();
  });
  const [rateHistories, setRateHistories] = useState<Record<string, RatePoint[]>>({});
  const [currentRates, setCurrentRates] = useState<Record<string, { in: number; out: number }>>({});
  const prevIface = useRef<Record<string, { bytes_in: number; bytes_out: number }>>({});
  const prevTime = useRef(0);

  const ifaceNames = (ws.interfaces as IfaceData[]);
  const allSelected = selectedNics.size === 0 || selectedNics.size === ifaceNames.length;

  const toggleNic = (name: string) => {
    setSelectedNics(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      localStorage.setItem("aifw_traffic_nics", JSON.stringify([...next]));
      return next;
    });
  };

  const selectAll = () => {
    setSelectedNics(new Set());
    localStorage.setItem("aifw_traffic_nics", "[]");
  };

  const visibleNics = allSelected ? ifaceNames.map(i => i.name) : [...selectedNics].filter(n => ifaceNames.some(i => i.name === n));

  const historyProcessed = useRef(false);
  const lastHistoryLen = useRef(0);

  // Pre-populate rate histories from WebSocket history (same pattern as dashboard)
  useEffect(() => {
    if (!ws.historyLoaded) return;
    if (ws.history.length === 0) { historyProcessed.current = true; return; }
    if (historyProcessed.current && ws.history.length === lastHistoryLen.current) return;

    const rawHistory = ws.history as Record<string, unknown>[];
    const prevByIf: Record<string, { bytes_in: number; bytes_out: number }> = {};
    const histories: Record<string, RatePoint[]> = {};
    let prevTs = 0;

    for (let idx = 0; idx < rawHistory.length; idx++) {
      const entry = rawHistory[idx];
      if ((entry as { type?: string }).type !== "status_update") continue;
      const ts = Date.now() - (rawHistory.length - idx) * 1000;
      const entryIfaces = ((entry as { interfaces?: IfaceData[] }).interfaces || []) as IfaceData[];

      for (const cur of entryIfaces) {
        const prev = prevByIf[cur.name];
        if (prev && prevTs) {
          const dt = (ts - prevTs) / 1000;
          if (dt > 0 && dt < 5) {
            const bi = Math.max(0, (cur.bytes_in - prev.bytes_in) / dt * 8);
            const bo = Math.max(0, (cur.bytes_out - prev.bytes_out) / dt * 8);
            if (!histories[cur.name]) histories[cur.name] = [];
            histories[cur.name].push({ time: ts, bpsIn: bi, bpsOut: bo });
          }
        }
        prevByIf[cur.name] = { bytes_in: cur.bytes_in, bytes_out: cur.bytes_out };
      }
      prevTs = ts;
    }

    // Trim to MAX_POINTS and set state
    for (const name of Object.keys(histories)) {
      histories[name] = histories[name].slice(-MAX_POINTS);
    }
    Object.assign(prevIface.current, prevByIf);
    prevTime.current = Date.now();
    lastHistoryLen.current = ws.history.length;
    historyProcessed.current = true;
    setRateHistories(histories);

    // Set current rates from the last computed points
    const rates: Record<string, { in: number; out: number }> = {};
    for (const [name, pts] of Object.entries(histories)) {
      if (pts.length > 0) {
        const last = pts[pts.length - 1];
        rates[name] = { in: last.bpsIn, out: last.bpsOut };
      }
    }
    setCurrentRates(rates);
  }, [ws.historyLoaded, ws.history, ws.history.length]);

  // Process live updates — all interfaces
  useEffect(() => {
    if (!ws.status || !ws.interfaces.length) return;
    const now = Date.now();
    const ifaces = ws.interfaces as IfaceData[];

    const newRates: Record<string, { in: number; out: number }> = {};
    const newPoints: Record<string, RatePoint> = {};

    for (const cur of ifaces) {
      const prev = prevIface.current[cur.name];
      if (prev && prevTime.current) {
        const dt = (now - prevTime.current) / 1000;
        if (dt > 0 && dt < 5) {
          const bi = Math.max(0, (cur.bytes_in - prev.bytes_in) / dt * 8);
          const bo = Math.max(0, (cur.bytes_out - prev.bytes_out) / dt * 8);
          newRates[cur.name] = { in: bi, out: bo };
          newPoints[cur.name] = { time: now, bpsIn: bi, bpsOut: bo };
        }
      }
      prevIface.current[cur.name] = { bytes_in: cur.bytes_in, bytes_out: cur.bytes_out };
    }
    prevTime.current = now;

    if (Object.keys(newRates).length > 0) {
      setCurrentRates(newRates);
      setRateHistories(prev => {
        const next = { ...prev };
        for (const [name, pt] of Object.entries(newPoints)) {
          next[name] = [...(next[name] || []), pt].slice(-MAX_POINTS);
        }
        return next;
      });
    }
  }, [ws.status, ws.interfaces]);

  const connections = ws.connections as { src_addr: string; dst_addr: string; dst_port: number; protocol: string; bytes_in: number; bytes_out: number }[];

  const topTalkers = useMemo(() =>
    connections.reduce<{ ip: string; bytes: number; conns: number }[]>((a, c) => {
      const e = a.find(t => t.ip === c.src_addr), tot = (c.bytes_in || 0) + (c.bytes_out || 0);
      if (e) { e.bytes += tot; e.conns++; } else a.push({ ip: c.src_addr, bytes: tot, conns: 1 }); return a;
    }, []).sort((a, b) => b.bytes - a.bytes).slice(0, 10),
  [connections]);
  const maxTB = topTalkers[0]?.bytes || 1;

  const topPorts = useMemo(() =>
    connections.reduce<{ port: number; proto: string; conns: number }[]>((a, c) => {
      const key = `${c.dst_port}-${c.protocol}`, e = a.find(p => `${p.port}-${p.proto}` === key);
      if (e) e.conns++; else a.push({ port: c.dst_port, proto: c.protocol, conns: 1 }); return a;
    }, []).sort((a, b) => b.conns - a.conns).slice(0, 15),
  [connections]);
  const maxPC = topPorts[0]?.conns || 1;

  // Aggregate totals for summary cards
  const totalIn = visibleNics.reduce((s, n) => s + (currentRates[n]?.in || 0), 0);
  const totalOut = visibleNics.reduce((s, n) => s + (currentRates[n]?.out || 0), 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Traffic Analytics</h1>
          <p className="text-sm text-[var(--text-muted)]">Per-interface bandwidth monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
          </div>
        </div>
      </div>

      {/* Interface selector — multi-select chips */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-[var(--text-muted)] mr-1">Interfaces:</span>
        <button onClick={selectAll}
          className={`px-2.5 py-1 text-xs rounded-md border transition-colors ${allSelected ? "bg-blue-600/20 border-blue-500/40 text-blue-400" : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"}`}>
          All
        </button>
        {ifaceNames.map((iface, idx) => {
          const selected = !allSelected && selectedNics.has(iface.name);
          const c = IFACE_COLORS[idx % Object.keys(IFACE_COLORS).length];
          return (
            <button key={iface.name} onClick={() => toggleNic(iface.name)}
              className={`px-2.5 py-1 text-xs rounded-md border transition-colors ${selected ? "bg-blue-600/20 border-blue-500/40 text-blue-400" : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"}`}>
              <span className="inline-block w-2 h-2 rounded-full mr-1.5" style={{ backgroundColor: c.stroke }} />
              {iface.name}{iface.role ? ` (${iface.role})` : ""}
            </button>
          );
        })}
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total Rate In</div>
          <div className="text-xl font-bold text-green-400">{formatBps(totalIn)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total Rate Out</div>
          <div className="text-xl font-bold text-blue-400">{formatBps(totalOut)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Active Connections</div>
          <div className="text-xl font-bold text-cyan-400">{connections.length}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Interfaces</div>
          <div className="text-xl font-bold text-amber-400">{visibleNics.length}</div>
        </div>
      </div>

      {/* Per-interface graphs */}
      {visibleNics.map((nicName, idx) => {
        const c = IFACE_COLORS[ifaceNames.findIndex(i => i.name === nicName) % Object.keys(IFACE_COLORS).length];
        const iface = ifaceNames.find(i => i.name === nicName);
        const rate = currentRates[nicName];
        return (
          <div key={nicName} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: c.stroke }} />
                <h3 className="text-sm font-medium">{nicName}</h3>
                {iface?.role && <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700 text-gray-400">{iface.role}</span>}
                {rate && <span className="text-[10px] text-gray-500 ml-2">In: {formatBps(rate.in)} / Out: {formatBps(rate.out)}</span>}
              </div>
              <div className="flex items-center gap-4 text-xs">
                <span className="flex items-center gap-1.5"><span className="w-3 h-[3px] rounded-full inline-block" style={{ backgroundColor: c.stroke }} /> In</span>
                <span className="flex items-center gap-1.5"><span className="w-3 h-[3px] bg-blue-500 rounded-full inline-block" /> Out</span>
              </div>
            </div>
            <TrafficChart data={rateHistories[nicName] || []} height={160} color={c.stroke} />
            {iface && (
              <div className="flex gap-4 mt-2 text-[10px] text-[var(--text-muted)]">
                <span>Total In: {formatBytes(iface.bytes_in)} ({formatNumber(iface.packets_in)} pkts)</span>
                <span>Total Out: {formatBytes(iface.bytes_out)} ({formatNumber(iface.packets_out)} pkts)</span>
              </div>
            )}
          </div>
        );
      })}

      {/* Top Talkers + Top Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]"><h3 className="text-sm font-medium">Top Talkers</h3></div>
          {topTalkers.length === 0 ? <div className="text-center py-8 text-[var(--text-muted)] text-sm">No data</div> : (
            <div className="divide-y divide-[var(--border)]">{topTalkers.map((t, i) => (
              <div key={t.ip} className="px-4 py-2 hover:bg-[var(--bg-card-hover)]">
                <div className="flex justify-between mb-1"><span className="font-mono text-xs">{i + 1}. {t.ip}</span><span className="text-xs text-[var(--text-secondary)]">{formatBytes(t.bytes)} · {t.conns} conn</span></div>
                <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden"><div className="h-full rounded-full bg-cyan-500 transition-all" style={{ width: `${(t.bytes / maxTB) * 100}%` }} /></div>
              </div>
            ))}</div>
          )}
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]"><h3 className="text-sm font-medium">Top Ports</h3></div>
          {topPorts.length === 0 ? <div className="text-center py-8 text-[var(--text-muted)] text-sm">No data</div> : (
            <div className="divide-y divide-[var(--border)]">{topPorts.map(p => {
              const svc = portNames[p.port];
              const pc = p.proto === "tcp" ? "text-blue-400" : p.proto === "udp" ? "text-purple-400" : "text-gray-400";
              return (
                <div key={`${p.port}-${p.proto}`} className="px-3 py-1.5 hover:bg-[var(--bg-card-hover)] flex items-center gap-2">
                  <span className={`uppercase text-[10px] font-bold w-7 ${pc}`}>{p.proto}</span>
                  <span className="font-mono text-xs text-cyan-400 w-12 text-right">{p.port}</span>
                  {svc && <span className="text-[10px] text-[var(--text-muted)] w-16 truncate">{svc}</span>}
                  <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden"><div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${(p.conns / maxPC) * 100}%` }} /></div>
                  <span className="text-[10px] text-[var(--text-secondary)] w-8 text-right">{p.conns}</span>
                </div>
              );
            })}</div>
          )}
        </div>
      </div>
    </div>
  );
}
