"use client";

import { useEffect, useState, useRef, useCallback } from "react";

interface StatusData {
  pf_running: boolean; pf_states: number; pf_rules: number;
  aifw_rules: number; aifw_active_rules: number; nat_rules: number;
  packets_in: number; packets_out: number; bytes_in: number; bytes_out: number;
}

interface SystemData {
  cpu_usage: number; memory_total: number; memory_used: number; memory_pct: number;
  disks: { mount: string; filesystem: string; total: number; used: number; pct: number }[];
  uptime_secs: number; hostname: string; os_version: string;
  dns_servers: string[]; default_gateway: string; route_count: number;
}

interface Connection {
  protocol: string; src_addr: string; src_port: number;
  dst_addr: string; dst_port: number; state: string;
  bytes_in: number; bytes_out: number;
}

interface RatePoint { time: number; bpsIn: number; bpsOut: number; }

function formatBytes(b: number): string {
  if (b >= 1e12) return `${(b/1e12).toFixed(2)} TB`;
  if (b >= 1e9) return `${(b/1e9).toFixed(1)} GB`;
  if (b >= 1e6) return `${(b/1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB`;
  return `${b} B`;
}
function formatBps(b: number): string {
  if (b >= 1e9) return `${(b/1e9).toFixed(2)} Gbps`;
  if (b >= 1e6) return `${(b/1e6).toFixed(1)} Mbps`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} Kbps`;
  return `${b.toFixed(0)} bps`;
}
function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n/1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n/1e3).toFixed(1)}K`;
  return n.toLocaleString();
}
function formatUptime(secs: number): string {
  const d = Math.floor(secs/86400), h = Math.floor((secs%86400)/3600), m = Math.floor((secs%3600)/60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

// Usage gauge ring
function Gauge({ pct, label, color, size = 80 }: { pct: number; label: string; color: string; size?: number }) {
  const r = (size - 10) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (Math.min(pct, 100) / 100) * circ;
  const gaugeColor = pct > 90 ? "#ef4444" : pct > 70 ? "#f59e0b" : color;
  return (
    <div className="flex flex-col items-center">
      <div className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider mb-1">{label}</div>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke="#1e293b" strokeWidth="6" />
        <circle cx={size/2} cy={size/2} r={r} fill="none" stroke={gaugeColor} strokeWidth="6"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round" className="transition-all duration-500" />
      </svg>
      <div className="text-center -mt-[52px]">
        <div className="text-lg font-bold" style={{ color: gaugeColor }}>{pct.toFixed(0)}%</div>
      </div>
    </div>
  );
}

const MAX_PTS = 300;
function TrafficChart({ data, height = 140 }: { data: RatePoint[]; height?: number }) {
  if (data.length < 3) return <div className="flex items-center justify-center text-[var(--text-muted)] text-sm" style={{height}}>Collecting data...</div>;
  const w = 900, h2 = height, pad = { top: 8, right: 8, bottom: 4, left: 55 };
  const cW = w-pad.left-pad.right, cH = h2-pad.top-pad.bottom;
  const ppx = cW / MAX_PTS;
  const maxV = Math.max(...data.map(d => Math.max(d.bpsIn, d.bpsOut)), 1000);
  const sY = (v: number) => pad.top+cH-(v/maxV)*cH;
  const sX = pad.left+cW-data.length*ppx;
  const smooth = (pts: {x:number;y:number}[]) => {
    if (pts.length<2) return "";
    let d=`M ${pts[0].x},${pts[0].y}`;
    for (let i=0;i<pts.length-1;i++){const p0=pts[Math.max(0,i-1)],p1=pts[i],p2=pts[i+1],p3=pts[Math.min(pts.length-1,i+2)];d+=` C ${p1.x+(p2.x-p0.x)/6},${p1.y+(p2.y-p0.y)/6} ${p2.x-(p3.x-p1.x)/6},${p2.y-(p3.y-p1.y)/6} ${p2.x},${p2.y}`;}
    return d;
  };
  const inP = data.map((d,i)=>({x:sX+i*ppx,y:sY(d.bpsIn)}));
  const outP = data.map((d,i)=>({x:sX+i*ppx,y:sY(d.bpsOut)}));
  const inL=smooth(inP),outL=smooth(outP),bl=pad.top+cH;
  const inA=`${inL} L ${inP[inP.length-1].x},${bl} L ${inP[0].x},${bl} Z`;
  const outA=`${outL} L ${outP[outP.length-1].x},${bl} L ${outP[0].x},${bl} Z`;
  const yT=3,yL=Array.from({length:yT+1},(_,i)=>({y:sY((maxV/yT)*i),label:formatBps((maxV/yT)*i)}));
  return (
    <svg viewBox={`0 0 ${w} ${h2}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="gI" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22c55e" stopOpacity="0.4"/><stop offset="100%" stopColor="#22c55e" stopOpacity="0.02"/></linearGradient>
        <linearGradient id="gO" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35"/><stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02"/></linearGradient>
        <clipPath id="cc"><rect x={pad.left} y={pad.top} width={cW} height={cH}/></clipPath>
      </defs>
      {yL.map((t,i)=>(<g key={i}><line x1={pad.left} y1={t.y} x2={w-pad.right} y2={t.y} stroke="#1e293b"/><text x={pad.left-4} y={t.y+3} textAnchor="end" fill="#64748b" fontSize="9" fontFamily="monospace">{t.label}</text></g>))}
      <g clipPath="url(#cc)">
        <path d={inA} fill="url(#gI)"/><path d={outA} fill="url(#gO)"/>
        <path d={inL} fill="none" stroke="#22c55e" strokeWidth="1.5"/><path d={outL} fill="none" stroke="#3b82f6" strokeWidth="1.5"/>
        <circle cx={inP[inP.length-1].x} cy={inP[inP.length-1].y} r="2.5" fill="#22c55e"/>
        <circle cx={outP[outP.length-1].x} cy={outP[outP.length-1].y} r="2.5" fill="#3b82f6"/>
      </g>
    </svg>
  );
}

export default function Dashboard() {
  const [status, setStatus] = useState<StatusData|null>(null);
  const [system, setSystem] = useState<SystemData|null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [error, setError] = useState<string|null>(null);
  const [rateHistory, setRateHistory] = useState<RatePoint[]>([]);
  const [cpuHistory, setCpuHistory] = useState<number[]>([]);
  const [rateIn, setRateIn] = useState(0);
  const [rateOut, setRateOut] = useState(0);
  const prev = useRef<StatusData|null>(null);
  const prevT = useRef(0);
  const wsRef = useRef<WebSocket|null>(null);
  const reconRef = useRef<ReturnType<typeof setTimeout>|null>(null);

  const connectWs = useCallback(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws`);
    wsRef.current = ws;
    ws.onopen = () => { setWsConnected(true); setError(null); };
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type !== "status_update") return;
        const now = Date.now();
        setStatus(msg.status);
        setSystem(msg.system);
        setConnections(msg.connections || []);
        if (msg.system) setCpuHistory(h => [...h, msg.system.cpu_usage].slice(-60));
        if (prev.current && prevT.current) {
          const dt = (now - prevT.current) / 1000;
          if (dt > 0 && dt < 5) {
            const bi = Math.max(0, (msg.status.bytes_in - prev.current.bytes_in) / dt * 8);
            const bo = Math.max(0, (msg.status.bytes_out - prev.current.bytes_out) / dt * 8);
            setRateIn(bi); setRateOut(bo);
            setRateHistory(h => [...h, { time: now, bpsIn: bi, bpsOut: bo }].slice(-300));
          }
        }
        prev.current = msg.status; prevT.current = now;
      } catch {}
    };
    ws.onclose = () => { setWsConnected(false); reconRef.current = setTimeout(connectWs, 3000); };
    ws.onerror = () => { setError("WebSocket failed"); ws.close(); };
  }, []);

  useEffect(() => { connectWs(); return () => { wsRef.current?.close(); if (reconRef.current) clearTimeout(reconRef.current); }; }, [connectWs]);

  const topTalkers = connections.reduce<{ip:string;bytes:number;conns:number}[]>((a,c) => {
    const e = a.find(t=>t.ip===c.src_addr), tot=c.bytes_in+c.bytes_out;
    if(e){e.bytes+=tot;e.conns++}else a.push({ip:c.src_addr,bytes:tot,conns:1});
    return a;
  },[]).sort((a,b)=>b.bytes-a.bytes).slice(0,5);
  const mtb = topTalkers[0]?.bytes||1;

  if (!status) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"/>
        <p className="text-sm text-[var(--text-muted)]">Connecting to firewall...</p>
      </div>
    </div>
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{system?.hostname || "Dashboard"}</h1>
          <p className="text-sm text-[var(--text-muted)]">{system?.os_version} · Uptime {formatUptime(system?.uptime_secs ?? 0)}</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${wsConnected ? "bg-green-500 animate-pulse" : "bg-red-500"}`}/>
            <span className="text-xs text-[var(--text-muted)]">{wsConnected ? "Live" : "Reconnecting..."}</span>
          </div>
          <div className={`px-2 py-1 rounded text-xs font-medium ${status.pf_running ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
            pf {status.pf_running ? "Active" : "Inactive"}
          </div>
        </div>
      </div>
      {error && <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400">{error}</div>}

      {/* System Gauges + Rates */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 flex justify-center">
          <Gauge pct={system?.cpu_usage ?? 0} label="CPU" color="#3b82f6" size={76}/>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 flex justify-center">
          <Gauge pct={system?.memory_pct ?? 0} label="Memory" color="#8b5cf6" size={76}/>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 flex justify-center">
          <Gauge pct={system?.disks?.[0]?.pct ?? 0} label="Disk" color="#06b6d4" size={76}/>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Throughput In</div>
          <div className="text-xl font-bold text-green-400">{formatBps(rateIn)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatBytes(status.bytes_in)} total</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Throughput Out</div>
          <div className="text-xl font-bold text-blue-400">{formatBps(rateOut)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatBytes(status.bytes_out)} total</div>
        </div>
      </div>

      {/* Traffic Graph */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
        <div className="flex items-center justify-between mb-1">
          <h3 className="text-xs font-medium text-[var(--text-muted)] uppercase">Network Throughput</h3>
          <div className="flex items-center gap-3 text-[10px]">
            <span className="flex items-center gap-1"><span className="w-2.5 h-[2px] bg-green-500 inline-block rounded"/> In</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-[2px] bg-blue-500 inline-block rounded"/> Out</span>
          </div>
        </div>
        <TrafficChart data={rateHistory} height={140}/>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-2">
        {[
          { label: "PF Rules", value: status.pf_rules, color: "#f59e0b" },
          { label: "Managed", value: status.aifw_active_rules, color: "#3b82f6" },
          { label: "NAT", value: status.nat_rules, color: "#8b5cf6" },
          { label: "States", value: formatNumber(status.pf_states), color: "#06b6d4" },
          { label: "Packets", value: formatNumber(status.packets_in + status.packets_out), color: "#22c55e" },
          { label: "Conns", value: connections.length, color: "#f97316" },
        ].map(s => (
          <div key={s.label} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg px-3 py-2 text-center">
            <div className="text-[10px] text-[var(--text-muted)] uppercase">{s.label}</div>
            <div className="text-base font-bold" style={{color: s.color}}>{s.value}</div>
          </div>
        ))}
      </div>

      {/* System Info + Network */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Memory & Disk */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-xs font-medium text-[var(--text-muted)] uppercase mb-2">Resources</h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Memory</span><span>{formatBytes(system?.memory_used??0)} / {formatBytes(system?.memory_total??0)}</span></div>
            {system?.disks?.map(d => (
              <div key={d.mount}>
                <div className="flex justify-between"><span className="text-[var(--text-muted)]">{d.mount}</span><span>{formatBytes(d.used)} / {formatBytes(d.total)}</span></div>
                <div className="w-full h-1 bg-gray-700 rounded-full mt-0.5"><div className="h-full rounded-full bg-cyan-500 transition-all" style={{width:`${d.pct}%`}}/></div>
              </div>
            ))}
          </div>
        </div>

        {/* Network / Routing */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-xs font-medium text-[var(--text-muted)] uppercase mb-2">Network</h3>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Gateway</span><span className="font-mono">{system?.default_gateway || "—"}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Routes</span><span>{system?.route_count ?? 0}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">PF States</span><span>{formatNumber(status.pf_states)}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Connections</span><span>{connections.length}</span></div>
          </div>
        </div>

        {/* DNS */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-xs font-medium text-[var(--text-muted)] uppercase mb-2">DNS</h3>
          <div className="space-y-1 text-xs">
            {system?.dns_servers?.length ? system.dns_servers.map((s, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-green-500"/>
                <span className="font-mono">{s}</span>
              </div>
            )) : <span className="text-[var(--text-muted)]">No DNS configured</span>}
          </div>
        </div>
      </div>

      {/* Bottom Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-3 py-2 border-b border-[var(--border)]"><h3 className="text-xs font-medium">Top Talkers</h3></div>
          {topTalkers.length===0 ? <div className="text-center py-6 text-[var(--text-muted)] text-sm">No connections</div> : (
            <div className="divide-y divide-[var(--border)]">
              {topTalkers.map(t => (
                <div key={t.ip} className="px-3 py-2 hover:bg-[var(--bg-card-hover)]">
                  <div className="flex justify-between mb-1"><span className="font-mono text-xs">{t.ip}</span><span className="text-[10px] text-[var(--text-secondary)]">{formatBytes(t.bytes)} · {t.conns}</span></div>
                  <div className="w-full h-1 bg-gray-700 rounded-full"><div className="h-full rounded-full bg-cyan-500 transition-all" style={{width:`${(t.bytes/mtb)*100}%`}}/></div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Connections */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-3 py-2 border-b border-[var(--border)]"><h3 className="text-xs font-medium">Connections ({connections.length})</h3></div>
          <div className="overflow-y-auto max-h-52">
            {connections.length===0 ? <div className="text-center py-6 text-[var(--text-muted)] text-sm">No connections</div> : (
              <table className="w-full text-[11px]">
                <thead><tr className="border-b border-[var(--border)]">
                  <th className="text-left py-1.5 px-2 text-[var(--text-muted)] uppercase text-[9px]">Proto</th>
                  <th className="text-left py-1.5 px-2 text-[var(--text-muted)] uppercase text-[9px]">Source</th>
                  <th className="text-left py-1.5 px-2 text-[var(--text-muted)] uppercase text-[9px]">Destination</th>
                  <th className="text-left py-1.5 px-2 text-[var(--text-muted)] uppercase text-[9px]">State</th>
                </tr></thead>
                <tbody>{connections.slice(0,15).map((c,i) => (
                  <tr key={i} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)]">
                    <td className="py-1 px-2 uppercase text-cyan-400">{c.protocol}</td>
                    <td className="py-1 px-2 font-mono">{c.src_addr}:{c.src_port}</td>
                    <td className="py-1 px-2 font-mono">{c.dst_addr}:{c.dst_port}</td>
                    <td className="py-1 px-2 text-[var(--text-secondary)]">{c.state.split(":")[0]}</td>
                  </tr>
                ))}</tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
