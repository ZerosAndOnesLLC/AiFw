"use client";

import { useEffect, useState, useRef, useMemo } from "react";
import { useWs } from "@/context/WsContext";

interface StatusData {
  pf_running: boolean; pf_states: number; pf_rules: number;
  aifw_rules: number; aifw_active_rules: number; nat_rules: number;
  packets_in: number; packets_out: number; bytes_in: number; bytes_out: number;
}
interface SystemData {
  cpu_usage: number; memory_total: number; memory_used: number; memory_pct: number;
  disks: { mount: string; filesystem: string; total: number; used: number; pct: number }[];
  disk_io: { reads_per_sec: number; writes_per_sec: number; read_kbps: number; write_kbps: number };
  uptime_secs: number; hostname: string; os_version: string;
  dns_servers: string[]; default_gateway: string; route_count: number;
}
interface Connection {
  protocol: string; src_addr: string; src_port: number;
  dst_addr: string; dst_port: number; state: string;
  bytes_in: number; bytes_out: number;
}
interface HistoryPoint {
  time: number; cpu: number; memPct: number;
  diskReadKbps: number; diskWriteKbps: number;
  bpsIn: number; bpsOut: number;
}

interface InterfaceEntry {
  name: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
}

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
function formatUptime(s: number): string {
  const d=Math.floor(s/86400),h=Math.floor((s%86400)/3600),m=Math.floor((s%3600)/60);
  if(d>0) return `${d}d ${h}h`; if(h>0) return `${h}h ${m}m`; return `${m}m`;
}

const MAX_PTS = 300;
const SVG_W = 900;

interface ChartLine { key: string; color: string; label: string; }

function StackedChart({ data, getValue, lines, maxValue, formatY, title, height = 100, hoverIdx, onHover }: {
  data: HistoryPoint[]; getValue: (d: HistoryPoint, key: string) => number;
  lines: ChartLine[]; maxValue?: number; formatY: (v: number) => string;
  title: string; height?: number; hoverIdx: number | null; onHover: (idx: number | null) => void;
}) {
  const svgRef = useRef<SVGSVGElement>(null);
  if (data.length < 3) return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-2">
      <div className="flex items-center justify-between px-1 mb-1">
        <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">{title}</span>
        <div className="flex gap-3">{lines.map(l => (
          <span key={l.key} className="flex items-center gap-1 text-[10px]">
            <span className="w-2 h-[2px] rounded inline-block" style={{backgroundColor:l.color}}/>{l.label}
          </span>
        ))}</div>
      </div>
      <div className="flex items-center justify-center text-[var(--text-muted)] text-xs" style={{height}}>Collecting...</div>
    </div>
  );

  const h = height, pad = { top: 4, right: 4, bottom: 2, left: 44 };
  const cW = SVG_W-pad.left-pad.right, cH = h-pad.top-pad.bottom;
  const ppx = cW/MAX_PTS;
  const allVals = data.flatMap(d => lines.map(l => getValue(d, l.key)));
  const maxV = maxValue ?? Math.max(...allVals, 1);
  const sY = (v: number) => pad.top+cH-(v/maxV)*cH;
  const startX = pad.left+cW-data.length*ppx;

  const smooth = (pts:{x:number;y:number}[]) => {
    if(pts.length<2) return "";
    let d=`M ${pts[0].x},${pts[0].y}`;
    for(let i=0;i<pts.length-1;i++){
      const p0=pts[Math.max(0,i-1)],p1=pts[i],p2=pts[i+1],p3=pts[Math.min(pts.length-1,i+2)];
      d+=` C ${p1.x+(p2.x-p0.x)/6},${p1.y+(p2.y-p0.y)/6} ${p2.x-(p3.x-p1.x)/6},${p2.y-(p3.y-p1.y)/6} ${p2.x},${p2.y}`;
    }
    return d;
  };

  const lineData = lines.map(l => {
    const pts = data.map((d,i)=>({x:startX+i*ppx,y:sY(getValue(d,l.key))}));
    const path = smooth(pts);
    const bl = pad.top+cH;
    const area = `${path} L ${pts[pts.length-1].x},${bl} L ${pts[0].x},${bl} Z`;
    return { ...l, pts, path, area };
  });

  const yTicks = 3;
  const yLabels = Array.from({length:yTicks+1},(_,i)=>({y:sY((maxV/yTicks)*i),label:formatY((maxV/yTicks)*i)}));

  const handleMouse = (e: React.MouseEvent<SVGSVGElement>) => {
    const svg = svgRef.current; if(!svg) return;
    const rect = svg.getBoundingClientRect();
    const xRatio = (e.clientX - rect.left) / rect.width;
    const svgX = xRatio * SVG_W;
    const idx = Math.round((svgX - startX) / ppx);
    if (idx >= 0 && idx < data.length) onHover(idx);
    else onHover(null);
  };

  const hoverX = hoverIdx !== null ? startX + hoverIdx * ppx : null;

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-2">
      <div className="flex items-center justify-between px-1 mb-0.5">
        <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">{title}</span>
        <div className="flex gap-3">
          {hoverIdx !== null && data[hoverIdx] ? (
            lines.map(l => (
              <span key={l.key} className="text-[10px] font-mono" style={{color:l.color}}>
                {l.label}: {formatY(getValue(data[hoverIdx], l.key))}
              </span>
            ))
          ) : (
            lines.map(l => (
              <span key={l.key} className="flex items-center gap-1 text-[10px]">
                <span className="w-2 h-[2px] rounded inline-block" style={{backgroundColor:l.color}}/>{l.label}
              </span>
            ))
          )}
        </div>
      </div>
      <svg ref={svgRef} viewBox={`0 0 ${SVG_W} ${h}`} className="w-full cursor-crosshair" preserveAspectRatio="xMidYMid meet"
        onMouseMove={handleMouse} onMouseLeave={() => onHover(null)}>
        <defs>
          {lineData.map(l => (
            <linearGradient key={l.key} id={`g-${l.key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={l.color} stopOpacity="0.35"/><stop offset="100%" stopColor={l.color} stopOpacity="0.02"/>
            </linearGradient>
          ))}
          <clipPath id={`clip-${title.replace(/\s/g,'')}`}><rect x={pad.left} y={pad.top} width={cW} height={cH}/></clipPath>
        </defs>
        {yLabels.map((t,i)=>(<g key={i}><line x1={pad.left} y1={t.y} x2={SVG_W-pad.right} y2={t.y} stroke="#1e293b"/>
          <text x={pad.left-3} y={t.y+3} textAnchor="end" fill="#475569" fontSize="8" fontFamily="monospace">{t.label}</text></g>))}
        <g clipPath={`url(#clip-${title.replace(/\s/g,'')})`}>
          {lineData.map(l => (<g key={l.key}>
            <path d={l.area} fill={`url(#g-${l.key})`}/>
            <path d={l.path} fill="none" stroke={l.color} strokeWidth="1.5"/>
            <circle cx={l.pts[l.pts.length-1].x} cy={l.pts[l.pts.length-1].y} r="2" fill={l.color}/>
          </g>))}
          {hoverX !== null && <line x1={hoverX} y1={pad.top} x2={hoverX} y2={pad.top+cH} stroke="#94a3b8" strokeWidth="1" strokeDasharray="3,2"/>}
          {hoverIdx !== null && lineData.map(l => l.pts[hoverIdx] ? (
            <circle key={l.key} cx={l.pts[hoverIdx].x} cy={l.pts[hoverIdx].y} r="3" fill={l.color} stroke="#0f172a" strokeWidth="1.5"/>
          ) : null)}
        </g>
      </svg>
    </div>
  );
}

export default function Dashboard() {
  const ws = useWs();

  const status = ws.status as StatusData | null;
  const system = ws.system as SystemData | null;
  const connections = (ws.connections || []) as unknown as Connection[];
  const ifaces = (ws.interfaces || []) as unknown as InterfaceEntry[];
  const services = (ws.services || []) as unknown as { name: string; running: boolean; enabled: boolean }[];

  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [rateIn, setRateIn] = useState(0);
  const [rateOut, setRateOut] = useState(0);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [selectedNic, setSelectedNic] = useState(() =>
    typeof window !== "undefined" ? localStorage.getItem("aifw_dashboard_nic") || "" : ""
  );

  const selectedNicRef = useRef(selectedNic);
  const prevIfaceData = useRef<Record<string, { bytes_in: number; bytes_out: number }>>({});
  const prevT = useRef(0);
  const historyProcessed = useRef(false);
  const lastHistoryLen = useRef(0);

  const pickNic = (name: string) => {
    setSelectedNic(name);
    selectedNicRef.current = name;
    localStorage.setItem("aifw_dashboard_nic", name);
  };

  // Process history from context on mount / when history changes
  useEffect(() => {
    if (!ws.historyLoaded || ws.history.length === 0) return;
    // Only reprocess full history once, or when NIC changes
    if (historyProcessed.current && ws.history.length === lastHistoryLen.current) return;

    const rawHistory = ws.history as Record<string, unknown>[];
    const points: HistoryPoint[] = [];
    const prevByIf: Record<string, { bytes_in: number; bytes_out: number }> = {};
    let prevTs = 0;
    let nic = selectedNicRef.current;

    for (let idx = 0; idx < rawHistory.length; idx++) {
      const entry = rawHistory[idx];
      if ((entry as { type?: string }).type !== "status_update") continue;
      const ts = Date.now() - (rawHistory.length - idx) * 1000;
      const entryIfaces = ((entry as { interfaces?: InterfaceEntry[] }).interfaces || []) as InterfaceEntry[];
      if (!nic && entryIfaces.length > 0) nic = entryIfaces[0].name;

      const curIf = entryIfaces.find(i => i.name === nic);
      const prevIf = prevByIf[nic || ""];
      let bi = 0, bo = 0;
      if (curIf && prevIf && prevTs) {
        const dt = (ts - prevTs) / 1000;
        if (dt > 0 && dt < 5) {
          bi = Math.max(0, (curIf.bytes_in - prevIf.bytes_in) / dt * 8);
          bo = Math.max(0, (curIf.bytes_out - prevIf.bytes_out) / dt * 8);
        }
      }
      if (curIf && nic) prevByIf[nic] = { bytes_in: curIf.bytes_in, bytes_out: curIf.bytes_out };
      prevTs = ts;

      const entrySys = (entry as { system?: SystemData }).system;
      points.push({
        time: ts,
        cpu: entrySys?.cpu_usage ?? 0,
        memPct: entrySys?.memory_pct ?? 0,
        diskReadKbps: entrySys?.disk_io?.read_kbps ?? 0,
        diskWriteKbps: entrySys?.disk_io?.write_kbps ?? 0,
        bpsIn: bi,
        bpsOut: bo,
      });
    }

    if (!selectedNicRef.current && nic) pickNic(nic);
    Object.assign(prevIfaceData.current, prevByIf);
    prevT.current = Date.now();
    lastHistoryLen.current = ws.history.length;
    historyProcessed.current = true;
    setHistory(points.slice(-MAX_PTS));
  }, [ws.historyLoaded, ws.history, ws.history.length]);

  // Reset history processing when NIC changes so it recomputes rates
  useEffect(() => {
    if (historyProcessed.current) {
      historyProcessed.current = false;
      lastHistoryLen.current = 0;
    }
  }, [selectedNic]);

  // Process live updates from ws.status/ws.interfaces changes
  useEffect(() => {
    if (!status || !historyProcessed.current) return;

    const now = Date.now();
    const nic = selectedNicRef.current || (ifaces[0]?.name ?? "");
    const curIface = ifaces.find(i => i.name === nic);
    const prevIfData = prevIfaceData.current[nic];

    let bIn = 0, bOut = 0;
    if (curIface && prevIfData && prevT.current) {
      const dt = (now - prevT.current) / 1000;
      if (dt > 0 && dt < 5) {
        bIn = Math.max(0, (curIface.bytes_in - prevIfData.bytes_in) / dt * 8);
        bOut = Math.max(0, (curIface.bytes_out - prevIfData.bytes_out) / dt * 8);
        setRateIn(bIn);
        setRateOut(bOut);
      }
    }
    if (curIface) prevIfaceData.current[nic] = { bytes_in: curIface.bytes_in, bytes_out: curIface.bytes_out };
    prevT.current = now;

    if (!selectedNicRef.current && ifaces.length > 0) pickNic(ifaces[0].name);

    setHistory(h => [...h, {
      time: now,
      cpu: system?.cpu_usage ?? 0,
      memPct: system?.memory_pct ?? 0,
      diskReadKbps: system?.disk_io?.read_kbps ?? 0,
      diskWriteKbps: system?.disk_io?.write_kbps ?? 0,
      bpsIn: bIn,
      bpsOut: bOut,
    }].slice(-MAX_PTS));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ws.status]);

  const interfaceList = useMemo(() =>
    ifaces.map(i => ({ name: i.name })),
    [ifaces]
  );

  const topTalkers = connections.reduce<{ip:string;bytes:number;conns:number}[]>((a,c) => {
    const e=a.find(t=>t.ip===c.src_addr),tot=c.bytes_in+c.bytes_out;
    if(e){e.bytes+=tot;e.conns++}else a.push({ip:c.src_addr,bytes:tot,conns:1});return a;
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
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">{system?.hostname || "Dashboard"}</h1>
          <p className="text-sm text-[var(--text-muted)]">{system?.os_version} · Up {formatUptime(system?.uptime_secs ?? 0)}</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`}/>
            <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
          </div>
          {interfaceList.length > 0 && (
            <select value={selectedNic} onChange={(e) => pickNic(e.target.value)}
              className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-blue-500">
              {interfaceList.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
            </select>
          )}
          <div className={`px-2 py-1 rounded text-xs font-medium ${status.pf_running ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
            pf {status.pf_running ? "Active" : "Inactive"}
          </div>
        </div>
      </div>

      {/* Summary Stats Row */}
      <div className="grid grid-cols-4 md:grid-cols-8 gap-2">
        {[
          { l:`CPU (${(system as Record<string,unknown>)?.cpu_cores ?? "?"}c)`, v:`${(system?.cpu_usage??0).toFixed(0)}%`, c: (system?.cpu_usage??0) > 80 ? "#ef4444" : "#3b82f6" },
          { l:"Memory", v:`${(system?.memory_pct??0).toFixed(0)}%`, c: (system?.memory_pct??0) > 80 ? "#ef4444" : "#8b5cf6" },
          { l:"Disk", v:`${(system?.disks?.[0]?.pct??0).toFixed(0)}%`, c: (system?.disks?.[0]?.pct??0) > 90 ? "#ef4444" : "#06b6d4" },
          { l:"In", v:formatBps(rateIn), c:"#22c55e" },
          { l:"Out", v:formatBps(rateOut), c:"#3b82f6" },
          { l:"States", v:formatNumber(status.pf_states), c:"#06b6d4" },
          { l:"Rules", v:`${status.pf_rules}`, c:"#f59e0b" },
          { l:"Conns", v:`${connections.length}`, c:"#f97316" },
        ].map(s => (
          <div key={s.l} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg px-2 py-1.5 text-center">
            <div className="text-[9px] text-[var(--text-muted)] uppercase">{s.l}</div>
            <div className="text-sm font-bold" style={{color:s.c}}>{s.v}</div>
          </div>
        ))}
      </div>

      {/* Service Health — only enabled services */}
      {services.filter(s => s.enabled).length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {services.filter(s => s.enabled).map(svc => (
            <div key={svc.name} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg px-3 py-2 flex items-center justify-between">
              <span className="text-xs font-medium">{svc.name}</span>
              <span className={`text-[10px] px-2 py-0.5 rounded-full ${svc.running ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
                {svc.running ? "Running" : "Stopped"}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Stacked Graphs — all share hoverIdx for time-aligned tooltip */}
      <StackedChart data={history} title="CPU" height={90} hoverIdx={hoverIdx} onHover={setHoverIdx}
        lines={[{key:"cpu",color:"#3b82f6",label:"CPU"}]}
        getValue={(d,k) => k==="cpu" ? d.cpu : 0}
        maxValue={100} formatY={v => `${v.toFixed(0)}%`}
      />
      <StackedChart data={history} title="Memory" height={90} hoverIdx={hoverIdx} onHover={setHoverIdx}
        lines={[{key:"mem",color:"#8b5cf6",label:"Memory"}]}
        getValue={(d,k) => k==="mem" ? d.memPct : 0}
        maxValue={100} formatY={v => `${v.toFixed(0)}%`}
      />
      <StackedChart data={history} title="Disk I/O" height={90} hoverIdx={hoverIdx} onHover={setHoverIdx}
        lines={[{key:"read",color:"#22c55e",label:"Read"},{key:"write",color:"#f97316",label:"Write"}]}
        getValue={(d,k) => k==="read" ? d.diskReadKbps : d.diskWriteKbps}
        formatY={v => v >= 1024 ? `${(v/1024).toFixed(0)} MB/s` : `${v.toFixed(0)} KB/s`}
      />
      <StackedChart data={history} title="Network" height={110} hoverIdx={hoverIdx} onHover={setHoverIdx}
        lines={[{key:"in",color:"#22c55e",label:"In"},{key:"out",color:"#3b82f6",label:"Out"}]}
        getValue={(d,k) => k==="in" ? d.bpsIn : d.bpsOut}
        formatY={formatBps}
      />

      {/* System Info Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {/* Memory */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase mb-2">Memory</h3>
          <div className="space-y-1.5 text-xs">
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Used</span><span>{formatBytes(system?.memory_used??0)} / {formatBytes(system?.memory_total??0)}</span></div>
            <div className="w-full h-1.5 bg-gray-700 rounded-full"><div className="h-full rounded-full transition-all" style={{width:`${system?.memory_pct??0}%`,backgroundColor:(system?.memory_pct??0)>80?"#ef4444":"#8b5cf6"}}/></div>
          </div>
        </div>
        {/* Disk / Mounts */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase mb-2">Disk</h3>
          <div className="space-y-1.5 text-xs">
            {system?.disks?.map(d => (
              <div key={d.mount}>
                <div className="flex justify-between"><span className="text-[var(--text-muted)] font-mono">{d.mount}</span><span>{d.pct.toFixed(0)}% ({formatBytes(d.used)})</span></div>
                <div className="w-full h-1 bg-gray-700 rounded-full mt-0.5"><div className="h-full rounded-full transition-all" style={{width:`${d.pct}%`,backgroundColor:d.pct>80?"#ef4444":"#06b6d4"}}/></div>
              </div>
            ))}
          </div>
        </div>
        {/* Network */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase mb-2">Network</h3>
          <div className="space-y-1 text-xs">
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">GW</span><span className="font-mono text-[10px]">{system?.default_gateway||"—"}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">DNS</span><span className="font-mono text-[10px]">{system?.dns_servers?.join(", ")||"—"}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">In / Out</span><span>{formatBytes(status.bytes_in)} / {formatBytes(status.bytes_out)}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Packets</span><span>{formatNumber(status.packets_in+status.packets_out)} ({system?.route_count??0} routes)</span></div>
          </div>
        </div>
        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase mb-2">Top Talkers</h3>
          {topTalkers.length===0 ? <div className="text-xs text-[var(--text-muted)]">No connections</div> : (
            <div className="space-y-1.5">
              {topTalkers.map(t => (
                <div key={t.ip}>
                  <div className="flex justify-between text-xs"><span className="font-mono text-[10px]">{t.ip}</span><span className="text-[var(--text-muted)]">{formatBytes(t.bytes)}</span></div>
                  <div className="w-full h-1 bg-gray-700 rounded-full mt-0.5"><div className="h-full rounded-full bg-cyan-500 transition-all" style={{width:`${(t.bytes/mtb)*100}%`}}/></div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Connections Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-3 py-2 border-b border-[var(--border)]"><h3 className="text-xs font-medium">Connections ({connections.length})</h3></div>
        <div className="overflow-y-auto max-h-48">
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
  );
}
