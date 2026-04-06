"use client";

import { useEffect, useState, useRef, useMemo } from "react";
import { useWs } from "@/context/WsContext";

interface StatusData {
  pf_running: boolean; pf_states: number; pf_rules: number;
  aifw_rules: number; aifw_active_rules: number; nat_rules: number;
  packets_in: number; packets_out: number; bytes_in: number; bytes_out: number;
}
interface SystemData {
  cpu_usage: number; cpu_cores: number; memory_total: number; memory_used: number; memory_pct: number;
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
        {yLabels.map((t,i)=>(<g key={i}><line x1={pad.left} y1={t.y} x2={SVG_W-pad.right} y2={t.y} stroke="#334155"/>
          <text x={pad.left-3} y={t.y+3} textAnchor="end" fill="#94a3b8" fontSize="8" fontFamily="monospace">{t.label}</text></g>))}
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
    if (!ws.historyLoaded) return;
    if (ws.history.length === 0) { historyProcessed.current = true; return; }
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

  const blocked = (ws.blocked || []) as unknown as { timestamp: string; action: string; direction: string; interface: string; protocol: string; src_addr: string; src_port: number; dst_addr: string; dst_port: number }[];

  const topTalkers = connections.reduce<{ip:string;bytes:number;conns:number}[]>((a,c) => {
    const e=a.find(t=>t.ip===c.src_addr),tot=c.bytes_in+c.bytes_out;
    if(e){e.bytes+=tot;e.conns++}else a.push({ip:c.src_addr,bytes:tot,conns:1});return a;
  },[]).sort((a,b)=>b.bytes-a.bytes).slice(0,5);
  const mtb = topTalkers[0]?.bytes||1;

  const healthColors = { critical: "border-red-500/50 bg-red-500/5", warning: "border-yellow-500/50 bg-yellow-500/5", healthy: "border-green-500/30 bg-green-500/5" } as const;
  const healthDot = { critical: "bg-red-500", warning: "bg-yellow-500", healthy: "bg-green-500" } as const;
  const healthTextCls = { critical: "text-red-400", warning: "text-yellow-400", healthy: "text-green-400" } as const;

  if (!status) return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3"/>
        <p className="text-sm text-[var(--text-muted)]">Connecting to firewall...</p>
      </div>
    </div>
  );

  // Compute overall health (after null check)
  const cpu = system?.cpu_usage ?? 0;
  const mem = system?.memory_pct ?? 0;
  const disk = system?.disks?.[0]?.pct ?? 0;
  const svcDown = services.filter(s => s.enabled && !s.running).length;
  const healthLevel: "critical" | "warning" | "healthy" = (!status.pf_running || svcDown > 0) ? "critical"
    : (cpu > 90 || mem > 90 || disk > 95) ? "critical"
    : (cpu > 70 || mem > 70 || disk > 80) ? "warning"
    : "healthy";
  const healthLabel = healthLevel === "critical" ? "Attention Required" : healthLevel === "warning" ? "Degraded" : "All Systems Operational";

  return (
    <div className="space-y-4">
      {/* Header + Health Banner */}
      <div className={`rounded-lg border p-3 sm:p-4 ${healthColors[healthLevel]}`}>
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full ${healthDot[healthLevel]} ${healthLevel === "healthy" ? "animate-pulse" : ""}`} />
            <div>
              <h1 className="text-xl font-bold">{system?.hostname || "AiFw"}</h1>
              <p className="text-xs text-[var(--text-muted)]">{system?.os_version} · Up {formatUptime(system?.uptime_secs ?? 0)}</p>
            </div>
            <span className={`text-xs font-medium ${healthTextCls[healthLevel]}`}>{healthLabel}</span>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
              <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
            </div>
            {interfaceList.length > 0 && (
              <select value={selectedNic} onChange={(e) => pickNic(e.target.value)}
                className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
                {interfaceList.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
              </select>
            )}
            <div className={`px-2 py-1 rounded text-xs font-medium ${status.pf_running ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
              pf {status.pf_running ? "Active" : "Inactive"}
            </div>
          </div>
        </div>
      </div>

      {/* Stats Grid — 3 groups */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* System Resources */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-3">System</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-center">
            {[
              { l: `CPU (${system?.cpu_cores ?? "?"}c)`, v: `${cpu.toFixed(0)}%`, c: cpu > 80 ? "#ef4444" : "#3b82f6", pct: cpu },
              { l: "Memory", v: `${mem.toFixed(0)}%`, c: mem > 80 ? "#ef4444" : "#8b5cf6", pct: mem },
              { l: "Disk", v: `${disk.toFixed(0)}%`, c: disk > 90 ? "#ef4444" : "#06b6d4", pct: disk },
            ].map(s => (
              <div key={s.l}>
                <div className="text-[9px] text-[var(--text-muted)] uppercase">{s.l}</div>
                <div className="text-lg font-bold mt-0.5" style={{ color: s.c }}>{s.v}</div>
                <div className="w-full h-1 bg-gray-700 rounded-full mt-1">
                  <div className="h-full rounded-full transition-all" style={{ width: `${s.pct}%`, backgroundColor: s.c }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Network Throughput */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-3">Throughput</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-center">
            <div>
              <div className="text-[9px] text-[var(--text-muted)] uppercase">Inbound</div>
              <div className="text-lg font-bold text-green-400 mt-0.5">{formatBps(rateIn)}</div>
              <div className="text-[10px] text-[var(--text-muted)] mt-0.5">{formatBytes(status.bytes_in)} total</div>
            </div>
            <div>
              <div className="text-[9px] text-[var(--text-muted)] uppercase">Outbound</div>
              <div className="text-lg font-bold text-blue-400 mt-0.5">{formatBps(rateOut)}</div>
              <div className="text-[10px] text-[var(--text-muted)] mt-0.5">{formatBytes(status.bytes_out)} total</div>
            </div>
          </div>
        </div>

        {/* Firewall Stats */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-3">Firewall</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-2 text-xs">
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">PF States</span><span className="font-mono font-bold text-cyan-400">{formatNumber(status.pf_states)}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">PF Rules</span><span className="font-mono font-bold text-yellow-400">{status.pf_rules}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">AiFw Rules</span><span className="font-mono font-bold text-blue-400">{status.aifw_active_rules}/{status.aifw_rules}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">NAT Rules</span><span className="font-mono font-bold text-purple-400">{status.nat_rules}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Connections</span><span className="font-mono font-bold text-orange-400">{connections.length}</span></div>
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Blocked</span><span className="font-mono font-bold text-red-400">{blocked.length}</span></div>
          </div>
        </div>
      </div>

      {/* Services */}
      {services.length > 0 && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-3">Services</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-2">
            {services.map(svc => (
              <div key={svc.name} className={`flex items-center gap-2 px-3 py-2 rounded-md border ${
                !svc.enabled ? "border-[var(--border)] opacity-50"
                  : svc.running ? "border-green-500/20 bg-green-500/5"
                  : "border-red-500/20 bg-red-500/5"
              }`}>
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                  !svc.enabled ? "bg-gray-500" : svc.running ? "bg-green-500" : "bg-red-500"
                }`} />
                <span className="text-xs font-medium truncate">{svc.name}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Charts — 2x2 grid on desktop */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <StackedChart data={history} title="CPU" height={100} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "cpu", color: "#3b82f6", label: "CPU" }]}
          getValue={(d, k) => k === "cpu" ? d.cpu : 0}
          maxValue={100} formatY={v => `${v.toFixed(0)}%`}
        />
        <StackedChart data={history} title="Memory" height={100} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "mem", color: "#8b5cf6", label: "Memory" }]}
          getValue={(d, k) => k === "mem" ? d.memPct : 0}
          maxValue={100} formatY={v => `${v.toFixed(0)}%`}
        />
        <StackedChart data={history} title="Disk I/O" height={100} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "read", color: "#22c55e", label: "Read" }, { key: "write", color: "#f97316", label: "Write" }]}
          getValue={(d, k) => k === "read" ? d.diskReadKbps : d.diskWriteKbps}
          formatY={v => v >= 1024 ? `${(v / 1024).toFixed(0)} MB/s` : `${v.toFixed(0)} KB/s`}
        />
        <StackedChart data={history} title="Network" height={100} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "in", color: "#22c55e", label: "In" }, { key: "out", color: "#3b82f6", label: "Out" }]}
          getValue={(d, k) => k === "in" ? d.bpsIn : d.bpsOut}
          formatY={formatBps}
        />
      </div>

      {/* Bottom grid — 3 columns */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* System Details */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-3">System Details</h3>
          <div className="space-y-2 text-xs">
            <div className="flex justify-between"><span className="text-[var(--text-muted)]">Memory</span><span>{formatBytes(system?.memory_used ?? 0)} / {formatBytes(system?.memory_total ?? 0)}</span></div>
            <div className="w-full h-1 bg-gray-700 rounded-full"><div className="h-full rounded-full transition-all" style={{ width: `${mem}%`, backgroundColor: mem > 80 ? "#ef4444" : "#8b5cf6" }} /></div>
            {system?.disks?.map(d => (
              <div key={d.mount}>
                <div className="flex justify-between"><span className="text-[var(--text-muted)] font-mono">{d.mount}</span><span>{d.pct.toFixed(0)}% ({formatBytes(d.used)})</span></div>
                <div className="w-full h-1 bg-gray-700 rounded-full mt-0.5"><div className="h-full rounded-full transition-all" style={{ width: `${d.pct}%`, backgroundColor: d.pct > 80 ? "#ef4444" : "#06b6d4" }} /></div>
              </div>
            ))}
            <div className="pt-1 border-t border-[var(--border)] mt-2 space-y-1">
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Gateway</span><span className="font-mono text-[10px]">{system?.default_gateway || "---"}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">DNS</span><span className="font-mono text-[10px]">{system?.dns_servers?.join(", ") || "---"}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Routes</span><span>{system?.route_count ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Packets</span><span>{formatNumber(status.packets_in + status.packets_out)}</span></div>
            </div>
          </div>
        </div>

        {/* Top Talkers */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider mb-3">Top Talkers</h3>
          {topTalkers.length === 0 ? (
            <div className="text-xs text-[var(--text-muted)] text-center py-4">No active connections</div>
          ) : (
            <div className="space-y-2.5">
              {topTalkers.map((t, i) => (
                <div key={t.ip}>
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-[var(--text-muted)] w-3">{i + 1}.</span>
                      <span className="font-mono text-[11px]">{t.ip}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--text-muted)]">{t.conns} conn{t.conns !== 1 ? "s" : ""}</span>
                      <span className="font-mono text-cyan-400">{formatBytes(t.bytes)}</span>
                    </div>
                  </div>
                  <div className="w-full h-1 bg-gray-700 rounded-full mt-1">
                    <div className="h-full rounded-full bg-cyan-500 transition-all" style={{ width: `${(t.bytes / mtb) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Blocked */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-[10px] font-medium text-[var(--text-muted)] uppercase tracking-wider">Recent Blocked</h3>
            <span className="text-[10px] font-mono text-red-400">{blocked.length} entries</span>
          </div>
          {blocked.length === 0 ? (
            <div className="text-xs text-[var(--text-muted)] text-center py-4">No blocked traffic</div>
          ) : (
            <div className="space-y-1.5 max-h-40 overflow-y-auto">
              {blocked.slice(-10).reverse().map((b, i) => (
                <div key={i} className="flex items-center justify-between text-[11px] py-1 px-2 rounded bg-[var(--bg-primary)]">
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-red-400 uppercase text-[9px] font-bold w-8 flex-shrink-0">{b.action}</span>
                    <span className="font-mono truncate">{b.src_addr}</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0 ml-2">
                    <span className="text-[var(--text-muted)]">{b.protocol || "---"}</span>
                    <span className="font-mono text-[10px]">:{b.dst_port || "---"}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Connections Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="text-xs font-medium">Active Connections</h3>
          <span className="text-[10px] text-[var(--text-muted)]">{connections.length} total</span>
        </div>
        <div className="overflow-x-auto overflow-y-auto max-h-56">
          {connections.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No active connections</div>
          ) : (
            <table className="w-full text-[11px] min-w-[600px]">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[9px] tracking-wider">Proto</th>
                  <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[9px] tracking-wider">Source</th>
                  <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[9px] tracking-wider">Destination</th>
                  <th className="text-left py-2 px-3 text-[var(--text-muted)] uppercase text-[9px] tracking-wider">State</th>
                  <th className="text-right py-2 px-3 text-[var(--text-muted)] uppercase text-[9px] tracking-wider">In/Out</th>
                </tr>
              </thead>
              <tbody>
                {connections.slice(0, 20).map((c, i) => (
                  <tr key={i} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                    <td className="py-1.5 px-3 uppercase text-cyan-400 font-medium">{c.protocol}</td>
                    <td className="py-1.5 px-3 font-mono">{c.src_addr}:{c.src_port}</td>
                    <td className="py-1.5 px-3 font-mono">{c.dst_addr}:{c.dst_port}</td>
                    <td className="py-1.5 px-3 text-[var(--text-secondary)]">{c.state.split(":")[0]}</td>
                    <td className="py-1.5 px-3 text-right font-mono text-[10px] text-[var(--text-muted)]">{formatBytes(c.bytes_in)} / {formatBytes(c.bytes_out)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
