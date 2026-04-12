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
interface IdsData {
  running: boolean; mode: string; loaded_rules: number;
  alerts_total: number; drops_total: number; packets_inspected: number;
  packets_per_sec: number; bytes_per_sec: number; active_flows: number;
  recent_alerts: { severity: number; signature_msg: string; src_ip: string; dst_ip: string; protocol: string; timestamp: string }[];
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

const MAX_PTS = 1800;
const SVG_W = 900;
const TIMEFRAMES = [
  { key: "1m", label: "1m", points: 60 },
  { key: "5m", label: "5m", points: 300 },
  { key: "15m", label: "15m", points: 900 },
  { key: "30m", label: "30m", points: 1800 },
] as const;

interface ChartLine { key: string; color: string; label: string; }

function StackedChart({ data, getValue, lines, maxValue, formatY, title, height = 100, hoverIdx, onHover, maxPts }: {
  data: HistoryPoint[]; getValue: (d: HistoryPoint, key: string) => number;
  lines: ChartLine[]; maxValue?: number; formatY: (v: number) => string;
  title: string; height?: number; hoverIdx: number | null; onHover: (idx: number | null) => void;
  maxPts?: number;
}) {
  const chartMax = maxPts ?? MAX_PTS;
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
  const ppx = cW/chartMax;
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
  const ids = ws.ids as IdsData | null;

  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [modal, setModal] = useState<"system" | "talkers" | "blocked" | null>(null);
  const [svcStatus, setSvcStatus] = useState<{
    dns: { running: boolean; version: string; total_hosts: number; total_domains: number; total_acls: number; queries_total: number; cache_hits: number; cache_misses: number } | null;
    dhcp: { running: boolean; version: string; total_subnets: number; active_leases: number; total_reservations: number } | null;
    time: { running: boolean; version: string; sources_count: number } | null;
  }>({ dns: null, dhcp: null, time: null });
  const [rateIn, setRateIn] = useState(0);
  const [rateOut, setRateOut] = useState(0);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);
  const [blockedCount, setBlockedCount] = useState(() => {
    if (typeof window === "undefined") return 10;
    const saved = localStorage.getItem("aifw_blocked_count");
    return saved ? parseInt(saved, 10) : 10;
  });
  const [timeframe, setTimeframe] = useState(() =>
    typeof window !== "undefined" ? localStorage.getItem("aifw_dashboard_tf") || "5m" : "5m"
  );
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

  const pickTimeframe = (tf: string) => {
    setTimeframe(tf);
    localStorage.setItem("aifw_dashboard_tf", tf);
  };

  const tfPoints = TIMEFRAMES.find(t => t.key === timeframe)?.points ?? 300;

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

  // Fetch DNS/DHCP/Time status on mount + every 30s
  useEffect(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    const headers = { Authorization: `Bearer ${token}` };
    const fetchSvc = async () => {
      const [dnsRes, dhcpRes, timeRes] = await Promise.allSettled([
        fetch("/api/v1/dns/resolver/status", { headers }).then(r => r.ok ? r.json() : null),
        fetch("/api/v1/dhcp/status", { headers }).then(r => r.ok ? r.json() : null),
        fetch("/api/v1/time/status", { headers }).then(r => r.ok ? r.json() : null),
      ]);
      setSvcStatus({
        dns: dnsRes.status === "fulfilled" ? dnsRes.value : null,
        dhcp: dhcpRes.status === "fulfilled" ? dhcpRes.value : null,
        time: timeRes.status === "fulfilled" ? timeRes.value : null,
      });
    };
    fetchSvc();
    const iv = setInterval(fetchSvc, 30000);
    return () => clearInterval(iv);
  }, []);

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
  const svcDown = services.filter(s => s.enabled && !s.running);
  const healthReasons: string[] = [];
  if (!status.pf_running) healthReasons.push("pf not running");
  if (svcDown.length > 0) healthReasons.push(`${svcDown.map(s => s.name).join(", ")} down`);
  if (cpu > 90) healthReasons.push(`CPU ${cpu.toFixed(0)}%`);
  if (mem > 90) healthReasons.push(`Memory ${mem.toFixed(0)}%`);
  if (disk > 95) healthReasons.push(`Disk ${disk.toFixed(0)}%`);
  const healthLevel: "critical" | "warning" | "healthy" =
    (!status.pf_running || svcDown.length > 0 || cpu > 90 || mem > 90 || disk > 95) ? "critical"
    : (cpu > 70 || mem > 70 || disk > 80) ? "warning"
    : "healthy";
  if (healthLevel === "warning") {
    if (cpu > 70) healthReasons.push(`CPU ${cpu.toFixed(0)}%`);
    if (mem > 70) healthReasons.push(`Memory ${mem.toFixed(0)}%`);
    if (disk > 80) healthReasons.push(`Disk ${disk.toFixed(0)}%`);
  }
  const healthLabel = healthLevel === "critical" ? "Attention Required"
    : healthLevel === "warning" ? "Degraded"
    : "All Systems Operational";

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
            {healthReasons.length > 0 && (
              <span className={`text-[11px] font-medium ${healthTextCls[healthLevel]}`}>
                {healthReasons.join(" · ")}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Services inline */}
            {services.map(svc => (
              <div key={svc.name} className={`flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium ${
                !svc.enabled ? "bg-gray-700/30 text-gray-500"
                : svc.running ? "bg-green-500/15 text-green-400"
                : "bg-red-500/15 text-red-400"
              }`}>
                <div className={`w-1.5 h-1.5 rounded-full ${
                  !svc.enabled ? "bg-gray-600" : svc.running ? "bg-green-500" : "bg-red-500"
                }`} />
                {svc.name}
              </div>
            ))}
            {interfaceList.length > 0 && (
              <select value={selectedNic} onChange={(e) => pickNic(e.target.value)}
                className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
                {interfaceList.map((i) => <option key={i.name} value={i.name}>{i.name}</option>)}
              </select>
            )}
            <div className={`px-2 py-1 rounded text-xs font-medium ${status.pf_running ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"}`}>
              pf {status.pf_running ? "Active" : "Inactive"}
            </div>
            <div className="flex items-center gap-1.5">
              <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
              <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
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


      {/* Charts — timeframe picker + 2x2 grid */}
      <div className="flex items-center justify-between">
        <h3 className="text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Performance</h3>
        <div className="flex items-center gap-1">
          {TIMEFRAMES.map(tf => (
            <button key={tf.key} onClick={() => pickTimeframe(tf.key)}
              className={`px-2.5 py-1 text-[10px] font-medium rounded-md transition-colors ${
                timeframe === tf.key
                  ? "bg-blue-600/20 border border-blue-500/40 text-blue-400"
                  : "bg-[var(--bg-card)] border border-[var(--border)] text-[var(--text-muted)] hover:border-[var(--text-muted)]"
              }`}>
              {tf.label}
            </button>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <StackedChart data={history.slice(-tfPoints)} maxPts={tfPoints} title="CPU" height={225} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "cpu", color: "#3b82f6", label: "CPU" }]}
          getValue={(d, k) => k === "cpu" ? d.cpu : 0}
          maxValue={100} formatY={v => `${v.toFixed(0)}%`}
        />
        <StackedChart data={history.slice(-tfPoints)} maxPts={tfPoints} title="Memory" height={225} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "mem", color: "#8b5cf6", label: "Memory" }]}
          getValue={(d, k) => k === "mem" ? d.memPct : 0}
          maxValue={100} formatY={v => `${v.toFixed(0)}%`}
        />
        <StackedChart data={history.slice(-tfPoints)} maxPts={tfPoints} title="Disk I/O" height={225} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "read", color: "#22c55e", label: "Read" }, { key: "write", color: "#f97316", label: "Write" }]}
          getValue={(d, k) => k === "read" ? d.diskReadKbps : d.diskWriteKbps}
          formatY={v => v >= 1024 ? `${(v / 1024).toFixed(0)} MB/s` : `${v.toFixed(0)} KB/s`}
        />
        <StackedChart data={history.slice(-tfPoints)} maxPts={tfPoints} title="Network" height={225} hoverIdx={hoverIdx} onHover={setHoverIdx}
          lines={[{ key: "in", color: "#22c55e", label: "In" }, { key: "out", color: "#3b82f6", label: "Out" }]}
          getValue={(d, k) => k === "in" ? d.bpsIn : d.bpsOut}
          formatY={formatBps}
        />
      </div>

      {/* Compact summary row — click to expand modals */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <button onClick={() => setModal("system")} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-left hover:border-[var(--text-muted)] transition-colors">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">System</span>
            <svg className="w-3.5 h-3.5 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
          </div>
          <div className="flex items-center gap-2 text-xs">
            <span style={{ color: cpu > 80 ? "#ef4444" : "#3b82f6" }}>{cpu.toFixed(0)}% CPU</span>
            <span className="text-[var(--border)]">|</span>
            <span style={{ color: mem > 80 ? "#ef4444" : "#8b5cf6" }}>{mem.toFixed(0)}% Mem</span>
            <span className="text-[var(--border)]">|</span>
            <span style={{ color: disk > 90 ? "#ef4444" : "#06b6d4" }}>{disk.toFixed(0)}% Disk</span>
          </div>
        </button>

        <button onClick={() => setModal("talkers")} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-left hover:border-[var(--text-muted)] transition-colors">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">Top Talkers</span>
            <svg className="w-3.5 h-3.5 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
          </div>
          <div className="text-xs">
            {topTalkers.length === 0
              ? <span className="text-[var(--text-muted)]">No active hosts</span>
              : <><span className="font-mono text-cyan-400">{topTalkers[0].ip}</span><span className="text-[var(--text-muted)] ml-1.5">+ {topTalkers.length - 1} more</span></>
            }
          </div>
        </button>

        <button onClick={() => setModal("blocked")} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 text-left hover:border-[var(--text-muted)] transition-colors">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">Blocked</span>
            <svg className="w-3.5 h-3.5 text-[var(--text-muted)]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
          </div>
          <div className="text-xs">
            <span className="font-mono font-bold text-red-400">{blocked.length}</span>
            <span className="text-[var(--text-muted)] ml-1.5">
              {blocked.length > 0 ? `latest: ${(blocked[blocked.length - 1] as { src_addr?: string })?.src_addr ?? "---"}` : "none"}
            </span>
          </div>
        </button>

        {/* IDS Overview */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">IDS/IPS</span>
            {ids ? (
              <div className="flex items-center gap-1.5">
                <div className={`w-1.5 h-1.5 rounded-full ${ids.running ? "bg-green-500" : "bg-gray-600"}`} />
                <span className={`text-[10px] font-medium ${
                  ids.mode === "ids" ? "text-blue-400" : ids.mode === "ips" ? "text-amber-400" : "text-gray-500"
                }`}>{(ids.mode || "off").toUpperCase()}</span>
              </div>
            ) : (
              <span className="text-[10px] text-gray-600">N/A</span>
            )}
          </div>
          {ids ? (
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px]">
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Alerts</span><span className="font-mono text-red-400">{formatNumber(ids.alerts_total ?? 0)}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Pkts/s</span><span className="font-mono text-cyan-400">{(ids.packets_per_sec ?? 0).toFixed(0)}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Drops</span><span className="font-mono text-yellow-400">{formatNumber(ids.drops_total ?? 0)}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Rules</span><span className="font-mono text-blue-400">{ids.loaded_rules ?? 0}</span></div>
            </div>
          ) : (
            <div className="text-xs text-[var(--text-muted)]">Disabled</div>
          )}
        </div>
      </div>

      {/* Service Overview — DNS, DHCP, Time */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* DNS */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">DNS Resolver</span>
            {svcStatus.dns !== null && (
              <div className="flex items-center gap-1">
                <div className={`w-1.5 h-1.5 rounded-full ${svcStatus.dns.running ? "bg-green-500" : "bg-red-500"}`} />
                <span className="text-[10px] text-[var(--text-muted)]">{svcStatus.dns.running ? "Running" : "Stopped"}</span>
              </div>
            )}
          </div>
          {svcStatus.dns ? (
            <div className="space-y-1 text-[11px]">
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Backend</span><span className="font-mono">{svcStatus.dns.version || "---"}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Queries</span><span className="font-mono text-green-400">{formatNumber(svcStatus.dns.queries_total ?? 0)}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Cache Hit/Miss</span><span className="font-mono"><span className="text-cyan-400">{formatNumber(svcStatus.dns.cache_hits ?? 0)}</span> / <span className="text-yellow-400">{formatNumber(svcStatus.dns.cache_misses ?? 0)}</span></span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Hosts / Domains</span><span className="font-mono">{svcStatus.dns.total_hosts ?? 0} / {svcStatus.dns.total_domains ?? 0}</span></div>
            </div>
          ) : (
            <div className="text-[11px] text-[var(--text-muted)]">Loading...</div>
          )}
        </div>

        {/* DHCP */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">DHCP Server</span>
            {svcStatus.dhcp !== null && (
              <div className="flex items-center gap-1">
                <div className={`w-1.5 h-1.5 rounded-full ${svcStatus.dhcp.running ? "bg-green-500" : "bg-red-500"}`} />
                <span className="text-[10px] text-[var(--text-muted)]">{svcStatus.dhcp.running ? "Running" : "Stopped"}</span>
              </div>
            )}
          </div>
          {svcStatus.dhcp ? (
            <div className="space-y-1 text-[11px]">
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Version</span><span className="font-mono">{svcStatus.dhcp.version || "---"}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Subnets</span><span className="font-mono text-cyan-400">{svcStatus.dhcp.total_subnets ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Active Leases</span><span className="font-mono text-green-400">{svcStatus.dhcp.active_leases ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Reservations</span><span className="font-mono text-purple-400">{svcStatus.dhcp.total_reservations ?? 0}</span></div>
            </div>
          ) : (
            <div className="text-[11px] text-[var(--text-muted)]">Loading...</div>
          )}
        </div>

        {/* Time */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] text-[var(--text-muted)] uppercase font-medium">Time Sync</span>
            {svcStatus.time !== null && (
              <div className="flex items-center gap-1">
                <div className={`w-1.5 h-1.5 rounded-full ${svcStatus.time.running ? "bg-green-500" : "bg-red-500"}`} />
                <span className="text-[10px] text-[var(--text-muted)]">{svcStatus.time.running ? "Synced" : "Stopped"}</span>
              </div>
            )}
          </div>
          {svcStatus.time ? (
            <div className="space-y-1 text-[11px]">
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Backend</span><span className="font-mono">{svcStatus.time.version || "---"}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Sources</span><span className="font-mono text-cyan-400">{svcStatus.time.sources_count ?? 0}</span></div>
            </div>
          ) : (
            <div className="text-[11px] text-[var(--text-muted)]">Loading...</div>
          )}
        </div>
      </div>

      {/* Modals */}
      {modal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setModal(null)}>
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-xl shadow-2xl max-w-lg w-full mx-4 max-h-[80vh] overflow-hidden" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3 border-b border-[var(--border)]">
              <h2 className="text-sm font-bold">
                {modal === "system" ? "System Details" : modal === "talkers" ? "Top Talkers" : "Recent Blocked"}
              </h2>
              <button onClick={() => setModal(null)} className="text-[var(--text-muted)] hover:text-white transition-colors">
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
              </button>
            </div>
            <div className="p-5 overflow-y-auto max-h-[calc(80vh-52px)]">
              {modal === "system" && (() => {
                const mb = (system as unknown as Record<string, unknown>)?.memory_breakdown as {
                  active_mb: number; inactive_mb: number; wired_mb: number; cached_mb: number; free_mb: number;
                  api_rss_mb: number; daemon_rss_mb: number;
                  ids_buffer_mb: number; ids_buffer_max_mb: number; ids_buffer_count: number;
                  metrics_history_count: number; metrics_history_mb: number;
                  pf_states: number; pf_states_max: number; db_size_mb: number; arc_mb: number;
                } | undefined;
                const totalMb = (system?.memory_total ?? 0) / (1024 * 1024);
                const barItem = (label: string, val: number, color: string) => {
                  const pct = totalMb > 0 ? Math.min(100, (val / totalMb) * 100) : 0;
                  return (
                    <div key={label} className="flex items-center gap-2">
                      <span className="text-[var(--text-muted)] w-20 text-right">{label}</span>
                      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
                      </div>
                      <span className="font-mono w-16 text-right">{val.toFixed(0)} MB</span>
                    </div>
                  );
                };
                return (
                <div className="space-y-3 text-xs">
                  <div className="flex justify-between"><span className="text-[var(--text-muted)]">Memory</span><span>{formatBytes(system?.memory_used ?? 0)} / {formatBytes(system?.memory_total ?? 0)} ({mem.toFixed(0)}%)</span></div>
                  <div className="w-full h-1.5 bg-gray-700 rounded-full"><div className="h-full rounded-full transition-all" style={{ width: `${mem}%`, backgroundColor: mem > 80 ? "#ef4444" : "#8b5cf6" }} /></div>

                  {mb && (
                    <div className="pt-2 border-t border-[var(--border)]">
                      <h4 className="text-[10px] text-[var(--text-muted)] uppercase font-medium mb-2">Memory Breakdown</h4>
                      <div className="space-y-1.5">
                        {barItem("Active", mb.active_mb, "#8b5cf6")}
                        {barItem("Wired", mb.wired_mb, "#f59e0b")}
                        {barItem("Inactive", mb.inactive_mb, "#6366f1")}
                        {barItem("Cached", mb.cached_mb, "#06b6d4")}
                        {barItem("Free", mb.free_mb, "#22c55e")}
                        {mb.arc_mb > 0 && barItem("ZFS ARC", mb.arc_mb, "#3b82f6")}
                      </div>

                      <h4 className="text-[10px] text-[var(--text-muted)] uppercase font-medium mt-3 mb-2">AiFw Memory Usage</h4>
                      <div className="space-y-1.5">
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">API Process</span><span className="font-mono">{mb.api_rss_mb.toFixed(1)} MB</span></div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Daemon Process</span><span className="font-mono">{mb.daemon_rss_mb.toFixed(1)} MB</span></div>
                        <div className="flex justify-between">
                          <span className="text-[var(--text-muted)]">IDS Alert Buffer</span>
                          <span className="font-mono">{mb.ids_buffer_mb.toFixed(1)} / {mb.ids_buffer_max_mb.toFixed(0)} MB <span className="text-[var(--text-muted)]">({mb.ids_buffer_count.toLocaleString()} alerts)</span></span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--text-muted)]">Metrics History</span>
                          <span className="font-mono">{mb.metrics_history_mb.toFixed(1)} MB <span className="text-[var(--text-muted)]">({mb.metrics_history_count.toLocaleString()} entries)</span></span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--text-muted)]">pf State Table</span>
                          <span className="font-mono">{mb.pf_states.toLocaleString()} / {mb.pf_states_max.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between"><span className="text-[var(--text-muted)]">Database</span><span className="font-mono">{mb.db_size_mb.toFixed(1)} MB</span></div>
                      </div>
                    </div>
                  )}

                  {system?.disks?.map(d => (
                    <div key={d.mount}>
                      <div className="flex justify-between"><span className="text-[var(--text-muted)] font-mono">{d.mount}</span><span>{d.pct.toFixed(0)}% ({formatBytes(d.used)} / {formatBytes(d.total)})</span></div>
                      <div className="w-full h-1.5 bg-gray-700 rounded-full mt-1"><div className="h-full rounded-full transition-all" style={{ width: `${d.pct}%`, backgroundColor: d.pct > 80 ? "#ef4444" : "#06b6d4" }} /></div>
                    </div>
                  ))}
                  <div className="pt-2 border-t border-[var(--border)] space-y-2">
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">Hostname</span><span className="font-mono">{system?.hostname || "---"}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">OS</span><span className="font-mono text-[10px]">{system?.os_version || "---"}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">Uptime</span><span>{formatUptime(system?.uptime_secs ?? 0)}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">Gateway</span><span className="font-mono">{system?.default_gateway || "---"}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">DNS</span><span className="font-mono text-[10px]">{system?.dns_servers?.join(", ") || "---"}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">Routes</span><span>{system?.route_count ?? 0}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">Packets</span><span>{formatNumber(status.packets_in + status.packets_out)}</span></div>
                    <div className="flex justify-between"><span className="text-[var(--text-muted)]">Disk I/O</span><span>R: {(system?.disk_io?.read_kbps ?? 0).toFixed(0)} KB/s · W: {(system?.disk_io?.write_kbps ?? 0).toFixed(0)} KB/s</span></div>
                  </div>
                </div>
                );
              })()}
              {modal === "talkers" && (
                topTalkers.length === 0
                  ? <div className="text-center text-[var(--text-muted)] py-4">No active connections</div>
                  : <div className="space-y-3">
                      {topTalkers.map((t, i) => (
                        <div key={t.ip}>
                          <div className="flex items-center justify-between text-xs">
                            <div className="flex items-center gap-2">
                              <span className="text-[var(--text-muted)] w-4">{i + 1}.</span>
                              <span className="font-mono">{t.ip}</span>
                            </div>
                            <div className="flex items-center gap-3">
                              <span className="text-[var(--text-muted)]">{t.conns} conn{t.conns !== 1 ? "s" : ""}</span>
                              <span className="font-mono text-cyan-400">{formatBytes(t.bytes)}</span>
                            </div>
                          </div>
                          <div className="w-full h-1.5 bg-gray-700 rounded-full mt-1">
                            <div className="h-full rounded-full bg-cyan-500 transition-all" style={{ width: `${(t.bytes / mtb) * 100}%` }} />
                          </div>
                        </div>
                      ))}
                    </div>
              )}
              {modal === "blocked" && (
                <>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs text-[var(--text-muted)]">{blocked.length} total blocked</span>
                    <select value={blockedCount}
                      onChange={(e) => { const v = parseInt(e.target.value, 10); setBlockedCount(v); localStorage.setItem("aifw_blocked_count", String(v)); }}
                      className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-xs text-[var(--text-muted)] focus:outline-none">
                      {[10, 25, 50, 100].map(n => <option key={n} value={n}>Last {n}</option>)}
                    </select>
                  </div>
                  {blocked.length === 0
                    ? <div className="text-center text-[var(--text-muted)] py-4">No blocked traffic</div>
                    : <div className="space-y-1.5">
                        {blocked.slice(-blockedCount).reverse().map((b, i) => (
                          <div key={i} className="flex items-center justify-between text-[11px] py-1.5 px-3 rounded bg-[var(--bg-primary)]">
                            <div className="flex items-center gap-2 min-w-0">
                              <span className="text-red-400 uppercase text-[9px] font-bold w-10 flex-shrink-0">{b.action}</span>
                              <span className="font-mono truncate">{b.src_addr}</span>
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                              <span className="text-[var(--text-muted)]">{b.protocol || "---"}</span>
                              <span className="font-mono text-[10px]">:{b.dst_port || "---"}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                  }
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
