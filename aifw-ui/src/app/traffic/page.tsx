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

function TrafficChart({ data, height = 200 }: { data: RatePoint[]; height?: number }) {
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
  return (
    <svg viewBox={`0 0 ${w} ${h2}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="tIn" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22c55e" stopOpacity="0.4"/><stop offset="100%" stopColor="#22c55e" stopOpacity="0.02"/></linearGradient>
        <linearGradient id="tOut" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35"/><stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02"/></linearGradient>
        <clipPath id="tc"><rect x={pad.left} y={pad.top} width={cW} height={cH}/></clipPath>
      </defs>
      {yL.map((t,i)=>(<g key={i}><line x1={pad.left} y1={t.y} x2={w-pad.right} y2={t.y} stroke="#1e293b"/><text x={pad.left-4} y={t.y+3} textAnchor="end" fill="#64748b" fontSize="9" fontFamily="monospace">{t.label}</text></g>))}
      <g clipPath="url(#tc)">
        <path d={inA} fill="url(#tIn)"/><path d={outA} fill="url(#tOut)"/>
        <path d={inL} fill="none" stroke="#22c55e" strokeWidth="1.5"/><path d={outL} fill="none" stroke="#3b82f6" strokeWidth="1.5"/>
        <circle cx={inP[inP.length-1].x} cy={inP[inP.length-1].y} r="2.5" fill="#22c55e"/>
        <circle cx={outP[outP.length-1].x} cy={outP[outP.length-1].y} r="2.5" fill="#3b82f6"/>
      </g>
    </svg>
  );
}

export default function TrafficPage() {
  const ws = useWs();
  const [selectedNic, setSelectedNic] = useState(() => typeof window !== "undefined" ? localStorage.getItem("aifw_traffic_nic") || "" : "");
  const selectedNicRef = useRef(selectedNic);
  const [rateHistory, setRateHistory] = useState<RatePoint[]>([]);
  const [currentRateIn, setCurrentRateIn] = useState(0);
  const [currentRateOut, setCurrentRateOut] = useState(0);
  const prevIface = useRef<Record<string, {bytes_in:number;bytes_out:number}>>({});
  const prevTime = useRef(0);
  const historyProcessed = useRef(false);

  const pickNic = (name: string) => { setSelectedNic(name); selectedNicRef.current = name; localStorage.setItem("aifw_traffic_nic", name); };

  // Auto-select first NIC
  useEffect(() => {
    if (!selectedNicRef.current && ws.interfaces.length > 0) {
      pickNic((ws.interfaces[0] as {name:string}).name);
    }
  }, [ws.interfaces]);

  // Process history once on load
  useEffect(() => {
    if (historyProcessed.current || !ws.historyLoaded || ws.history.length === 0) return;
    historyProcessed.current = true;

    const points: RatePoint[] = [];
    const prevByIf: Record<string, {bytes_in:number;bytes_out:number}> = {};
    let prevTs = 0;
    let nic = selectedNicRef.current;

    for (const entry of ws.history) {
      if ((entry as {type:string}).type !== "status_update") continue;
      const ts = Date.now() - (ws.history.length - points.length) * 1000;
      const ifaces = (entry as {interfaces:{name:string;bytes_in:number;bytes_out:number}[]}).interfaces || [];
      if (!nic && ifaces.length > 0) { nic = ifaces[0].name; pickNic(nic); }

      const cur = ifaces.find(i => i.name === nic);
      const prev = prevByIf[nic || ""];
      let bi = 0, bo = 0;
      if (cur && prev && prevTs) {
        const dt = (ts - prevTs) / 1000;
        if (dt > 0 && dt < 5) {
          bi = Math.max(0, (cur.bytes_in - prev.bytes_in) / dt * 8);
          bo = Math.max(0, (cur.bytes_out - prev.bytes_out) / dt * 8);
        }
      }
      if (cur && nic) prevByIf[nic] = { bytes_in: cur.bytes_in, bytes_out: cur.bytes_out };
      prevTs = ts;
      points.push({ time: ts, bpsIn: bi, bpsOut: bo });
    }

    Object.assign(prevIface.current, prevByIf);
    prevTime.current = Date.now();
    if (points.length > 0) setRateHistory(points.slice(-MAX_POINTS));
  }, [ws.historyLoaded, ws.history]);

  // Process live updates
  useEffect(() => {
    if (!ws.status || !ws.interfaces.length) return;
    const now = Date.now();
    const nic = selectedNicRef.current;
    if (!nic) return;

    const cur = (ws.interfaces as {name:string;bytes_in:number;bytes_out:number}[]).find(i => i.name === nic);
    const prev = prevIface.current[nic];

    if (cur && prev && prevTime.current) {
      const dt = (now - prevTime.current) / 1000;
      if (dt > 0 && dt < 5) {
        const bi = Math.max(0, (cur.bytes_in - prev.bytes_in) / dt * 8);
        const bo = Math.max(0, (cur.bytes_out - prev.bytes_out) / dt * 8);
        setCurrentRateIn(bi);
        setCurrentRateOut(bo);
        setRateHistory(h => [...h, { time: now, bpsIn: bi, bpsOut: bo }].slice(-MAX_POINTS));
      }
    }
    if (cur) prevIface.current[nic] = { bytes_in: cur.bytes_in, bytes_out: cur.bytes_out };
    prevTime.current = now;
  }, [ws.status]);

  // Reset on NIC change
  useEffect(() => {
    historyProcessed.current = false;
    setRateHistory([]);
    prevIface.current = {};
    prevTime.current = 0;
  }, [selectedNic]);

  const connections = ws.connections as {src_addr:string;dst_addr:string;dst_port:number;protocol:string;bytes_in:number;bytes_out:number}[];
  const currentIface = (ws.interfaces as {name:string;bytes_in:number;bytes_out:number;packets_in:number;packets_out:number}[]).find(i => i.name === selectedNic);
  const ifaceNames = (ws.interfaces as {name:string}[]);

  const topTalkers = useMemo(() =>
    connections.reduce<{ip:string;bytes:number;conns:number}[]>((a,c) => {
      const e=a.find(t=>t.ip===c.src_addr),tot=c.bytes_in+c.bytes_out;
      if(e){e.bytes+=tot;e.conns++}else a.push({ip:c.src_addr,bytes:tot,conns:1});return a;
    },[]).sort((a,b)=>b.bytes-a.bytes).slice(0,10),
  [connections]);
  const maxTB = topTalkers[0]?.bytes || 1;

  const topPorts = useMemo(() =>
    connections.reduce<{port:number;proto:string;conns:number}[]>((a,c) => {
      const key=`${c.dst_port}-${c.protocol}`,e=a.find(p=>`${p.port}-${p.proto}`===key);
      if(e)e.conns++;else a.push({port:c.dst_port,proto:c.protocol,conns:1});return a;
    },[]).sort((a,b)=>b.conns-a.conns).slice(0,15),
  [connections]);
  const maxPC = topPorts[0]?.conns || 1;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Traffic Analytics</h1>
          <p className="text-sm text-[var(--text-muted)]">Per-interface bandwidth monitoring</p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <div className={`w-2 h-2 rounded-full ${ws.connected ? "bg-green-500 animate-pulse" : "bg-red-500"}`}/>
            <span className="text-xs text-[var(--text-muted)]">{ws.connected ? "Live" : "..."}</span>
          </div>
          <select value={selectedNic} onChange={(e) => pickNic(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500">
            {ifaceNames.map(i => <option key={i.name} value={i.name}>{i.name}</option>)}
          </select>
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Rate In</div>
          <div className="text-xl font-bold text-green-400">{formatBps(currentRateIn)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Rate Out</div>
          <div className="text-xl font-bold text-blue-400">{formatBps(currentRateOut)}</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total In ({selectedNic})</div>
          <div className="text-lg font-bold text-cyan-400">{formatBytes(currentIface?.bytes_in ?? 0)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatNumber(currentIface?.packets_in ?? 0)} pkts</div>
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3">
          <div className="text-[10px] text-[var(--text-muted)] uppercase">Total Out ({selectedNic})</div>
          <div className="text-lg font-bold text-orange-400">{formatBytes(currentIface?.bytes_out ?? 0)}</div>
          <div className="text-[10px] text-[var(--text-muted)]">{formatNumber(currentIface?.packets_out ?? 0)} pkts</div>
        </div>
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium">Throughput — {selectedNic}</h3>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5"><span className="w-3 h-[3px] bg-green-500 rounded-full inline-block"/> Inbound</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-[3px] bg-blue-500 rounded-full inline-block"/> Outbound</span>
          </div>
        </div>
        <TrafficChart data={rateHistory} height={200}/>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]"><h3 className="text-sm font-medium">Top Talkers</h3></div>
          {topTalkers.length===0 ? <div className="text-center py-8 text-[var(--text-muted)] text-sm">No data</div> : (
            <div className="divide-y divide-[var(--border)]">{topTalkers.map((t,i)=>(
              <div key={t.ip} className="px-4 py-2 hover:bg-[var(--bg-card-hover)]">
                <div className="flex justify-between mb-1"><span className="font-mono text-xs">{i+1}. {t.ip}</span><span className="text-xs text-[var(--text-secondary)]">{formatBytes(t.bytes)} · {t.conns} conn</span></div>
                <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden"><div className="h-full rounded-full bg-cyan-500 transition-all" style={{width:`${(t.bytes/maxTB)*100}%`}}/></div>
              </div>
            ))}</div>
          )}
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]"><h3 className="text-sm font-medium">Top Ports</h3></div>
          {topPorts.length===0 ? <div className="text-center py-8 text-[var(--text-muted)] text-sm">No data</div> : (
            <div className="divide-y divide-[var(--border)]">{topPorts.map(p => {
              const svc = portNames[p.port];
              const pc = p.proto==="tcp"?"text-blue-400":p.proto==="udp"?"text-purple-400":"text-gray-400";
              return (
                <div key={`${p.port}-${p.proto}`} className="px-3 py-1.5 hover:bg-[var(--bg-card-hover)] flex items-center gap-2">
                  <span className={`uppercase text-[10px] font-bold w-7 ${pc}`}>{p.proto}</span>
                  <span className="font-mono text-xs text-cyan-400 w-12 text-right">{p.port}</span>
                  {svc && <span className="text-[10px] text-[var(--text-muted)] w-16 truncate">{svc}</span>}
                  <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden"><div className="h-full rounded-full bg-blue-500 transition-all" style={{width:`${(p.conns/maxPC)*100}%`}}/></div>
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
