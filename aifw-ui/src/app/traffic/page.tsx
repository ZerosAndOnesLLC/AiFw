"use client";

import { useEffect, useState, useRef, useCallback } from "react";

interface InterfaceData {
  name: string;
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
}

interface Connection {
  src_addr: string;
  src_port: number;
  dst_addr: string;
  dst_port: number;
  protocol: string;
  bytes_in: number;
  bytes_out: number;
}

interface RatePoint {
  time: number;
  bpsIn: number;
  bpsOut: number;
}

function formatBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(2)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${bytes} B`;
}

function formatBps(bps: number): string {
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(1)} Kbps`;
  return `${bps.toFixed(0)} bps`;
}

function formatNumber(n: number): string {
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toLocaleString();
}

function formatTime(ts: number): string {
  return new Date(ts).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function TrafficChart({ data, height = 200 }: { data: RatePoint[]; height?: number }) {
  if (data.length < 3) {
    return (
      <div className="flex items-center justify-center text-[var(--text-muted)] text-sm" style={{ height }}>
        <div className="text-center">
          <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-2" />
          Collecting data...
        </div>
      </div>
    );
  }
  const w = 900, h = height;
  const pad = { top: 10, right: 10, bottom: 25, left: 65 };
  const cW = w - pad.left - pad.right, cH = h - pad.top - pad.bottom;
  const maxVal = Math.max(...data.map((d) => Math.max(d.bpsIn, d.bpsOut)), 1000);
  const sY = (v: number) => pad.top + cH - (v / maxVal) * cH;
  const sX = (i: number) => pad.left + (i / (data.length - 1)) * cW;

  const smooth = (pts: { x: number; y: number }[]) => {
    if (pts.length < 2) return "";
    let d = `M ${pts[0].x},${pts[0].y}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[Math.max(0, i - 1)], p1 = pts[i], p2 = pts[i + 1], p3 = pts[Math.min(pts.length - 1, i + 2)];
      d += ` C ${p1.x + (p2.x - p0.x) / 6},${p1.y + (p2.y - p0.y) / 6} ${p2.x - (p3.x - p1.x) / 6},${p2.y - (p3.y - p1.y) / 6} ${p2.x},${p2.y}`;
    }
    return d;
  };

  const inPts = data.map((d, i) => ({ x: sX(i), y: sY(d.bpsIn) }));
  const outPts = data.map((d, i) => ({ x: sX(i), y: sY(d.bpsOut) }));
  const inLine = smooth(inPts), outLine = smooth(outPts);
  const bl = pad.top + cH;
  const inArea = `${inLine} L ${inPts[inPts.length - 1].x},${bl} L ${inPts[0].x},${bl} Z`;
  const outArea = `${outLine} L ${outPts[outPts.length - 1].x},${bl} L ${outPts[0].x},${bl} Z`;

  const yTicks = 5;
  const yLabels = Array.from({ length: yTicks + 1 }, (_, i) => ({ y: sY((maxVal / yTicks) * i), label: formatBps((maxVal / yTicks) * i) }));
  const xStep = Math.max(1, Math.floor(data.length / 8));

  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full" preserveAspectRatio="xMidYMid meet">
      <defs>
        <linearGradient id="tgIn" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#22c55e" stopOpacity="0.4" /><stop offset="100%" stopColor="#22c55e" stopOpacity="0.02" /></linearGradient>
        <linearGradient id="tgOut" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#3b82f6" stopOpacity="0.35" /><stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02" /></linearGradient>
      </defs>
      {yLabels.map((t, i) => (<g key={i}><line x1={pad.left} y1={t.y} x2={w - pad.right} y2={t.y} stroke="#1e293b" /><text x={pad.left - 5} y={t.y + 3} textAnchor="end" fill="#64748b" fontSize="10" fontFamily="monospace">{t.label}</text></g>))}
      {data.filter((_, i) => i % xStep === 0).map((d, i) => (<text key={i} x={sX(data.indexOf(d))} y={h - 5} textAnchor="middle" fill="#64748b" fontSize="10" fontFamily="monospace">{formatTime(d.time)}</text>))}
      <path d={inArea} fill="url(#tgIn)" /><path d={outArea} fill="url(#tgOut)" />
      <path d={inLine} fill="none" stroke="#22c55e" strokeWidth="2" /><path d={outLine} fill="none" stroke="#3b82f6" strokeWidth="2" />
      <circle cx={inPts[inPts.length - 1].x} cy={inPts[inPts.length - 1].y} r="3" fill="#22c55e" />
      <circle cx={outPts[outPts.length - 1].x} cy={outPts[outPts.length - 1].y} r="3" fill="#3b82f6" />
    </svg>
  );
}

export default function TrafficPage() {
  const [interfaces, setInterfaces] = useState<InterfaceData[]>([]);
  const [selectedNic, setSelectedNic] = useState("");
  const [connections, setConnections] = useState<Connection[]>([]);
  const [rateHistory, setRateHistory] = useState<RatePoint[]>([]);
  const [currentRateIn, setCurrentRateIn] = useState(0);
  const [currentRateOut, setCurrentRateOut] = useState(0);
  const [wsConnected, setWsConnected] = useState(false);
  const prevIface = useRef<Record<string, InterfaceData>>({});
  const prevTime = useRef(0);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connectWs = useCallback(() => {
    const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
    if (!token) return;
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/ws`);
    wsRef.current = ws;

    ws.onopen = () => setWsConnected(true);
    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type !== "status_update") return;

        const now = Date.now();
        const ifaces: InterfaceData[] = msg.interfaces || [];
        setInterfaces(ifaces);
        setConnections(msg.connections || []);

        if (!selectedNic && ifaces.length > 0) {
          setSelectedNic(ifaces[0].name);
        }

        // Calculate per-interface rate
        const nic = selectedNic || (ifaces[0]?.name ?? "");
        const current = ifaces.find((i: InterfaceData) => i.name === nic);
        const prev = prevIface.current[nic];

        if (current && prev && prevTime.current) {
          const dt = (now - prevTime.current) / 1000;
          if (dt > 0 && dt < 5) {
            const bpsIn = Math.max(0, (current.bytes_in - prev.bytes_in) / dt * 8);
            const bpsOut = Math.max(0, (current.bytes_out - prev.bytes_out) / dt * 8);
            setCurrentRateIn(bpsIn);
            setCurrentRateOut(bpsOut);
            setRateHistory((h) => [...h, { time: now, bpsIn, bpsOut }].slice(-300));
          }
        }

        if (current) prevIface.current[nic] = current;
        prevTime.current = now;
      } catch { /* ignore */ }
    };
    ws.onclose = () => { setWsConnected(false); reconnectTimer.current = setTimeout(connectWs, 3000); };
    ws.onerror = () => ws.close();
  }, [selectedNic]);

  useEffect(() => {
    connectWs();
    return () => { wsRef.current?.close(); if (reconnectTimer.current) clearTimeout(reconnectTimer.current); };
  }, [connectWs]);

  // Reset history when NIC changes
  useEffect(() => {
    setRateHistory([]);
    prevIface.current = {};
    prevTime.current = 0;
  }, [selectedNic]);

  const currentIface = interfaces.find((i) => i.name === selectedNic);

  // Top talkers
  const topTalkers = connections
    .reduce<{ ip: string; bytes: number; conns: number }[]>((acc, c) => {
      const existing = acc.find((t) => t.ip === c.src_addr);
      const total = c.bytes_in + c.bytes_out;
      if (existing) { existing.bytes += total; existing.conns++; }
      else acc.push({ ip: c.src_addr, bytes: total, conns: 1 });
      return acc;
    }, []).sort((a, b) => b.bytes - a.bytes).slice(0, 10);
  const maxTB = topTalkers[0]?.bytes || 1;

  // Top ports — group by port+protocol
  const portNames: Record<number, string> = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 143: "imap",
    161: "snmp", 443: "https", 445: "smb", 465: "smtps", 514: "syslog",
    587: "submission", 636: "ldaps", 853: "dot", 993: "imaps", 995: "pop3s",
    1194: "openvpn", 1433: "mssql", 1723: "pptp", 3306: "mysql", 3389: "rdp",
    5060: "sip", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
    51820: "wireguard",
  };
  const topPorts = connections
    .reduce<{ port: number; proto: string; conns: number }[]>((acc, c) => {
      const key = `${c.dst_port}-${c.protocol}`;
      const existing = acc.find((p) => `${p.port}-${p.proto}` === key);
      if (existing) existing.conns++;
      else acc.push({ port: c.dst_port, proto: c.protocol, conns: 1 });
      return acc;
    }, []).sort((a, b) => b.conns - a.conns).slice(0, 15);
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
            <div className={`w-2 h-2 rounded-full ${wsConnected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-xs text-[var(--text-muted)]">{wsConnected ? "Live" : "Reconnecting..."}</span>
          </div>
          <select value={selectedNic} onChange={(e) => setSelectedNic(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500">
            {interfaces.map((i) => (
              <option key={i.name} value={i.name}>{i.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Rate Cards */}
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

      {/* Traffic Graph */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-medium">Throughput — {selectedNic}</h3>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5"><span className="w-3 h-[3px] bg-green-500 rounded-full inline-block" /> Inbound</span>
            <span className="flex items-center gap-1.5"><span className="w-3 h-[3px] bg-blue-500 rounded-full inline-block" /> Outbound</span>
          </div>
        </div>
        <TrafficChart data={rateHistory} height={200} />
      </div>

      {/* Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]"><h3 className="text-sm font-medium">Top Talkers</h3></div>
          {topTalkers.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No data</div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {topTalkers.map((t, i) => (
                <div key={t.ip} className="px-4 py-2 hover:bg-[var(--bg-card-hover)]">
                  <div className="flex justify-between mb-1">
                    <span className="font-mono text-xs">{i + 1}. {t.ip}</span>
                    <span className="text-xs text-[var(--text-secondary)]">{formatBytes(t.bytes)} · {t.conns} conn</span>
                  </div>
                  <div className="w-full h-1.5 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-cyan-500 transition-all" style={{ width: `${(t.bytes / maxTB) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-[var(--border)]"><h3 className="text-sm font-medium">Top Ports</h3></div>
          {topPorts.length === 0 ? (
            <div className="text-center py-8 text-[var(--text-muted)] text-sm">No data</div>
          ) : (
            <div className="divide-y divide-[var(--border)]">
              {topPorts.map((p) => {
                const svcName = portNames[p.port];
                const protoColor = p.proto === "tcp" ? "text-blue-400" : p.proto === "udp" ? "text-purple-400" : "text-gray-400";
                return (
                <div key={`${p.port}-${p.proto}`} className="px-3 py-1.5 hover:bg-[var(--bg-card-hover)] flex items-center gap-2">
                  <span className={`uppercase text-[10px] font-bold w-7 ${protoColor}`}>{p.proto}</span>
                  <span className="font-mono text-xs text-cyan-400 w-12 text-right">{p.port}</span>
                  {svcName && <span className="text-[10px] text-[var(--text-muted)] w-16 truncate">{svcName}</span>}
                  <div className="flex-1 h-1.5 bg-gray-700 rounded-full overflow-hidden">
                    <div className="h-full rounded-full bg-blue-500 transition-all" style={{ width: `${(p.conns / maxPC) * 100}%` }} />
                  </div>
                  <span className="text-[10px] text-[var(--text-secondary)] w-8 text-right">{p.conns}</span>
                </div>);
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
