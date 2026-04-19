"use client";

import { useState, useEffect } from "react";

interface ServiceInfo {
  name: string;
  binary: string;
  version: string;
  running: boolean;
  description: string;
  color: string;
}

interface MemoryBreakdown {
  active_mb: number;
  inactive_mb: number;
  wired_mb: number;
  cached_mb: number;
  free_mb: number;
  api_rss_mb: number;
  daemon_rss_mb: number;
  ids_buffer_mb: number;
  ids_buffer_max_mb: number;
  ids_buffer_count: number;
  metrics_history_count: number;
  metrics_history_mb: number;
  pf_states: number;
  pf_states_max: number;
  db_size_mb: number;
  arc_mb: number;
}

interface AboutInfo {
  version: string;
  git_commit: string | null;
  built_at: string | null;
  memory: MemoryBreakdown;
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function fmtMb(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  if (mb >= 1)    return `${mb.toFixed(0)} MB`;
  return `${(mb * 1024).toFixed(0)} KB`;
}
function fmtNum(n: number): string {
  return new Intl.NumberFormat().format(n);
}
function pct(num: number, total: number): number {
  return total > 0 ? Math.round((num / total) * 100) : 0;
}

export default function AboutPage() {
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [aifwVersion, setAifwVersion] = useState("");
  const [about, setAbout] = useState<AboutInfo | null>(null);

  useEffect(() => {
    (async () => {
      const headers = authHeaders();
      const results: ServiceInfo[] = [];

      // /api/v1/about returns version + memory breakdown in one shot.
      try {
        const res = await fetch("/api/v1/about", { headers });
        if (res.ok) {
          const data: AboutInfo = await res.json();
          setAbout(data);
          setAifwVersion(data.version);
        }
      } catch {}

      // Firewall daemon
      try {
        const res = await fetch("/api/v1/status", { headers });
        const data = res.ok ? await res.json() : {};
        results.push({
          name: "AiFw Daemon",
          binary: "aifw-daemon",
          version: data.version || data.data?.version || "unknown",
          running: true,
          description: "Core firewall daemon — loads pf rules, NAT, and aliases on boot",
          color: "text-blue-400",
        });
      } catch {
        results.push({ name: "AiFw Daemon", binary: "aifw-daemon", version: "unknown", running: false, description: "Core firewall daemon", color: "text-blue-400" });
      }

      // API
      results.push({
        name: "AiFw API",
        binary: "aifw-api",
        version: aifwVersion || "running",
        running: true,
        description: "REST API server — manages configuration, serves web UI",
        color: "text-cyan-400",
      });

      // DNS
      try {
        const res = await fetch("/api/v1/dns/resolver/status", { headers });
        const data = res.ok ? await res.json() : {};
        results.push({
          name: "rDNS",
          binary: "rdns",
          version: data.version || "unknown",
          running: data.running ?? false,
          description: "High-performance DNS resolver with DNSSEC, RPZ, and zone file support",
          color: "text-emerald-400",
        });
      } catch {
        results.push({ name: "rDNS", binary: "rdns", version: "unknown", running: false, description: "DNS resolver", color: "text-emerald-400" });
      }

      // DHCP
      try {
        const res = await fetch("/api/v1/dhcp/status", { headers });
        const data = res.ok ? await res.json() : {};
        const d = data.data || data;
        results.push({
          name: "rDHCP",
          binary: "rdhcpd",
          version: d.version || "unknown",
          running: d.running ?? d.status === "running",
          description: "Dual-stack DHCPv4/v6 server with HA support and WAL durability",
          color: "text-amber-400",
        });
      } catch {
        results.push({ name: "rDHCP", binary: "rdhcpd", version: "unknown", running: false, description: "DHCP server", color: "text-amber-400" });
      }

      // TrafficCop
      try {
        const res = await fetch("/api/v1/reverse-proxy/status", { headers });
        const data = res.ok ? await res.json() : {};
        const d = data.data || data;
        results.push({
          name: "TrafficCop",
          binary: "trafficcop",
          version: d.version || "unknown",
          running: d.running ?? false,
          description: "Real-time traffic monitoring and bandwidth analysis",
          color: "text-purple-400",
        });
      } catch {
        results.push({ name: "TrafficCop", binary: "trafficcop", version: "unknown", running: false, description: "Traffic monitor", color: "text-purple-400" });
      }

      setServices(results);
      setLoading(false);
    })();
  }, [aifwVersion]);

  return (
    <div className="max-w-3xl space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <div className="w-14 h-14 rounded-xl bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20">
          <svg className="w-8 h-8 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
        </div>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-white flex items-center gap-3 flex-wrap">
            AiFw
            {aifwVersion && (
              <span className="text-base font-mono text-blue-400 bg-blue-500/10 border border-blue-500/30 rounded px-2 py-0.5">
                v{aifwVersion}
              </span>
            )}
          </h1>
          <p className="text-sm text-gray-400">AI-Powered Firewall for FreeBSD</p>
          <p className="text-xs text-gray-500 mt-0.5">No garbage collectors. Pure Rust, C, and C++ on pf.</p>
          {about && (about.git_commit || about.built_at) && (
            <p className="text-[10px] text-gray-600 mt-1 font-mono">
              {about.git_commit && <>commit {about.git_commit.slice(0, 8)}</>}
              {about.git_commit && about.built_at && <> · </>}
              {about.built_at && <>built {about.built_at}</>}
            </p>
          )}
        </div>
      </div>

      {/* Memory breakdown */}
      {about?.memory && (() => {
        const m = about.memory;
        const totalMb = m.active_mb + m.inactive_mb + m.wired_mb + m.cached_mb + m.free_mb;
        return (
          <div>
            <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Memory Usage</h2>

            {/* OS-level breakdown bar */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 space-y-3">
              <div className="flex items-center justify-between text-xs">
                <span className="text-gray-400">System total</span>
                <span className="text-white font-mono">{fmtMb(totalMb)}</span>
              </div>
              <div className="flex h-3 rounded overflow-hidden bg-gray-900">
                <div className="bg-blue-500"   style={{ width: `${pct(m.active_mb, totalMb)}%` }}   title={`Active ${fmtMb(m.active_mb)}`} />
                <div className="bg-cyan-500"   style={{ width: `${pct(m.wired_mb, totalMb)}%` }}    title={`Wired ${fmtMb(m.wired_mb)}`} />
                <div className="bg-amber-500"  style={{ width: `${pct(m.inactive_mb, totalMb)}%` }} title={`Inactive ${fmtMb(m.inactive_mb)}`} />
                <div className="bg-purple-500" style={{ width: `${pct(m.cached_mb, totalMb)}%` }}   title={`Cached ${fmtMb(m.cached_mb)}`} />
                <div className="bg-gray-600"   style={{ width: `${pct(m.free_mb, totalMb)}%` }}     title={`Free ${fmtMb(m.free_mb)}`} />
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
                {[
                  ["Active",   m.active_mb,   "bg-blue-500"],
                  ["Wired",    m.wired_mb,    "bg-cyan-500"],
                  ["Inactive", m.inactive_mb, "bg-amber-500"],
                  ["Cached",   m.cached_mb,   "bg-purple-500"],
                  ["Free",     m.free_mb,     "bg-gray-600"],
                ].map(([label, val, color]) => (
                  <div key={label as string} className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded ${color as string}`} />
                    <div>
                      <div className="text-gray-500 text-[10px] uppercase tracking-wider">{label as string}</div>
                      <div className="text-white font-mono">{fmtMb(val as number)}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Per-component breakdown */}
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2 mt-2">
              <MemoryTile label="aifw-api RSS"     value={fmtMb(m.api_rss_mb)} />
              <MemoryTile label="aifw-daemon RSS"  value={fmtMb(m.daemon_rss_mb)} />
              <MemoryTile label="ZFS ARC"          value={fmtMb(m.arc_mb)} />
              <MemoryTile label="IDS alert buffer" value={`${fmtMb(m.ids_buffer_mb)} / ${fmtMb(m.ids_buffer_max_mb)}`} sub={`${fmtNum(m.ids_buffer_count)} alerts`} />
              <MemoryTile label="Dashboard history" value={fmtMb(m.metrics_history_mb)} sub={`${fmtNum(m.metrics_history_count)} entries`} />
              <MemoryTile label="pf state table"   value={`${fmtNum(m.pf_states)} / ${fmtNum(m.pf_states_max)}`} sub={`${pct(m.pf_states, m.pf_states_max)}%`} />
              <MemoryTile label="SQLite DB"        value={fmtMb(m.db_size_mb)} />
            </div>
          </div>
        );
      })()}

      {/* Links */}
      <div className="flex gap-3">
        <a
          href="https://github.com/ZerosAndOnesLLC/AiFw"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          AiFw on GitHub
        </a>
        <a
          href="https://github.com/ZerosAndOnesLLC/rDNS"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          rDNS
        </a>
        <a
          href="https://github.com/ZerosAndOnesLLC/rDHCP"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2 px-4 py-2 bg-gray-800 border border-gray-700 rounded-lg text-sm text-gray-300 hover:text-white hover:border-gray-500 transition-colors"
        >
          <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
          rDHCP
        </a>
      </div>

      {/* Services */}
      <div>
        <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">Services</h2>
        {loading ? (
          <div className="text-center py-8 text-gray-500">Loading service info...</div>
        ) : (
          <div className="space-y-2">
            {services.map((svc) => (
              <div key={svc.binary} className="bg-gray-800 border border-gray-700 rounded-lg px-4 py-3 flex items-center gap-4">
                <div className={`w-2 h-2 rounded-full flex-shrink-0 ${svc.running ? "bg-green-500" : "bg-red-500"}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-semibold ${svc.color}`}>{svc.name}</span>
                    <span className="text-[10px] text-gray-500 font-mono">{svc.binary}</span>
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">{svc.description}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <span className="text-xs font-mono text-gray-400">{svc.version}</span>
                  <div className={`text-[10px] mt-0.5 ${svc.running ? "text-green-400" : "text-red-400"}`}>
                    {svc.running ? "Running" : "Stopped"}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* License */}
      <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-3 text-xs text-gray-500">
        MIT License &middot; Copyright &copy; 2026 Zeros and Ones LLC
      </div>
    </div>
  );
}

function MemoryTile({ label, value, sub }: { label: string; value: string; sub?: string }) {
  return (
    <div className="bg-gray-800/60 border border-gray-700/60 rounded-lg px-3 py-2">
      <div className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</div>
      <div className="text-sm font-mono text-white">{value}</div>
      {sub && <div className="text-[10px] text-gray-500 mt-0.5">{sub}</div>}
    </div>
  );
}
