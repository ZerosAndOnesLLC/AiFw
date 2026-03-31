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

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

export default function AboutPage() {
  const [services, setServices] = useState<ServiceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [aifwVersion, setAifwVersion] = useState("");

  useEffect(() => {
    (async () => {
      const headers = authHeaders();
      const results: ServiceInfo[] = [];

      // AiFw API version
      try {
        const res = await fetch("/api/v1/status", { headers });
        if (res.ok) {
          const data = await res.json();
          setAifwVersion(data.version || data.data?.version || "");
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
        const res = await fetch("/api/v1/traffic/status", { headers });
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
        <div>
          <h1 className="text-2xl font-bold text-white">AiFw</h1>
          <p className="text-sm text-gray-400">AI-Powered Firewall for FreeBSD</p>
          <p className="text-xs text-gray-500 mt-0.5">No garbage collectors. Pure Rust, C, and C++ on pf.</p>
        </div>
      </div>

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
