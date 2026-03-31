"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface DnsStatus {
  running: boolean;
  version: string;
  total_hosts: number;
  total_domains: number;
  total_acls: number;
  cache_hits: number;
  cache_misses: number;
  queries_total: number;
}

interface ResolverConfig {
  backend: string;
  enabled: boolean;
  listen_interfaces: string[];
  port: number;
  dnssec: boolean;
  dns64: boolean;
  register_dhcp: boolean;
  dhcp_domain: string;
  local_zone_type: string;
  outgoing_interface: string;
  num_threads: number;
  msg_cache_size: number;
  rrset_cache_size: number;
  cache_max_ttl: number;
  cache_min_ttl: number;
  prefetch: boolean;
  prefetch_key: boolean;
  infra_host_ttl: number;
  unwanted_reply_threshold: number;
  log_queries: boolean;
  log_replies: boolean;
  log_verbosity: number;
  hide_identity: boolean;
  hide_version: boolean;
  rebind_protection: boolean;
  private_addresses: string[];
  dot_enabled: boolean;
  dot_upstream: string[];
  blocklists_enabled: boolean;
  blocklist_urls: string[];
  whitelist: string[];
  blocklist_action: string;
  blocklist_redirect_ip: string;
  custom_options: string;
}

interface NetInterface {
  name: string;
}

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

const defaultConfig: ResolverConfig = {
  backend: "rdns",
  enabled: false,
  listen_interfaces: [],
  port: 53,
  dnssec: true,
  dns64: false,
  register_dhcp: false,
  dhcp_domain: "local",
  local_zone_type: "transparent",
  outgoing_interface: "",
  num_threads: 2,
  msg_cache_size: 4,
  rrset_cache_size: 4,
  cache_max_ttl: 86400,
  cache_min_ttl: 0,
  prefetch: true,
  prefetch_key: false,
  infra_host_ttl: 900,
  unwanted_reply_threshold: 0,
  log_queries: false,
  log_replies: false,
  log_verbosity: 1,
  hide_identity: true,
  hide_version: true,
  rebind_protection: true,
  private_addresses: [],
  dot_enabled: false,
  dot_upstream: [],
  blocklists_enabled: false,
  blocklist_urls: [],
  whitelist: [],
  blocklist_action: "nxdomain",
  blocklist_redirect_ip: "",
  custom_options: "",
};

const TABS = ["General", "DNS over TLS", "Blocklists", "Advanced", "Custom"] as const;
type Tab = (typeof TABS)[number];

const LOCAL_ZONE_TYPES = [
  "transparent",
  "typetransparent",
  "static",
  "redirect",
  "deny",
  "refuse",
  "inform",
  "inform_deny",
  "inform_redirect",
  "always_transparent",
  "always_refuse",
  "always_nxdomain",
  "nodefault",
];

/* -- Page ------------------------------------------------------------ */

export default function DnsResolverPage() {
  const [status, setStatus] = useState<DnsStatus | null>(null);
  const [config, setConfig] = useState<ResolverConfig>(defaultConfig);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [applying, setApplying] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("General");

  // list inputs
  const [dotUpstreamInput, setDotUpstreamInput] = useState("");
  const [blocklistUrlInput, setBlocklistUrlInput] = useState("");
  const [whitelistInput, setWhitelistInput] = useState("");
  const [privateAddrInput, setPrivateAddrInput] = useState("");

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dns/resolver/status", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStatus(await res.json());
    } catch {
      /* silent */
    }
  }, []);

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dns/resolver/config", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: ResolverConfig = await res.json();
      setConfig(data);
    } catch {
      /* silent */
    }
  }, []);

  const fetchInterfaces = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/interfaces", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      const names = (body.data || [])
        .map((i: NetInterface) => i.name)
        .filter((n: string) => !n.startsWith("lo") && !n.startsWith("pflog"));
      setInterfaces(names);
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchStatus(), fetchConfig(), fetchInterfaces()]);
      setLoading(false);
    })();
  }, [fetchStatus, fetchConfig, fetchInterfaces]);

  /* -- Actions ------------------------------------------------------ */

  const serviceAction = async (action: "start" | "stop" | "restart") => {
    setActionLoading(action);
    try {
      const res = await fetch(`/api/v1/dns/resolver/${action}`, {
        method: "POST",
        headers: authHeaders(),
      });
      const data = await res.json().catch(() => ({ message: "" }));
      const msg = data.message || `DNS Resolver ${action} completed`;
      if (msg.toLowerCase().includes("fail") || msg.toLowerCase().includes("error")) {
        showFeedback("error", msg);
      } else {
        showFeedback("success", msg);
      }
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : `Failed to ${action} DNS Resolver`);
    } finally {
      setActionLoading(null);
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/v1/dns/resolver/config", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(config),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "DNS Resolver settings saved");
      await fetchConfig();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save config");
    } finally {
      setSaving(false);
    }
  };

  const applyConfig = async () => {
    setApplying(true);
    try {
      // Save config first, then apply
      const saveRes = await fetch("/api/v1/dns/resolver/config", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(config),
      });
      if (!saveRes.ok) throw new Error(`Save failed: HTTP ${saveRes.status}`);

      const res = await fetch("/api/v1/dns/resolver/apply", {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`Apply failed: HTTP ${res.status}`);
      const data = await res.json().catch(() => ({ message: "" }));
      showFeedback("success", data.message || "Configuration applied and service restarted");
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to apply config");
    } finally {
      setApplying(false);
    }
  };

  const isAllInterfaces = config.listen_interfaces.length === 0 ||
    (config.listen_interfaces.length === 1 && config.listen_interfaces[0] === "0.0.0.0");

  const toggleInterface = (name: string) => {
    if (name === "__all__") {
      // Toggle "All" — set to 0.0.0.0 (listen on everything)
      setConfig((prev) => ({
        ...prev,
        listen_interfaces: ["0.0.0.0"],
      }));
      return;
    }
    // Clicking a specific interface: remove "all" wildcard, toggle this one
    setConfig((prev) => {
      const filtered = prev.listen_interfaces.filter((i) => i !== "0.0.0.0");
      return {
        ...prev,
        listen_interfaces: filtered.includes(name)
          ? filtered.filter((i) => i !== name)
          : [...filtered, name],
      };
    });
  };

  /* -- List helpers ------------------------------------------------- */

  const addToList = (field: keyof ResolverConfig, value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    setConfig((prev) => {
      const arr = prev[field] as string[];
      if (arr.includes(trimmed)) return prev;
      return { ...prev, [field]: [...arr, trimmed] };
    });
  };

  const removeFromList = (field: keyof ResolverConfig, index: number) => {
    setConfig((prev) => {
      const arr = [...(prev[field] as string[])];
      arr.splice(index, 1);
      return { ...prev, [field]: arr };
    });
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading DNS Resolver status...
      </div>
    );
  }

  const cacheTotal = (status?.cache_hits ?? 0) + (status?.cache_misses ?? 0);
  const cacheHitRate = cacheTotal > 0 ? ((status?.cache_hits ?? 0) / cacheTotal * 100).toFixed(1) : "0";

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">DNS Resolver</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage the Unbound DNS resolver, caching, and security settings
        </p>
      </div>

      {/* Feedback */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* -- Status Card --------------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold">Service Status</h2>
          <span
            className={`text-xs px-2.5 py-1 rounded-full border font-medium ${
              status?.running
                ? "bg-green-500/20 text-green-400 border-green-500/30"
                : "bg-red-500/20 text-red-400 border-red-500/30"
            }`}
          >
            {status?.running ? "Running" : "Stopped"}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-4 text-sm mb-5">
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Version</span>
            <span className="text-[var(--text-primary)] font-mono text-xs">
              {status?.version || "-"}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Total Queries</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.queries_total ?? 0}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Cache Hit Rate</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {cacheHitRate}%
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Host Overrides</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.total_hosts ?? 0}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Domain Overrides</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.total_domains ?? 0}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Access Lists</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.total_acls ?? 0}
            </span>
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => serviceAction("start")}
            disabled={!!actionLoading || !!status?.running}
            className={`px-4 py-2 text-white text-sm rounded-md flex items-center gap-2 ${
              status?.running
                ? "bg-green-600/30 text-green-400/50 cursor-not-allowed"
                : "bg-green-600 hover:bg-green-700 disabled:opacity-50"
            }`}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {actionLoading === "start" ? "Starting..." : "Start"}
          </button>
          <button
            onClick={() => serviceAction("stop")}
            disabled={!!actionLoading || !status?.running}
            className={`px-4 py-2 text-white text-sm rounded-md flex items-center gap-2 ${
              !status?.running
                ? "bg-red-600/30 text-red-400/50 cursor-not-allowed"
                : "bg-red-600 hover:bg-red-700 disabled:opacity-50"
            }`}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
            </svg>
            {actionLoading === "stop" ? "Stopping..." : "Stop"}
          </button>
          <button
            onClick={() => serviceAction("restart")}
            disabled={!!actionLoading || !status?.running}
            className={`px-4 py-2 text-white text-sm rounded-md flex items-center gap-2 ${
              !status?.running
                ? "bg-yellow-600/30 text-yellow-400/50 cursor-not-allowed"
                : "bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50"
            }`}
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {actionLoading === "restart" ? "Restarting..." : "Restart"}
          </button>
          <button
            onClick={applyConfig}
            disabled={applying}
            className="px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 ml-auto"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {applying ? "Applying..." : "Apply & Restart"}
          </button>
        </div>
      </div>

      {/* -- Tabbed Settings ----------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {/* Tab bar */}
        <div className="flex border-b border-[var(--border)] overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-sm font-medium whitespace-nowrap transition-colors ${
                activeTab === tab
                  ? "text-blue-400 border-b-2 border-blue-400"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* ===================== General Tab ===================== */}
          {activeTab === "General" && (
            <div className="space-y-5">
              {/* Backend selector */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-2">DNS Backend</label>
                <div className="flex gap-2">
                  {[
                    { value: "rdns", label: "rDNS", desc: "High-performance resolver with DNSSEC, RPZ, DoT" },
                    { value: "unbound", label: "Unbound", desc: "Traditional recursive resolver" },
                  ].map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => setConfig((p) => ({ ...p, backend: opt.value }))}
                      className={`flex-1 px-4 py-3 rounded-lg border text-left transition-colors ${
                        config.backend === opt.value
                          ? "bg-blue-600/15 border-blue-500/50 text-blue-400"
                          : "bg-gray-900 border-gray-700 text-[var(--text-secondary)] hover:border-gray-500"
                      }`}
                    >
                      <div className="text-sm font-medium">{opt.label}</div>
                      <div className="text-[10px] text-[var(--text-muted)] mt-0.5">{opt.desc}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Enable toggle */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, enabled: !p.enabled }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.enabled ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">Enable DNS Resolver</span>
              </div>

              {/* Listen interfaces */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1.5">
                  Listen Interfaces
                </label>
                <div className="flex flex-wrap gap-2">
                  <button
                    onClick={() => toggleInterface("__all__")}
                    className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
                      isAllInterfaces
                        ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                        : "bg-gray-900 border-gray-700 text-[var(--text-secondary)] hover:border-gray-500"
                    }`}
                  >
                    All
                  </button>
                  {interfaces.map((iface) => {
                    const selected = !isAllInterfaces && config.listen_interfaces.includes(iface);
                    return (
                      <button
                        key={iface}
                        onClick={() => toggleInterface(iface)}
                        className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
                          selected
                            ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                            : "bg-gray-900 border-gray-700 text-[var(--text-secondary)] hover:border-gray-500"
                        }`}
                      >
                        {iface}
                      </button>
                    );
                  })}
                </div>
                <p className="text-xs text-[var(--text-muted)] mt-1">
                  {isAllInterfaces ? "Listening on all interfaces (0.0.0.0)" : `Listening on ${config.listen_interfaces.length} selected interface(s)`}
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Port */}
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Listen Port</label>
                  <input
                    type="number"
                    value={config.port}
                    onChange={(e) => setConfig((p) => ({ ...p, port: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                {/* Local zone type */}
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Local Zone Type</label>
                  <select
                    value={config.local_zone_type}
                    onChange={(e) => setConfig((p) => ({ ...p, local_zone_type: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    {LOCAL_ZONE_TYPES.map((t) => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>

              {/* DNSSEC toggle */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, dnssec: !p.dnssec }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.dnssec ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.dnssec ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">DNSSEC Validation</span>
              </div>

              {/* DNS64 toggle */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, dns64: !p.dns64 }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.dns64 ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.dns64 ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">DNS64</span>
              </div>

              {/* Register DHCP leases */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, register_dhcp: !p.register_dhcp }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.register_dhcp ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.register_dhcp ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">Register DHCP Leases in DNS</span>
              </div>

              {/* DHCP domain */}
              {config.register_dhcp && (
                <div className="max-w-xs">
                  <label className="block text-xs text-[var(--text-muted)] mb-1.5">
                    DHCP Lease Domain
                  </label>
                  <input
                    type="text"
                    value={config.dhcp_domain || ""}
                    onChange={(e) => setConfig((p) => ({ ...p, dhcp_domain: e.target.value }))}
                    placeholder="local"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                  <p className="text-[10px] text-[var(--text-muted)] mt-1">
                    DHCP clients will be registered as hostname.{config.dhcp_domain || "local"}
                  </p>
                </div>
              )}
            </div>
          )}

          {/* ===================== DNS over TLS Tab ================ */}
          {activeTab === "DNS over TLS" && (
            <div className="space-y-5">
              {/* DoT enable */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, dot_enabled: !p.dot_enabled }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.dot_enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.dot_enabled ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">Enable DNS over TLS</span>
              </div>

              {/* DoT upstream servers */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1.5">
                  Upstream DoT Servers
                </label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    value={dotUpstreamInput}
                    onChange={(e) => setDotUpstreamInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        addToList("dot_upstream", dotUpstreamInput);
                        setDotUpstreamInput("");
                      }
                    }}
                    placeholder="e.g. 1.1.1.1@853#cloudflare-dns.com"
                    className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={() => {
                      addToList("dot_upstream", dotUpstreamInput);
                      setDotUpstreamInput("");
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
                  >
                    Add
                  </button>
                </div>
                {config.dot_upstream.length > 0 && (
                  <div className="space-y-1">
                    {config.dot_upstream.map((server, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md"
                      >
                        <span className="text-xs font-mono text-[var(--text-secondary)]">{server}</span>
                        <button
                          onClick={() => removeFromList("dot_upstream", i)}
                          className="text-red-400 hover:text-red-300 text-xs ml-2"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== Blocklists Tab ================== */}
          {activeTab === "Blocklists" && (
            <div className="space-y-5">
              {/* Enable blocklists */}
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, blocklists_enabled: !p.blocklists_enabled }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.blocklists_enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.blocklists_enabled ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">Enable Blocklists</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Blocklist action */}
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Block Action</label>
                  <select
                    value={config.blocklist_action}
                    onChange={(e) => setConfig((p) => ({ ...p, blocklist_action: e.target.value }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    <option value="nxdomain">NXDOMAIN</option>
                    <option value="redirect">Redirect</option>
                  </select>
                </div>

                {/* Redirect IP */}
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Redirect IP (if redirect)</label>
                  <input
                    type="text"
                    value={config.blocklist_redirect_ip}
                    onChange={(e) => setConfig((p) => ({ ...p, blocklist_redirect_ip: e.target.value }))}
                    placeholder="e.g. 0.0.0.0"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              {/* Blocklist URLs */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1.5">Blocklist URLs</label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    value={blocklistUrlInput}
                    onChange={(e) => setBlocklistUrlInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        addToList("blocklist_urls", blocklistUrlInput);
                        setBlocklistUrlInput("");
                      }
                    }}
                    placeholder="https://example.com/blocklist.txt"
                    className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={() => {
                      addToList("blocklist_urls", blocklistUrlInput);
                      setBlocklistUrlInput("");
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
                  >
                    Add
                  </button>
                </div>
                {config.blocklist_urls.length > 0 && (
                  <div className="space-y-1">
                    {config.blocklist_urls.map((url, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md"
                      >
                        <span className="text-xs font-mono text-[var(--text-secondary)] truncate mr-2">{url}</span>
                        <button
                          onClick={() => removeFromList("blocklist_urls", i)}
                          className="text-red-400 hover:text-red-300 text-xs flex-shrink-0"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Whitelist entries */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1.5">Whitelist Entries</label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    value={whitelistInput}
                    onChange={(e) => setWhitelistInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        addToList("whitelist", whitelistInput);
                        setWhitelistInput("");
                      }
                    }}
                    placeholder="e.g. allowed-domain.com"
                    className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={() => {
                      addToList("whitelist", whitelistInput);
                      setWhitelistInput("");
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
                  >
                    Add
                  </button>
                </div>
                {config.whitelist.length > 0 && (
                  <div className="space-y-1">
                    {config.whitelist.map((entry, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md"
                      >
                        <span className="text-xs font-mono text-[var(--text-secondary)]">{entry}</span>
                        <button
                          onClick={() => removeFromList("whitelist", i)}
                          className="text-red-400 hover:text-red-300 text-xs"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== Advanced Tab ==================== */}
          {activeTab === "Advanced" && (
            <div className="space-y-5">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Outgoing Interface</label>
                <input
                  type="text"
                  value={config.outgoing_interface}
                  onChange={(e) => setConfig((p) => ({ ...p, outgoing_interface: e.target.value }))}
                  placeholder="Leave blank for auto"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <h3 className="text-sm font-medium text-[var(--text-secondary)]">Cache & Threading</h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Threads</label>
                  <input
                    type="number"
                    value={config.num_threads}
                    onChange={(e) => setConfig((p) => ({ ...p, num_threads: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Message Cache Size (MB)</label>
                  <input
                    type="number"
                    value={config.msg_cache_size}
                    onChange={(e) => setConfig((p) => ({ ...p, msg_cache_size: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">RRset Cache Size (MB)</label>
                  <input
                    type="number"
                    value={config.rrset_cache_size}
                    onChange={(e) => setConfig((p) => ({ ...p, rrset_cache_size: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <h3 className="text-sm font-medium text-[var(--text-secondary)]">TTL Settings</h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Cache Max TTL (seconds)</label>
                  <input
                    type="number"
                    value={config.cache_max_ttl}
                    onChange={(e) => setConfig((p) => ({ ...p, cache_max_ttl: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Cache Min TTL (seconds)</label>
                  <input
                    type="number"
                    value={config.cache_min_ttl}
                    onChange={(e) => setConfig((p) => ({ ...p, cache_min_ttl: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Infra Host TTL (seconds)</label>
                  <input
                    type="number"
                    value={config.infra_host_ttl}
                    onChange={(e) => setConfig((p) => ({ ...p, infra_host_ttl: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* Prefetch */}
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setConfig((p) => ({ ...p, prefetch: !p.prefetch }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      config.prefetch ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        config.prefetch ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Prefetch</span>
                </div>
                {/* Prefetch Key */}
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setConfig((p) => ({ ...p, prefetch_key: !p.prefetch_key }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      config.prefetch_key ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        config.prefetch_key ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Prefetch DNSKEY</span>
                </div>
              </div>

              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Unwanted Reply Threshold</label>
                <input
                  type="number"
                  value={config.unwanted_reply_threshold}
                  onChange={(e) => setConfig((p) => ({ ...p, unwanted_reply_threshold: Number(e.target.value) }))}
                  placeholder="0 = disabled"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-[var(--text-muted)] mt-1">Number of unwanted replies to trigger defensive action. 0 to disable.</p>
              </div>

              <h3 className="text-sm font-medium text-[var(--text-secondary)]">Logging</h3>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setConfig((p) => ({ ...p, log_queries: !p.log_queries }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      config.log_queries ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        config.log_queries ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Log Queries</span>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setConfig((p) => ({ ...p, log_replies: !p.log_replies }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      config.log_replies ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        config.log_replies ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Log Replies</span>
                </div>
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Log Verbosity</label>
                  <select
                    value={config.log_verbosity}
                    onChange={(e) => setConfig((p) => ({ ...p, log_verbosity: Number(e.target.value) }))}
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                  >
                    {[0, 1, 2, 3, 4, 5].map((v) => (
                      <option key={v} value={v}>Level {v}</option>
                    ))}
                  </select>
                </div>
              </div>

              <h3 className="text-sm font-medium text-[var(--text-secondary)]">Privacy & Security</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setConfig((p) => ({ ...p, hide_identity: !p.hide_identity }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      config.hide_identity ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        config.hide_identity ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Hide Identity</span>
                </div>
                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setConfig((p) => ({ ...p, hide_version: !p.hide_version }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      config.hide_version ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        config.hide_version ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Hide Version</span>
                </div>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, rebind_protection: !p.rebind_protection }))}
                  className={`relative w-11 h-6 rounded-full transition-colors ${
                    config.rebind_protection ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                      config.rebind_protection ? "translate-x-5" : ""
                    }`}
                  />
                </button>
                <span className="text-sm text-[var(--text-primary)]">DNS Rebind Protection</span>
              </div>

              {/* Private addresses */}
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1.5">
                  Private Addresses (rebind protection exemptions)
                </label>
                <div className="flex gap-2 mb-2">
                  <input
                    type="text"
                    value={privateAddrInput}
                    onChange={(e) => setPrivateAddrInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        addToList("private_addresses", privateAddrInput);
                        setPrivateAddrInput("");
                      }
                    }}
                    placeholder="e.g. 10.0.0.0/8"
                    className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={() => {
                      addToList("private_addresses", privateAddrInput);
                      setPrivateAddrInput("");
                    }}
                    className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
                  >
                    Add
                  </button>
                </div>
                {config.private_addresses.length > 0 && (
                  <div className="space-y-1">
                    {config.private_addresses.map((addr, i) => (
                      <div
                        key={i}
                        className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md"
                      >
                        <span className="text-xs font-mono text-[var(--text-secondary)]">{addr}</span>
                        <button
                          onClick={() => removeFromList("private_addresses", i)}
                          className="text-red-400 hover:text-red-300 text-xs"
                        >
                          Remove
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ===================== Custom Tab ====================== */}
          {activeTab === "Custom" && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1.5">
                  Custom Unbound Configuration
                </label>
                <p className="text-[10px] text-[var(--text-muted)] mb-2">
                  Raw unbound.conf lines appended to the generated configuration. Use with caution.
                </p>
                <textarea
                  value={config.custom_options}
                  onChange={(e) => setConfig((p) => ({ ...p, custom_options: e.target.value }))}
                  rows={12}
                  placeholder="# Custom unbound options..."
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 font-mono focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          )}

          {/* Save */}
          <div className="flex gap-3 pt-4 mt-4 border-t border-[var(--border)]">
            <button
              onClick={saveConfig}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              {saving ? "Saving..." : "Save Settings"}
            </button>
            <button
              onClick={applyConfig}
              disabled={applying}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {applying ? "Applying..." : "Apply & Restart"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
