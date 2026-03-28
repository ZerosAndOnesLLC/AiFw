"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface DhcpStatus {
  running: boolean;
  version: string;
  total_subnets: number;
  total_reservations: number;
  active_leases: number;
}

interface DhcpGlobalConfig {
  enabled: boolean;
  interfaces: string[];
  authoritative: boolean;
  default_lease_time: number;
  max_lease_time: number;
  dns_servers: string[];
  domain_name: string;
  next_server: string;
  boot_filename: string;
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

const defaultConfig: DhcpGlobalConfig = {
  enabled: false,
  interfaces: [],
  authoritative: true,
  default_lease_time: 86400,
  max_lease_time: 172800,
  dns_servers: [],
  domain_name: "",
  next_server: "",
  boot_filename: "",
};

/* -- Page ------------------------------------------------------------ */

export default function DhcpOverviewPage() {
  const [status, setStatus] = useState<DhcpStatus | null>(null);
  const [config, setConfig] = useState<DhcpGlobalConfig>(defaultConfig);
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [applying, setApplying] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // form fields (managed separately for comma-separated inputs)
  const [dnsInput, setDnsInput] = useState("");

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/status", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStatus(await res.json());
    } catch {
      /* silent */
    }
  }, []);

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/v4/config", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: DhcpGlobalConfig = await res.json();
      setConfig(data);
      setDnsInput((data.dns_servers || []).join(", "));
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
      const res = await fetch(`/api/v1/dhcp/${action}`, {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", `DHCP server ${action}ed successfully`);
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : `Failed to ${action} DHCP`);
    } finally {
      setActionLoading(null);
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      const payload: DhcpGlobalConfig = {
        ...config,
        dns_servers: dnsInput
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean),
      };
      const res = await fetch("/api/v1/dhcp/v4/config", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Global settings saved");
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
      const res = await fetch("/api/v1/dhcp/v4/apply", {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Configuration applied and service restarted");
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to apply config");
    } finally {
      setApplying(false);
    }
  };

  const toggleInterface = (name: string) => {
    setConfig((prev) => ({
      ...prev,
      interfaces: prev.interfaces.includes(name)
        ? prev.interfaces.filter((i) => i !== name)
        : [...prev.interfaces, name],
    }));
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading DHCP status...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">DHCP Server</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage the DHCPv4 server, global settings, and service lifecycle
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

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm mb-5">
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Version</span>
            <span className="text-[var(--text-primary)] font-mono text-xs">
              {status?.version || "-"}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Subnets</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.total_subnets ?? 0}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Reservations</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.total_reservations ?? 0}
            </span>
          </div>
          <div>
            <span className="block text-xs text-[var(--text-muted)] mb-0.5">Active Leases</span>
            <span className="text-[var(--text-primary)] font-semibold">
              {status?.active_leases ?? 0}
            </span>
          </div>
        </div>

        <div className="flex gap-3">
          <button
            onClick={() => serviceAction("start")}
            disabled={!!actionLoading}
            className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            {actionLoading === "start" ? "Starting..." : "Start"}
          </button>
          <button
            onClick={() => serviceAction("stop")}
            disabled={!!actionLoading}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 10a1 1 0 011-1h4a1 1 0 011 1v4a1 1 0 01-1 1h-4a1 1 0 01-1-1v-4z" />
            </svg>
            {actionLoading === "stop" ? "Stopping..." : "Stop"}
          </button>
          <button
            onClick={() => serviceAction("restart")}
            disabled={!!actionLoading}
            className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            {actionLoading === "restart" ? "Restarting..." : "Restart"}
          </button>
        </div>
      </div>

      {/* -- Global Settings ----------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Global Settings</h2>

        <div className="space-y-5">
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
            <span className="text-sm text-[var(--text-primary)]">Enable DHCP Server</span>
          </div>

          {/* Interfaces multi-select */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1.5">
              Listen Interfaces
            </label>
            {interfaces.length === 0 ? (
              <p className="text-xs text-[var(--text-muted)]">No interfaces available</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {interfaces.map((iface) => {
                  const selected = config.interfaces.includes(iface);
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
            )}
          </div>

          {/* Authoritative */}
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setConfig((p) => ({ ...p, authoritative: !p.authoritative }))}
              className={`relative w-11 h-6 rounded-full transition-colors ${
                config.authoritative ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                  config.authoritative ? "translate-x-5" : ""
                }`}
              />
            </button>
            <span className="text-sm text-[var(--text-primary)]">Authoritative</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Default lease time */}
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">
                Default Lease Time (seconds)
              </label>
              <input
                type="number"
                value={config.default_lease_time}
                onChange={(e) =>
                  setConfig((p) => ({ ...p, default_lease_time: Number(e.target.value) }))
                }
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Max lease time */}
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">
                Max Lease Time (seconds)
              </label>
              <input
                type="number"
                value={config.max_lease_time}
                onChange={(e) =>
                  setConfig((p) => ({ ...p, max_lease_time: Number(e.target.value) }))
                }
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* DNS servers */}
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">
                DNS Servers (comma-separated)
              </label>
              <input
                type="text"
                value={dnsInput}
                onChange={(e) => setDnsInput(e.target.value)}
                placeholder="e.g. 1.1.1.1, 8.8.8.8"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Domain name */}
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Domain Name</label>
              <input
                type="text"
                value={config.domain_name}
                onChange={(e) => setConfig((p) => ({ ...p, domain_name: e.target.value }))}
                placeholder="e.g. home.lan"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          {/* PXE options */}
          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-3">PXE Boot Options</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Next Server</label>
                <input
                  type="text"
                  value={config.next_server}
                  onChange={(e) => setConfig((p) => ({ ...p, next_server: e.target.value }))}
                  placeholder="e.g. 192.168.1.10"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Boot Filename</label>
                <input
                  type="text"
                  value={config.boot_filename}
                  onChange={(e) => setConfig((p) => ({ ...p, boot_filename: e.target.value }))}
                  placeholder="e.g. pxelinux.0"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>

          {/* Save + Apply */}
          <div className="flex gap-3 pt-2">
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
