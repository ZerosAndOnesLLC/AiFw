"use client";

import { useState, useEffect, useCallback } from "react";

interface HaConfig {
  mode: string;
  peer?: string;
  listen?: string;
  scope_split?: number;
  mclt?: number;
  partner_down_delay?: number;
  node_id?: number;
  peers?: string[];
  tls_cert?: string;
  tls_key?: string;
  tls_ca?: string;
}

interface HaStatus {
  mode: string;
  role: string;
  peer_state?: string;
  healthy: boolean;
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

export default function HaConfigPage() {
  const [config, setConfig] = useState<HaConfig>({ mode: "standalone" });
  const [status, setStatus] = useState<HaStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [peersInput, setPeersInput] = useState("");
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/ha/config", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: HaConfig = await res.json();
      setConfig(data);
      setPeersInput((data.peers || []).join(", "));
    } catch { /* silent */ }
  }, []);

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/ha/status", { headers: authHeadersPlain() });
      if (!res.ok) return;
      setStatus(await res.json());
    } catch { /* silent — service may not be running */ }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchConfig(), fetchStatus()]);
      setLoading(false);
    })();
  }, [fetchConfig, fetchStatus]);

  const saveConfig = async () => {
    setSaving(true);
    try {
      const payload: HaConfig = { ...config };
      if (config.mode === "raft") {
        payload.peers = peersInput.split(",").map(s => s.trim()).filter(Boolean);
      }
      const res = await fetch("/api/v1/dhcp/ha/config", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "HA settings saved. Apply config to take effect.");
      await fetchConfig();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">Loading HA config...</div>;
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">High Availability</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Configure rDHCP failover: standalone, active/active split-scope, or Raft consensus
        </p>
      </div>

      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success"
            ? "bg-green-500/10 border-green-500/30 text-green-400"
            : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>{feedback.msg}</div>
      )}

      {/* Live HA Status */}
      {status && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-3">Live Status</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
            <div>
              <span className="block text-xs text-[var(--text-muted)] mb-0.5">Mode</span>
              <span className="text-[var(--text-primary)] font-semibold capitalize">{status.mode}</span>
            </div>
            <div>
              <span className="block text-xs text-[var(--text-muted)] mb-0.5">Role</span>
              <span className="text-[var(--text-primary)] font-semibold capitalize">{status.role}</span>
            </div>
            <div>
              <span className="block text-xs text-[var(--text-muted)] mb-0.5">Peer State</span>
              <span className="text-[var(--text-primary)] capitalize">{status.peer_state || "N/A"}</span>
            </div>
            <div>
              <span className="block text-xs text-[var(--text-muted)] mb-0.5">Health</span>
              <span className={`text-xs px-2 py-0.5 rounded-full border ${
                status.healthy
                  ? "bg-green-500/20 text-green-400 border-green-500/30"
                  : "bg-red-500/20 text-red-400 border-red-500/30"
              }`}>
                {status.healthy ? "Healthy" : "Unhealthy"}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* HA Configuration */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-5">
        <h2 className="text-lg font-semibold">Configuration</h2>

        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">HA Mode</label>
          <select
            value={config.mode}
            onChange={(e) => setConfig((p) => ({ ...p, mode: e.target.value }))}
            className="w-full max-w-xs px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          >
            <option value="standalone">Standalone (no HA)</option>
            <option value="active-active">Active/Active (split-scope)</option>
            <option value="raft">Raft Consensus (3+ nodes)</option>
          </select>
        </div>

        {/* Active-Active settings */}
        {config.mode === "active-active" && (
          <div className="space-y-4 border-t border-[var(--border)] pt-4">
            <h3 className="text-sm font-medium text-[var(--text-secondary)]">Active/Active Settings</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Peer Address</label>
                <input
                  type="text"
                  value={config.peer || ""}
                  onChange={(e) => setConfig((p) => ({ ...p, peer: e.target.value }))}
                  placeholder="e.g. 10.0.0.2:9000"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Listen Address</label>
                <input
                  type="text"
                  value={config.listen || ""}
                  onChange={(e) => setConfig((p) => ({ ...p, listen: e.target.value }))}
                  placeholder="e.g. 0.0.0.0:9000"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Scope Split (0.0-1.0)</label>
                <input
                  type="number"
                  step="0.1"
                  value={config.scope_split ?? 0.5}
                  onChange={(e) => setConfig((p) => ({ ...p, scope_split: Number(e.target.value) }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-[var(--text-muted)] mt-1">Fraction of pool served by this node</p>
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">MCLT (seconds)</label>
                <input
                  type="number"
                  value={config.mclt ?? 3600}
                  onChange={(e) => setConfig((p) => ({ ...p, mclt: Number(e.target.value) }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-[var(--text-muted)] mt-1">Max client lead time</p>
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Partner Down Delay (s)</label>
                <input
                  type="number"
                  value={config.partner_down_delay ?? 3600}
                  onChange={(e) => setConfig((p) => ({ ...p, partner_down_delay: Number(e.target.value) }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>
        )}

        {/* Raft settings */}
        {config.mode === "raft" && (
          <div className="space-y-4 border-t border-[var(--border)] pt-4">
            <h3 className="text-sm font-medium text-[var(--text-secondary)]">Raft Settings</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Node ID</label>
                <input
                  type="number"
                  value={config.node_id ?? 1}
                  onChange={(e) => setConfig((p) => ({ ...p, node_id: Number(e.target.value) }))}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Peer Addresses (comma-separated)</label>
                <input
                  type="text"
                  value={peersInput}
                  onChange={(e) => setPeersInput(e.target.value)}
                  placeholder="10.0.0.2:9000, 10.0.0.3:9000"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>
        )}

        {/* TLS (shared by active-active and raft) */}
        {config.mode !== "standalone" && (
          <div className="space-y-4 border-t border-[var(--border)] pt-4">
            <h3 className="text-sm font-medium text-[var(--text-secondary)]">mTLS (peer communication)</h3>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">TLS Certificate</label>
                <input
                  type="text"
                  value={config.tls_cert || ""}
                  onChange={(e) => setConfig((p) => ({ ...p, tls_cert: e.target.value }))}
                  placeholder="/path/to/cert.pem"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">TLS Key</label>
                <input
                  type="text"
                  value={config.tls_key || ""}
                  onChange={(e) => setConfig((p) => ({ ...p, tls_key: e.target.value }))}
                  placeholder="/path/to/key.pem"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">TLS CA</label>
                <input
                  type="text"
                  value={config.tls_ca || ""}
                  onChange={(e) => setConfig((p) => ({ ...p, tls_ca: e.target.value }))}
                  placeholder="/path/to/ca.pem"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            </div>
          </div>
        )}

        <div className="pt-2">
          <button
            onClick={saveConfig}
            disabled={saving}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save HA Settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
