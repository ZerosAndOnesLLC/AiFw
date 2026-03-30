"use client";

import { useState, useEffect, useCallback } from "react";

interface DdnsConfig {
  enabled: boolean;
  forward_zone: string;
  reverse_zone_v4: string;
  reverse_zone_v6: string;
  dns_server: string;
  tsig_key: string;
  tsig_algorithm: string;
  tsig_secret: string;
  ttl: number;
}

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

const defaultConfig: DdnsConfig = {
  enabled: false,
  forward_zone: "",
  reverse_zone_v4: "",
  reverse_zone_v6: "",
  dns_server: "",
  tsig_key: "",
  tsig_algorithm: "hmac-sha256",
  tsig_secret: "",
  ttl: 300,
};

export default function DdnsConfigPage() {
  const [config, setConfig] = useState<DdnsConfig>(defaultConfig);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/ddns", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setConfig(await res.json());
    } catch {
      /* silent */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchConfig(); }, [fetchConfig]);

  const saveConfig = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/v1/dhcp/ddns", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(config),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "DDNS settings saved. Apply config to take effect.");
      await fetchConfig();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">Loading DDNS config...</div>;
  }

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Dynamic DNS</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Automatically register DHCP leases in DNS via RFC 2136 updates with TSIG authentication
        </p>
      </div>

      {feedback && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${
          feedback.type === "success"
            ? "bg-green-500/10 border-green-500/30 text-green-400"
            : "bg-red-500/10 border-red-500/30 text-red-400"
        }`}>{feedback.msg}</div>
      )}

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 space-y-5">
        {/* Enable */}
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setConfig((p) => ({ ...p, enabled: !p.enabled }))}
            className={`relative w-11 h-6 rounded-full transition-colors ${config.enabled ? "bg-blue-600" : "bg-gray-600"}`}
          >
            <span className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${config.enabled ? "translate-x-5" : ""}`} />
          </button>
          <span className="text-sm text-[var(--text-primary)]">Enable Dynamic DNS Updates</span>
        </div>

        {/* DNS Zones */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Forward Zone</label>
            <input
              type="text"
              value={config.forward_zone}
              onChange={(e) => setConfig((p) => ({ ...p, forward_zone: e.target.value }))}
              placeholder="e.g. example.com"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <p className="text-[10px] text-[var(--text-muted)] mt-1">Zone for A/AAAA records</p>
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">DNS Server</label>
            <input
              type="text"
              value={config.dns_server}
              onChange={(e) => setConfig((p) => ({ ...p, dns_server: e.target.value }))}
              placeholder="e.g. 10.0.0.53"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <p className="text-[10px] text-[var(--text-muted)] mt-1">Authoritative NS to send updates to</p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Reverse Zone (IPv4)</label>
            <input
              type="text"
              value={config.reverse_zone_v4}
              onChange={(e) => setConfig((p) => ({ ...p, reverse_zone_v4: e.target.value }))}
              placeholder="e.g. 1.168.192.in-addr.arpa"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Reverse Zone (IPv6)</label>
            <input
              type="text"
              value={config.reverse_zone_v6}
              onChange={(e) => setConfig((p) => ({ ...p, reverse_zone_v6: e.target.value }))}
              placeholder="Optional"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        {/* TSIG Authentication */}
        <div>
          <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-3">TSIG Authentication</h3>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">TSIG Key Name</label>
              <input
                type="text"
                value={config.tsig_key}
                onChange={(e) => setConfig((p) => ({ ...p, tsig_key: e.target.value }))}
                placeholder="e.g. dhcp-key"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Algorithm</label>
              <select
                value={config.tsig_algorithm}
                onChange={(e) => setConfig((p) => ({ ...p, tsig_algorithm: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
              >
                <option value="hmac-sha256">HMAC-SHA256</option>
                <option value="hmac-sha512">HMAC-SHA512</option>
                <option value="hmac-md5">HMAC-MD5 (legacy)</option>
              </select>
            </div>
          </div>
          <div className="mt-4">
            <label className="block text-xs text-[var(--text-muted)] mb-1">TSIG Secret (base64)</label>
            <input
              type="password"
              value={config.tsig_secret}
              onChange={(e) => setConfig((p) => ({ ...p, tsig_secret: e.target.value }))}
              placeholder="Base64-encoded shared secret"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>
        </div>

        {/* TTL */}
        <div className="w-48">
          <label className="block text-xs text-[var(--text-muted)] mb-1">DNS Record TTL (seconds)</label>
          <input
            type="number"
            value={config.ttl}
            onChange={(e) => setConfig((p) => ({ ...p, ttl: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="pt-2">
          <button
            onClick={saveConfig}
            disabled={saving}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
          >
            {saving ? "Saving..." : "Save DDNS Settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
