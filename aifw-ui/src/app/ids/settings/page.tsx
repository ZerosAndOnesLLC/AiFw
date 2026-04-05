"use client";

import { useState, useEffect, useCallback } from "react";

const API = "";

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return {
    "Content-Type": "application/json",
    Authorization: `Bearer ${token}`,
  };
}

interface IdsConfig {
  mode: string;
  home_net: string[];
  external_net: string[];
  alert_retention_days: number;
  eve_log_enabled: boolean;
  eve_log_path: string;
  syslog_target: string;
  worker_count: number | null;
  flow_table_size: number | null;
  stream_depth: number | null;
}

interface SectionFeedback {
  type: "success" | "error";
  message: string;
}

function FeedbackBanner({ feedback }: { feedback: SectionFeedback | null }) {
  if (!feedback) return null;
  const isError = feedback.type === "error";
  return (
    <div
      className={`p-3 text-sm rounded-md border ${
        isError
          ? "text-red-400 bg-red-500/10 border-red-500/20"
          : "text-green-400 bg-green-500/10 border-green-500/20"
      }`}
    >
      {feedback.message}
    </div>
  );
}

const modeOptions = [
  { value: "disabled", label: "Disabled", desc: "IDS engine is not running" },
  { value: "ids", label: "IDS", desc: "Monitor and alert only" },
  { value: "ips", label: "IPS", desc: "Actively block detected threats" },
];

export default function IdsSettingsPage() {
  const [config, setConfig] = useState<IdsConfig>({
    mode: "disabled",
    home_net: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
    external_net: ["!$HOME_NET"],
    alert_retention_days: 30,
    eve_log_enabled: false,
    eve_log_path: "/var/log/aifw/eve.json",
    syslog_target: "",
    worker_count: null,
    flow_table_size: null,
    stream_depth: null,
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);

  // CIDR add input
  const [newCidr, setNewCidr] = useState("");

  const clearFeedback = useCallback(() => {
    setTimeout(() => setFeedback(null), 4000);
  }, []);

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch(`${API}/api/v1/ids/config`, { headers: authHeaders() });
      if (!res.ok) throw new Error(`Failed to fetch config: ${res.status}`);
      const json = await res.json();
      const d = json.data || json;
      setConfig({
        mode: d.mode || "disabled",
        home_net: d.home_net || ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        external_net: d.external_net || ["!$HOME_NET"],
        alert_retention_days: d.alert_retention_days ?? 30,
        eve_log_enabled: d.eve_log_enabled ?? false,
        eve_log_path: d.eve_log_path || "/var/log/aifw/eve.json",
        syslog_target: d.syslog_target || "",
        worker_count: d.worker_count ?? null,
        flow_table_size: d.flow_table_size ?? null,
        stream_depth: d.stream_depth ?? null,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to load config";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setLoading(false);
    }
  }, [clearFeedback]);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  async function handleSave() {
    setSaving(true);
    setFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/ids/config`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(config),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `Save failed: ${res.status}`);
      }
      setFeedback({ type: "success", message: "Configuration saved" });
      clearFeedback();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to save config";
      setFeedback({ type: "error", message: msg });
      clearFeedback();
    } finally {
      setSaving(false);
    }
  }

  function addCidr() {
    const cidr = newCidr.trim();
    if (!cidr) return;
    // Basic CIDR validation
    if (!/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(cidr)) return;
    if (config.home_net.includes(cidr)) return;
    setConfig({ ...config, home_net: [...config.home_net, cidr] });
    setNewCidr("");
  }

  function removeCidr(cidr: string) {
    setConfig({ ...config, home_net: config.home_net.filter((c) => c !== cidr) });
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-3" />
          <p className="text-sm text-[var(--text-muted)]">Loading settings...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">IDS Settings</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Configure the intrusion detection engine
          </p>
        </div>
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-4 py-2 bg-green-600 hover:bg-green-500 disabled:opacity-40 text-white text-sm font-medium rounded-md transition-colors"
        >
          {saving ? "Saving..." : "Save Configuration"}
        </button>
      </div>

      <FeedbackBanner feedback={feedback} />

      {/* Engine Mode */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="text-sm font-medium mb-3">Engine Mode</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {modeOptions.map((opt) => (
            <button
              key={opt.value}
              onClick={() => setConfig({ ...config, mode: opt.value })}
              className={`p-3 rounded-lg border text-left transition-all ${
                config.mode === opt.value
                  ? opt.value === "disabled"
                    ? "border-gray-500 bg-gray-500/10"
                    : opt.value === "ids"
                    ? "border-blue-500 bg-blue-500/10"
                    : "border-red-500 bg-red-500/10"
                  : "border-[var(--border)] hover:border-[var(--text-muted)]"
              }`}
            >
              <div className="flex items-center gap-2">
                <div
                  className={`w-3 h-3 rounded-full border-2 ${
                    config.mode === opt.value
                      ? opt.value === "disabled"
                        ? "border-gray-400 bg-gray-400"
                        : opt.value === "ids"
                        ? "border-blue-400 bg-blue-400"
                        : "border-red-400 bg-red-400"
                      : "border-[var(--text-muted)]"
                  }`}
                />
                <span className="text-sm font-medium">{opt.label}</span>
              </div>
              <p className="text-xs text-[var(--text-muted)] mt-1 ml-5">{opt.desc}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Network Variables */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="text-sm font-medium mb-3">Network Variables</h3>
        <div className="space-y-4">
          {/* $HOME_NET */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1.5">
              $HOME_NET (protected networks)
            </label>
            <div className="flex flex-wrap gap-2 mb-2">
              {config.home_net.map((cidr) => (
                <span
                  key={cidr}
                  className="inline-flex items-center gap-1 text-xs font-mono bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-2 py-1"
                >
                  {cidr}
                  <button
                    onClick={() => removeCidr(cidr)}
                    className="text-[var(--text-muted)] hover:text-red-400 transition-colors ml-0.5"
                    title="Remove"
                  >
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={newCidr}
                onChange={(e) => setNewCidr(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && addCidr()}
                placeholder="e.g. 10.0.0.0/8"
                className="flex-1 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              />
              <button
                onClick={addCidr}
                disabled={!newCidr.trim()}
                className="px-3 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm rounded-md transition-colors"
              >
                Add
              </button>
            </div>
          </div>

          {/* $EXTERNAL_NET */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              $EXTERNAL_NET
            </label>
            <input
              type="text"
              value={config.external_net.join(", ")}
              onChange={(e) => setConfig({ ...config, external_net: e.target.value.split(",").map(s => s.trim()).filter(Boolean) })}
              placeholder="!$HOME_NET"
              className="w-full md:w-64 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Logging & Retention */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="text-sm font-medium mb-3">Logging & Retention</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Alert Retention */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Alert Retention (days)
            </label>
            <input
              type="number"
              value={config.alert_retention_days}
              onChange={(e) =>
                setConfig({
                  ...config,
                  alert_retention_days: parseInt(e.target.value) || 30,
                })
              }
              min={1}
              max={365}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>

          {/* Syslog Target */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Syslog Target
            </label>
            <input
              type="text"
              value={config.syslog_target}
              onChange={(e) =>
                setConfig({ ...config, syslog_target: e.target.value })
              }
              placeholder="e.g. 192.168.1.10:514"
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>

          {/* EVE Log */}
          <div className="md:col-span-2">
            <div className="flex items-center gap-3 mb-2">
              <button
                onClick={() =>
                  setConfig({ ...config, eve_log_enabled: !config.eve_log_enabled })
                }
                className="group flex items-center gap-2"
              >
                <div
                  className={`relative w-8 h-4 rounded-full transition-colors ${
                    config.eve_log_enabled ? "bg-green-600" : "bg-gray-600"
                  }`}
                >
                  <div
                    className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${
                      config.eve_log_enabled ? "left-4" : "left-0.5"
                    }`}
                  />
                </div>
                <span className="text-xs text-[var(--text-secondary)]">EVE JSON Log</span>
              </button>
            </div>
            {config.eve_log_enabled && (
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">
                  EVE Log Path
                </label>
                <input
                  type="text"
                  value={config.eve_log_path}
                  onChange={(e) =>
                    setConfig({ ...config, eve_log_path: e.target.value })
                  }
                  placeholder="/var/log/aifw/eve.json"
                  className="w-full md:w-96 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm font-mono text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
                />
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Performance Tuning */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
        <h3 className="text-sm font-medium mb-1">Performance Tuning</h3>
        <p className="text-xs text-[var(--text-muted)] mb-4">
          Optional settings. Leave empty to use engine defaults.
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Worker Count
            </label>
            <input
              type="number"
              value={config.worker_count ?? ""}
              onChange={(e) =>
                setConfig({
                  ...config,
                  worker_count: e.target.value ? parseInt(e.target.value) : null,
                })
              }
              placeholder="auto (CPU cores)"
              min={1}
              max={64}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Flow Table Size
            </label>
            <input
              type="number"
              value={config.flow_table_size ?? ""}
              onChange={(e) =>
                setConfig({
                  ...config,
                  flow_table_size: e.target.value ? parseInt(e.target.value) : null,
                })
              }
              placeholder="65536"
              min={1024}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Stream Depth (bytes)
            </label>
            <input
              type="number"
              value={config.stream_depth ?? ""}
              onChange={(e) =>
                setConfig({
                  ...config,
                  stream_depth: e.target.value ? parseInt(e.target.value) : null,
                })
              }
              placeholder="1048576"
              min={0}
              className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
          </div>
        </div>
      </div>

      {/* Bottom save button */}
      <div className="flex justify-end">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-6 py-2.5 bg-green-600 hover:bg-green-500 disabled:opacity-40 text-white text-sm font-medium rounded-md transition-colors"
        >
          {saving ? "Saving..." : "Save Configuration"}
        </button>
      </div>
    </div>
  );
}
