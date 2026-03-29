"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface ReverseProxyStatus {
  running: boolean;
  entrypoints: number;
  http_routers: number;
  http_services: number;
  http_middlewares: number;
  tcp_routers: number;
  udp_routers: number;
}

interface GlobalConfig {
  enabled: boolean;
  log_level: string;
  access_log_enabled: boolean;
  access_log_path: string;
  access_log_format: string;
  metrics_enabled: boolean;
  metrics_address: string;
  api_dashboard: boolean;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
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

const defaultConfig: GlobalConfig = {
  enabled: false,
  log_level: "info",
  access_log_enabled: true,
  access_log_path: "/var/log/trafficcop/access.log",
  access_log_format: "json",
  metrics_enabled: false,
  metrics_address: ":9090",
  api_dashboard: true,
};

/* -- Page ------------------------------------------------------------ */

export default function ReverseProxyPage() {
  const [status, setStatus] = useState<ReverseProxyStatus | null>(null);
  const [config, setConfig] = useState<GlobalConfig>(defaultConfig);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [applying, setApplying] = useState(false);
  const [validating, setValidating] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/status", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStatus(await res.json());
    } catch {
      /* silent */
    }
  }, []);

  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/config", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: GlobalConfig = await res.json();
      setConfig(data);
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchStatus(), fetchConfig()]);
      setLoading(false);
    })();
  }, [fetchStatus, fetchConfig]);

  /* -- Actions ------------------------------------------------------ */

  const serviceAction = async (action: "start" | "stop" | "restart") => {
    setActionLoading(action);
    try {
      const res = await fetch(`/api/v1/reverse-proxy/${action}`, {
        method: "POST",
        headers: authHeaders(),
      });
      const data = await res.json().catch(() => ({ message: "" }));
      const msg = data.message || `Reverse proxy ${action} completed`;
      if (msg.toLowerCase().includes("fail") || msg.toLowerCase().includes("error")) {
        showFeedback("error", msg);
      } else {
        showFeedback("success", msg);
      }
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : `Failed to ${action} reverse proxy`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await fetch("/api/v1/reverse-proxy/config", {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(config),
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

  const handleApply = async () => {
    setApplying(true);
    try {
      const res = await fetch("/api/v1/reverse-proxy/apply", {
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

  const handleValidate = async () => {
    setValidating(true);
    try {
      const res = await fetch("/api/v1/reverse-proxy/validate", {
        method: "POST",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      showFeedback("success", data.message || "Configuration is valid");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Configuration validation failed");
    } finally {
      setValidating(false);
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading reverse proxy status...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">Reverse Proxy</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage the TrafficCop reverse proxy and load balancer
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
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-4">
          <div className="space-y-4">
            <div className="flex items-center gap-3">
              <span className="text-xs text-[var(--text-muted)] uppercase tracking-wider">Service Status</span>
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

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-sm">
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Entrypoints</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {status?.entrypoints ?? 0}
                </span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">HTTP Routers</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {status?.http_routers ?? 0}
                </span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">HTTP Services</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {status?.http_services ?? 0}
                </span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">Middlewares</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {status?.http_middlewares ?? 0}
                </span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">TCP Routers</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {status?.tcp_routers ?? 0}
                </span>
              </div>
              <div>
                <span className="block text-xs text-[var(--text-muted)] mb-0.5">UDP Routers</span>
                <span className="text-[var(--text-primary)] font-semibold">
                  {status?.udp_routers ?? 0}
                </span>
              </div>
            </div>
          </div>

          <div className="flex flex-wrap gap-2 sm:flex-col sm:items-end">
            <button
              onClick={() => serviceAction("start")}
              disabled={!!actionLoading}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
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
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
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
              className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {actionLoading === "restart" ? "Restarting..." : "Restart"}
            </button>
          </div>
        </div>
      </div>

      {/* -- Global Settings ----------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <h2 className="text-lg font-semibold mb-4">Global Settings</h2>

        <div className="space-y-5">
          {/* Enable toggle */}
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">Enable reverse proxy</label>
            <button
              type="button"
              onClick={() => setConfig((p) => ({ ...p, enabled: !p.enabled }))}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                config.enabled ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  config.enabled ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          {/* Log Level */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Log Level</label>
            <select
              value={config.log_level}
              onChange={(e) => setConfig((p) => ({ ...p, log_level: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="debug">debug</option>
              <option value="info">info</option>
              <option value="warn">warn</option>
              <option value="error">error</option>
            </select>
          </div>

          {/* Access Log Section */}
          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-3">Access Log</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Enable access log</label>
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, access_log_enabled: !p.access_log_enabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    config.access_log_enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      config.access_log_enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {config.access_log_enabled && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-xs text-[var(--text-muted)] mb-1">Log Path</label>
                    <input
                      type="text"
                      value={config.access_log_path}
                      onChange={(e) => setConfig((p) => ({ ...p, access_log_path: e.target.value }))}
                      placeholder="/var/log/trafficcop/access.log"
                      className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-[var(--text-muted)] mb-1">Log Format</label>
                    <select
                      value={config.access_log_format}
                      onChange={(e) => setConfig((p) => ({ ...p, access_log_format: e.target.value }))}
                      className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
                    >
                      <option value="json">json</option>
                      <option value="clf">clf</option>
                      <option value="combined">combined</option>
                    </select>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Metrics Section */}
          <div>
            <h3 className="text-sm font-medium text-[var(--text-secondary)] mb-3">Metrics</h3>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Enable metrics</label>
                <button
                  type="button"
                  onClick={() => setConfig((p) => ({ ...p, metrics_enabled: !p.metrics_enabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    config.metrics_enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      config.metrics_enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>

              {config.metrics_enabled && (
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">Listen Address</label>
                  <input
                    type="text"
                    value={config.metrics_address}
                    onChange={(e) => setConfig((p) => ({ ...p, metrics_address: e.target.value }))}
                    placeholder=":9090"
                    className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                  <p className="text-[10px] text-[var(--text-muted)] mt-1">Prometheus metrics endpoint (e.g. :9090)</p>
                </div>
              )}
            </div>
          </div>

          {/* API Dashboard toggle */}
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">API dashboard</label>
            <button
              type="button"
              onClick={() => setConfig((p) => ({ ...p, api_dashboard: !p.api_dashboard }))}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                config.api_dashboard ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  config.api_dashboard ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          {/* Save + Apply + Validate */}
          <div className="flex gap-3 pt-2">
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
              </svg>
              {saving ? "Saving..." : "Save Settings"}
            </button>
            <button
              onClick={handleApply}
              disabled={applying}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {applying ? "Applying..." : "Apply & Restart"}
            </button>
            <button
              onClick={handleValidate}
              disabled={validating}
              className="px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2 transition-colors"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              {validating ? "Validating..." : "Validate Config"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
