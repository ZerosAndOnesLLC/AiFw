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

async function authFetch(url: string, options?: RequestInit): Promise<Response> {
  return fetch(url, { ...options, headers: { ...authHeaders(), ...options?.headers } });
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

export default function SettingsPage() {
  // --- Metrics Storage ---
  const [metricsBackend, setMetricsBackend] = useState("local");
  const [postgresUrl, setPostgresUrl] = useState("");
  const [collectionInterval, setCollectionInterval] = useState("1");
  const [retentionDays, setRetentionDays] = useState("365");
  const [metricsFeedback, setMetricsFeedback] = useState<SectionFeedback | null>(null);
  const [metricsSaving, setMetricsSaving] = useState(false);

  // --- API Server ---
  const [apiPort, setApiPort] = useState("8080");
  const [corsOrigins, setCorsOrigins] = useState("*");
  const [jwtSecret, setJwtSecret] = useState("auto-generated");
  const [apiFeedback, setApiFeedback] = useState<SectionFeedback | null>(null);
  const [apiSaving, setApiSaving] = useState(false);

  // --- TLS Policy ---
  const [minTlsVersion, setMinTlsVersion] = useState("tls12");
  const [blockExpired, setBlockExpired] = useState(true);
  const [blockWeakKeys, setBlockWeakKeys] = useState(true);
  const [tlsFeedback, setTlsFeedback] = useState<SectionFeedback | null>(null);
  const [tlsSaving, setTlsSaving] = useState(false);

  // --- DNS Configuration ---
  const [dnsServers, setDnsServers] = useState<string[]>([]);
  const [newDns, setNewDns] = useState("");
  const [dnsFeedback, setDnsFeedback] = useState<SectionFeedback | null>(null);
  const [dnsSaving, setDnsSaving] = useState(false);
  const [dnsLoading, setDnsLoading] = useState(true);

  // --- Auth Settings ---
  const [sessionTimeout, setSessionTimeout] = useState(480);
  const [maxLoginAttempts, setMaxLoginAttempts] = useState(5);
  const [lockoutDuration, setLockoutDuration] = useState(300);
  const [requireMfa, setRequireMfa] = useState(false);
  const [allowRegistration, setAllowRegistration] = useState(false);
  const [passwordMinLength, setPasswordMinLength] = useState(8);
  const [authFeedback, setAuthFeedback] = useState<SectionFeedback | null>(null);
  const [authSaving, setAuthSaving] = useState(false);
  const [authLoading, setAuthLoading] = useState(true);

  // --- Valkey/Metrics Persistence ---
  const [valkeyEnabled, setValkeyEnabled] = useState(true);
  const [valkeyUrl, setValkeyUrl] = useState("redis://127.0.0.1:6379");
  const [metricsRetention, setMetricsRetention] = useState(30);
  const [valkeyFeedback, setValkeyFeedback] = useState<SectionFeedback | null>(null);
  const [valkeySaving, setValkeySaving] = useState(false);
  const [valkeyLoading, setValkeyLoading] = useState(true);
  const [valkeyStatus, setValkeyStatus] = useState<string>("unknown");

  // --- Dashboard History ---
  const [historyMode, setHistoryMode] = useState<"duration" | "ram">("duration");
  const [historyMinutes, setHistoryMinutes] = useState(30);
  const [historyRamMb, setHistoryRamMb] = useState(512);
  const [historyEntries, setHistoryEntries] = useState(0);
  const [historyEstRamMb, setHistoryEstRamMb] = useState(0);
  const [historyFeedback, setHistoryFeedback] = useState<SectionFeedback | null>(null);
  const [historySaving, setHistorySaving] = useState(false);
  const [historyLoading, setHistoryLoading] = useState(true);

  // --- IDS Alert Buffer ---
  const [idsMaxMb, setIdsMaxMb] = useState(64);
  const [idsMaxAge, setIdsMaxAge] = useState(86400);
  const [idsStats, setIdsStats] = useState<{ count: number; estimated_mb: number; max_mb: number; usage_pct: number; oldest: string | null; newest: string | null; by_classification: { classification: string; count: number }[] } | null>(null);
  const [idsFeedback, setIdsFeedback] = useState<SectionFeedback | null>(null);
  const [idsSaving, setIdsSaving] = useState(false);

  // --- AI Providers ---
  const [aiEnabled, setAiEnabled] = useState(false);
  const [aiActiveProvider, setAiActiveProvider] = useState("");
  const [aiProviders, setAiProviders] = useState<{ provider: string; enabled: boolean; api_key_set: boolean; endpoint: string; model: string }[]>([]);
  const [aiFeedback, setAiFeedback] = useState<SectionFeedback | null>(null);
  const [aiSaving, setAiSaving] = useState(false);
  const [aiLoading, setAiLoading] = useState(true);
  const [aiEditingProvider, setAiEditingProvider] = useState<string | null>(null);
  const [aiEditKey, setAiEditKey] = useState("");
  const [aiEditEndpoint, setAiEditEndpoint] = useState("");
  const [aiEditModel, setAiEditModel] = useState("");
  const [aiModels, setAiModels] = useState<string[]>([]);
  const [aiModelsLoading, setAiModelsLoading] = useState(false);
  const [aiTesting, setAiTesting] = useState(false);
  const [aiTestResult, setAiTestResult] = useState<{ success: boolean; status_code: string } | null>(null);

  // Auto-clear feedback after 4 seconds
  const setFeedbackWithTimeout = useCallback(
    (setter: (v: SectionFeedback | null) => void, fb: SectionFeedback) => {
      setter(fb);
      setTimeout(() => setter(null), 4000);
    },
    []
  );

  // --- Fetch DNS on mount ---
  useEffect(() => {
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/dns`, {
          headers: authHeaders(),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        setDnsServers(data.servers || []);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setDnsFeedback({ type: "error", message: `Failed to load DNS servers: ${msg}` });
      } finally {
        setDnsLoading(false);
      }
    })();
  }, []);

  // --- Fetch Auth settings on mount ---
  useEffect(() => {
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/auth/settings`, {
          headers: authHeaders(),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (data.access_token_expiry_mins !== undefined) setSessionTimeout(data.access_token_expiry_mins);
        if (data.require_totp !== undefined) setRequireMfa(data.require_totp);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setAuthFeedback({ type: "error", message: `Failed to load auth settings: ${msg}` });
      } finally {
        setAuthLoading(false);
      }
    })();

    // Fetch Valkey settings
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/settings/valkey`, { headers: authHeaders() });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        if (data.enabled !== undefined) setValkeyEnabled(data.enabled);
        if (data.url) setValkeyUrl(data.url);
        if (data.retention_minutes) setMetricsRetention(data.retention_minutes);
        if (data.status) setValkeyStatus(data.status);
      } catch {
        // endpoint may not exist yet
      } finally {
        setValkeyLoading(false);
      }
    })();

    // Fetch Dashboard History settings
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/settings/dashboard-history`, { headers: authHeaders() });
        if (!res.ok) return;
        const data = await res.json();
        if (data.mode === "duration" || data.mode === "ram") setHistoryMode(data.mode);
        if (data.history_seconds) setHistoryMinutes(Math.round(data.history_seconds / 60));
        if (data.current_entries !== undefined) setHistoryEntries(data.current_entries);
        if (data.estimated_ram_mb !== undefined) setHistoryEstRamMb(data.estimated_ram_mb);
        if (data.ram_limit_mb) setHistoryRamMb(data.ram_limit_mb);
      } catch {
        // endpoint may not exist yet
      } finally {
        setHistoryLoading(false);
      }
    })();

    // Fetch IDS Alert Buffer settings
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/settings/ids-alerts`, { headers: authHeaders() });
        if (!res.ok) return;
        const data = await res.json();
        if (data.max_mb) setIdsMaxMb(data.max_mb);
        if (data.max_age_secs) setIdsMaxAge(data.max_age_secs);
        if (data.stats) setIdsStats(data.stats);
      } catch { /* endpoint may not exist */ }
    })();

    // Fetch AI provider settings
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/settings/ai`, { headers: authHeaders() });
        if (!res.ok) return;
        const data = await res.json();
        if (data.enabled !== undefined) setAiEnabled(data.enabled);
        if (data.active_provider) setAiActiveProvider(data.active_provider);
        if (data.providers) setAiProviders(data.providers);
      } catch { /* endpoint may not exist yet */ }
      finally { setAiLoading(false); }
    })();

    // Fetch TLS policy settings
    (async () => {
      try {
        const res = await authFetch(`${API}/api/v1/settings/tls`, { headers: authHeaders() });
        if (!res.ok) return;
        const data = await res.json();
        if (data.min_version) setMinTlsVersion(data.min_version);
        if (data.block_expired !== undefined) setBlockExpired(data.block_expired);
        if (data.block_weak_keys !== undefined) setBlockWeakKeys(data.block_weak_keys);
      } catch {
        // endpoint may not exist yet
      }
    })();
  }, []);

  // --- Save handlers ---

  const saveMetrics = async () => {
    setMetricsSaving(true);
    setMetricsFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/settings/metrics`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          backend: metricsBackend,
          postgres_url: metricsBackend === "postgres" ? postgresUrl : undefined,
          collection_interval: Number(collectionInterval),
          retention_days: Number(retentionDays),
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout(setMetricsFeedback, { type: "success", message: "Metrics settings saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setMetricsFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setMetricsSaving(false);
    }
  };

  const saveApi = async () => {
    setApiSaving(true);
    setApiFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/settings/api`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          port: Number(apiPort),
          cors_origins: corsOrigins,
          jwt_secret: jwtSecret,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout(setApiFeedback, { type: "success", message: "API settings saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setApiFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setApiSaving(false);
    }
  };

  const saveTls = async () => {
    setTlsSaving(true);
    setTlsFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/settings/tls`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          min_version: minTlsVersion,
          block_expired: blockExpired,
          block_weak_keys: blockWeakKeys,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout(setTlsFeedback, { type: "success", message: "TLS policy saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setTlsFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setTlsSaving(false);
    }
  };

  const saveDns = async () => {
    setDnsSaving(true);
    setDnsFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/dns`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ servers: dnsServers }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout(setDnsFeedback, { type: "success", message: "DNS servers saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setDnsFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setDnsSaving(false);
    }
  };

  const saveAuth = async () => {
    setAuthSaving(true);
    setAuthFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/auth/settings`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          access_token_expiry_mins: sessionTimeout,
          require_totp: requireMfa,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout(setAuthFeedback, { type: "success", message: "Auth settings saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setAuthFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setAuthSaving(false);
    }
  };

  const saveIdsAlerts = async () => {
    setIdsSaving(true);
    setIdsFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/settings/ids-alerts`, {
        method: "PUT", headers: authHeaders(),
        body: JSON.stringify({ max_mb: idsMaxMb, max_age_secs: idsMaxAge }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.stats) setIdsStats(data.stats);
      setFeedbackWithTimeout(setIdsFeedback, { type: "success", message: "IDS alert settings saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setIdsFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally { setIdsSaving(false); }
  };

  const saveHistory = async () => {
    setHistorySaving(true);
    setHistoryFeedback(null);
    try {
      const body =
        historyMode === "ram"
          ? { mode: "ram", ram_limit_mb: historyRamMb }
          : { mode: "duration", history_seconds: Math.max(5, historyMinutes) * 60 };
      const res = await authFetch(`${API}/api/v1/settings/dashboard-history`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.estimated_ram_mb !== undefined) setHistoryEstRamMb(data.estimated_ram_mb);
      if (data.history_seconds) setHistoryMinutes(Math.round(data.history_seconds / 60));
      setFeedbackWithTimeout(setHistoryFeedback, { type: "success", message: "Dashboard history updated. Takes effect immediately." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setHistoryFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setHistorySaving(false);
    }
  };

  const saveAiProvider = async (provider: string, enabled?: boolean) => {
    setAiSaving(true);
    setAiFeedback(null);
    try {
      const body: Record<string, unknown> = { provider };
      if (enabled !== undefined) body.provider_enabled = enabled;
      if (aiEditKey) body.api_key = aiEditKey;
      if (aiEditEndpoint) body.endpoint = aiEditEndpoint;
      if (aiEditModel) body.model = aiEditModel;
      const res = await authFetch(`${API}/api/v1/settings/ai`, {
        method: "PUT", headers: authHeaders(), body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setFeedbackWithTimeout(setAiFeedback, { type: "success", message: `${provider} settings saved.` });
      setAiEditingProvider(null);
      setAiEditKey("");
      // Refresh
      const r2 = await authFetch(`${API}/api/v1/settings/ai`, { headers: authHeaders() });
      if (r2.ok) { const d = await r2.json(); setAiProviders(d.providers || []); setAiActiveProvider(d.active_provider || ""); setAiEnabled(d.enabled); }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setAiFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally { setAiSaving(false); }
  };

  const saveAiGlobal = async (enabled: boolean, active?: string) => {
    setAiSaving(true);
    try {
      const body: Record<string, unknown> = { enabled };
      if (active) body.active_provider = active;
      await authFetch(`${API}/api/v1/settings/ai`, {
        method: "PUT", headers: authHeaders(), body: JSON.stringify(body),
      });
      setAiEnabled(enabled);
      if (active) setAiActiveProvider(active);
      setFeedbackWithTimeout(setAiFeedback, { type: "success", message: enabled ? "AI analysis enabled." : "AI analysis disabled." });
    } catch { /* ignore */ }
    finally { setAiSaving(false); }
  };

  const fetchAiModels = async (provider: string) => {
    setAiModelsLoading(true);
    setAiModels([]);
    try {
      const res = await authFetch(`${API}/api/v1/settings/ai/models?provider=${provider}`, { headers: authHeaders() });
      if (res.ok) {
        const data = await res.json();
        setAiModels(data.models || []);
      }
    } catch { /* ignore */ }
    finally { setAiModelsLoading(false); }
  };

  const testAiConnection = async (provider: string) => {
    setAiTesting(true);
    setAiTestResult(null);
    try {
      const body: Record<string, string> = { provider };
      if (aiEditEndpoint) body.endpoint = aiEditEndpoint;
      if (aiEditKey) body.api_key = aiEditKey;
      const res = await authFetch(`${API}/api/v1/settings/ai/test`, {
        method: "POST", headers: authHeaders(), body: JSON.stringify(body),
      });
      if (res.ok) {
        const data = await res.json();
        setAiTestResult({ success: data.success, status_code: data.status_code });
      } else {
        setAiTestResult({ success: false, status_code: "error" });
      }
    } catch {
      setAiTestResult({ success: false, status_code: "error" });
    } finally { setAiTesting(false); }
  };

  const saveValkey = async () => {
    setValkeySaving(true);
    setValkeyFeedback(null);
    try {
      const res = await authFetch(`${API}/api/v1/settings/valkey`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          enabled: valkeyEnabled,
          url: valkeyUrl,
          retention_minutes: metricsRetention,
        }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      if (data.status) setValkeyStatus(data.status);
      setFeedbackWithTimeout(setValkeyFeedback, { type: "success", message: "Valkey settings saved." });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setFeedbackWithTimeout(setValkeyFeedback, { type: "error", message: `Save failed: ${msg}` });
    } finally {
      setValkeySaving(false);
    }
  };

  // --- DNS helpers ---

  const addDnsServer = () => {
    const trimmed = newDns.trim();
    if (!trimmed) return;
    // Basic IPv4/IPv6 validation
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^[0-9a-fA-F:]+$/;
    if (!ipv4.test(trimmed) && !ipv6.test(trimmed)) {
      setFeedbackWithTimeout(setDnsFeedback, { type: "error", message: "Invalid IP address format." });
      return;
    }
    if (dnsServers.includes(trimmed)) {
      setFeedbackWithTimeout(setDnsFeedback, { type: "error", message: "Server already in list." });
      return;
    }
    setDnsServers((prev) => [...prev, trimmed]);
    setNewDns("");
  };

  const removeDnsServer = (index: number) => {
    setDnsServers((prev) => prev.filter((_, i) => i !== index));
  };

  // Shared styles
  const inputCls =
    "w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)]";
  const labelCls = "text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1";
  const sectionCls = "bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5";
  const saveBtnCls =
    "px-5 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed";

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-[var(--text-muted)]">System configuration and preferences</p>
      </div>

      {/* DNS Configuration */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">DNS Configuration</h2>
        </div>
        <FeedbackBanner feedback={dnsFeedback} />
        <div className="space-y-4 mt-2">
          <div>
            <label className={labelCls}>Nameservers</label>
            {dnsLoading ? (
              <p className="text-sm text-[var(--text-muted)]">Loading...</p>
            ) : dnsServers.length === 0 ? (
              <p className="text-sm text-[var(--text-muted)]">No DNS servers configured.</p>
            ) : (
              <ul className="space-y-2">
                {dnsServers.map((server, idx) => (
                  <li
                    key={idx}
                    className="flex items-center justify-between bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2"
                  >
                    <span className="font-mono text-sm">{server}</span>
                    <button
                      onClick={() => removeDnsServer(idx)}
                      className="text-red-400 hover:text-red-300 transition-colors text-sm font-bold px-2"
                      title="Remove server"
                    >
                      X
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={newDns}
              onChange={(e) => setNewDns(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  addDnsServer();
                }
              }}
              placeholder="e.g. 8.8.8.8"
              className={`${inputCls} font-mono`}
            />
            <button
              onClick={addDnsServer}
              className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-bold transition-colors flex-shrink-0"
              title="Add server"
            >
              +
            </button>
          </div>

          <div className="flex justify-end">
            <button onClick={saveDns} disabled={dnsSaving} className={saveBtnCls}>
              {dnsSaving ? "Saving..." : "Save DNS"}
            </button>
          </div>
        </div>
      </section>

      {/* Metrics Backend */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">Metrics Storage</h2>
        </div>
        <FeedbackBanner feedback={metricsFeedback} />
        <div className="space-y-4 mt-2">
          <div>
            <label className={labelCls}>Backend</label>
            <select
              value={metricsBackend}
              onChange={(e) => setMetricsBackend(e.target.value)}
              className={inputCls}
            >
              <option value="local">Local (In-Memory RRD + SQLite)</option>
              <option value="postgres">PostgreSQL</option>
            </select>
            <p className="text-xs text-[var(--text-muted)] mt-1">
              Local: ring buffers with 4-tier consolidation. Postgres: full time-series with configurable retention.
            </p>
          </div>

          {metricsBackend === "postgres" && (
            <div>
              <label className={labelCls}>PostgreSQL URL</label>
              <input
                type="text"
                value={postgresUrl}
                onChange={(e) => setPostgresUrl(e.target.value)}
                placeholder="postgresql://user:pass@host:5432/aifw_metrics"
                className={`${inputCls} font-mono`}
              />
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Collection Interval (sec)</label>
              <input
                type="number"
                value={collectionInterval}
                onChange={(e) => setCollectionInterval(e.target.value)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Retention (days)</label>
              <input
                type="number"
                value={retentionDays}
                onChange={(e) => setRetentionDays(e.target.value)}
                className={inputCls}
              />
            </div>
          </div>

          <div className="flex justify-end">
            <button onClick={saveMetrics} disabled={metricsSaving} className={saveBtnCls}>
              {metricsSaving ? "Saving..." : "Save Metrics"}
            </button>
          </div>
        </div>
      </section>

      {/* Dashboard History */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">Dashboard History</h2>
          <span className="text-xs text-[var(--text-muted)] font-mono">
            {historyEntries.toLocaleString()} entries buffered
          </span>
        </div>
        <FeedbackBanner feedback={historyFeedback} />
        <div className="space-y-4 mt-2">
          {historyLoading ? (
            <p className="text-sm text-[var(--text-muted)]">Loading...</p>
          ) : (
            <>
              {/* Mode toggle */}
              <div>
                <label className={labelCls}>Limit by</label>
                <div className="flex gap-1 bg-[var(--bg-primary)] rounded-lg p-1 border border-[var(--border)] w-fit">
                  {(["duration", "ram"] as const).map((m) => (
                    <button
                      key={m}
                      onClick={() => setHistoryMode(m)}
                      className={`px-4 py-1.5 text-xs font-medium rounded-md transition-all ${
                        historyMode === m
                          ? "bg-[var(--accent)] text-white"
                          : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      {m === "duration" ? "Duration" : "RAM Budget"}
                    </button>
                  ))}
                </div>
              </div>

              {/* Duration input */}
              {historyMode === "duration" && (
                <div>
                  <label className={labelCls}>History Duration (minutes)</label>
                  <input
                    type="number"
                    value={historyMinutes}
                    onChange={(e) => setHistoryMinutes(Math.max(5, Number(e.target.value)))}
                    className={inputCls}
                    min={5}
                    max={43200}
                  />
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    How many minutes of dashboard metrics to keep. Default: 30 min. Max: 43,200 (30 days).
                  </p>
                </div>
              )}

              {/* RAM budget input */}
              {historyMode === "ram" && (
                <div>
                  <label className={labelCls}>RAM Budget (MB)</label>
                  <input
                    type="number"
                    value={historyRamMb}
                    onChange={(e) => setHistoryRamMb(Math.max(1, Number(e.target.value)))}
                    className={inputCls}
                    min={1}
                    max={8192}
                  />
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    Maximum RAM to use for dashboard history. The system calculates how much history fits.
                    Each entry is ~2 KB. Example: 1024 MB = ~6 days of history.
                  </p>
                </div>
              )}

              {/* Summary */}
              <div className="flex items-center gap-4 p-3 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md">
                <div className="flex-1 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
                  <div>
                    <span className="text-[var(--text-muted)] uppercase tracking-wider">Duration</span>
                    <p className="font-mono mt-0.5">
                      {(() => {
                        const mins = historyMode === "ram"
                          ? Math.round((historyRamMb * 1024 * 1024) / 2048 / 60)
                          : historyMinutes;
                        return mins < 60
                          ? `${mins} min`
                          : mins < 1440
                          ? `${(mins / 60).toFixed(1)} hours`
                          : `${(mins / 1440).toFixed(1)} days`;
                      })()}
                    </p>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] uppercase tracking-wider">Entries</span>
                    <p className="font-mono mt-0.5">
                      {(() => {
                        const entries = historyMode === "ram"
                          ? Math.round((historyRamMb * 1024 * 1024) / 2048)
                          : historyMinutes * 60;
                        return entries.toLocaleString();
                      })()}
                    </p>
                  </div>
                  <div>
                    <span className="text-[var(--text-muted)] uppercase tracking-wider">Est. RAM</span>
                    <p className="font-mono mt-0.5">
                      {(() => {
                        const mb = historyMode === "ram"
                          ? historyRamMb
                          : (historyMinutes * 60 * 2) / 1024;
                        return mb < 1
                          ? `${Math.round(mb * 1024)} KB`
                          : mb >= 1024
                          ? `${(mb / 1024).toFixed(2)} GB`
                          : `${mb.toFixed(1)} MB`;
                      })()}
                    </p>
                  </div>
                </div>
              </div>
            </>
          )}

          <div className="flex justify-end">
            <button onClick={saveHistory} disabled={historySaving || historyLoading} className={saveBtnCls}>
              {historySaving ? "Saving..." : "Save History"}
            </button>
          </div>
        </div>
      </section>

      {/* API Settings */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">API Server</h2>
        </div>
        <FeedbackBanner feedback={apiFeedback} />
        <div className="space-y-4 mt-2">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className={labelCls}>Listen Port</label>
              <input
                type="text"
                value={apiPort}
                onChange={(e) => setApiPort(e.target.value)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>CORS Origins</label>
              <input
                type="text"
                value={corsOrigins}
                onChange={(e) => setCorsOrigins(e.target.value)}
                className={inputCls}
              />
            </div>
          </div>
          <div>
            <label className={labelCls}>JWT Secret</label>
            <input
              type="password"
              value={jwtSecret}
              onChange={(e) => setJwtSecret(e.target.value)}
              className={inputCls}
            />
          </div>

          <div className="flex justify-end">
            <button onClick={saveApi} disabled={apiSaving} className={saveBtnCls}>
              {apiSaving ? "Saving..." : "Save API"}
            </button>
          </div>
        </div>
      </section>

      {/* TLS Policy */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">TLS Policy</h2>
        </div>
        <FeedbackBanner feedback={tlsFeedback} />
        <div className="space-y-4 mt-2">
          <div>
            <label className={labelCls}>Minimum TLS Version</label>
            <select
              value={minTlsVersion}
              onChange={(e) => setMinTlsVersion(e.target.value)}
              className={inputCls}
            >
              <option value="ssl30">SSLv3 (not recommended)</option>
              <option value="tls10">TLS 1.0 (deprecated)</option>
              <option value="tls11">TLS 1.1 (deprecated)</option>
              <option value="tls12">TLS 1.2 (recommended)</option>
              <option value="tls13">TLS 1.3 (strict)</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={blockExpired}
                onChange={(e) => setBlockExpired(e.target.checked)}
                className="rounded border-[var(--border)]"
              />
              Block expired certificates
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={blockWeakKeys}
                onChange={(e) => setBlockWeakKeys(e.target.checked)}
                className="rounded border-[var(--border)]"
              />
              Block weak keys (&lt; 2048 bits)
            </label>
          </div>

          <div className="flex justify-end">
            <button onClick={saveTls} disabled={tlsSaving} className={saveBtnCls}>
              {tlsSaving ? "Saving..." : "Save TLS"}
            </button>
          </div>
        </div>
      </section>

      {/* Auth Settings */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">Authentication</h2>
        </div>
        <FeedbackBanner feedback={authFeedback} />
        <div className="space-y-4 mt-2">
          {authLoading ? (
            <p className="text-sm text-[var(--text-muted)]">Loading auth settings...</p>
          ) : (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>Session Timeout (minutes)</label>
                  <input
                    type="number"
                    value={sessionTimeout}
                    onChange={(e) => setSessionTimeout(Number(e.target.value))}
                    className={inputCls}
                    min={5}
                  />
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    How long before you need to login again. Default: 480 (8 hours).
                  </p>
                </div>
                <div>
                  <label className={labelCls}>Password Min Length</label>
                  <input
                    type="number"
                    value={passwordMinLength}
                    onChange={(e) => setPasswordMinLength(Number(e.target.value))}
                    min={4}
                    className={inputCls}
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>Max Login Attempts</label>
                  <input
                    type="number"
                    value={maxLoginAttempts}
                    onChange={(e) => setMaxLoginAttempts(Number(e.target.value))}
                    min={1}
                    className={inputCls}
                  />
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    Failed attempts before lockout.
                  </p>
                </div>
                <div>
                  <label className={labelCls}>Lockout Duration (sec)</label>
                  <input
                    type="number"
                    value={lockoutDuration}
                    onChange={(e) => setLockoutDuration(Number(e.target.value))}
                    className={inputCls}
                  />
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    How long the account stays locked.
                  </p>
                </div>
              </div>

              <div className="space-y-2">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={requireMfa}
                    onChange={(e) => setRequireMfa(e.target.checked)}
                    className="rounded border-[var(--border)]"
                  />
                  Require multi-factor authentication (MFA)
                </label>
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={allowRegistration}
                    onChange={(e) => setAllowRegistration(e.target.checked)}
                    className="rounded border-[var(--border)]"
                  />
                  Allow self-registration
                </label>
              </div>
            </>
          )}

          <div className="flex justify-end">
            <button onClick={saveAuth} disabled={authSaving || authLoading} className={saveBtnCls}>
              {authSaving ? "Saving..." : "Save Auth"}
            </button>
          </div>
        </div>
      </section>

      {/* Valkey / Metrics Persistence */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-3">
          <h2 className="font-medium">Metrics Persistence (Valkey)</h2>
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${
            valkeyStatus === "connected" ? "bg-green-500/20 text-green-400" :
            valkeyStatus === "disabled" ? "bg-gray-500/20 text-gray-400" :
            "bg-red-500/20 text-red-400"
          }`}>
            {valkeyStatus}
          </span>
        </div>
        <FeedbackBanner feedback={valkeyFeedback} />
        <div className="space-y-4 mt-2">
          {valkeyLoading ? (
            <p className="text-sm text-[var(--text-muted)]">Loading...</p>
          ) : (
            <>
              <div className="flex items-center gap-3">
                <label className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={valkeyEnabled}
                    onChange={(e) => setValkeyEnabled(e.target.checked)}
                    className="rounded border-[var(--border)]"
                  />
                  Enable Valkey persistence
                </label>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelCls}>Valkey URL</label>
                  <input
                    type="text"
                    value={valkeyUrl}
                    onChange={(e) => setValkeyUrl(e.target.value)}
                    className={inputCls}
                    disabled={!valkeyEnabled}
                    placeholder="redis://127.0.0.1:6379"
                  />
                </div>
                <div>
                  <label className={labelCls}>Retention (minutes)</label>
                  <input
                    type="number"
                    value={metricsRetention}
                    onChange={(e) => setMetricsRetention(Number(e.target.value))}
                    className={inputCls}
                    disabled={!valkeyEnabled}
                    min={5}
                    max={1440}
                  />
                  <p className="text-xs text-[var(--text-muted)] mt-1">
                    How many minutes of metrics to keep. Default: 30. Max: 1440 (24h).
                  </p>
                </div>
              </div>

              <p className="text-xs text-[var(--text-muted)]">
                When enabled, metrics are persisted to Valkey so dashboard graphs survive API restarts.
                Without Valkey, graphs reset when the API restarts but still work via in-memory buffer.
              </p>
            </>
          )}

          <div className="flex justify-end">
            <button onClick={saveValkey} disabled={valkeySaving || valkeyLoading} className={saveBtnCls}>
              {valkeySaving ? "Saving..." : "Save Valkey"}
            </button>
          </div>
        </div>
      </section>

      {/* IDS Alert Buffer */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-medium">IDS Alert Storage</h2>
            <p className="text-xs text-[var(--text-muted)]">In-memory alert buffer — no disk I/O</p>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className={labelCls}>Max Memory (MB)</label>
            <input type="number" value={idsMaxMb}
              onChange={e => setIdsMaxMb(Math.max(8, Math.min(512, parseInt(e.target.value) || 64)))}
              className={inputCls} min={8} max={512} />
            <p className="text-[10px] text-[var(--text-muted)] mt-1">8–512 MB. Each alert ≈ 512 bytes.</p>
          </div>
          <div>
            <label className={labelCls}>Max Age (hours)</label>
            <input type="number" value={Math.round(idsMaxAge / 3600)}
              onChange={e => setIdsMaxAge(Math.max(1, Math.min(168, parseInt(e.target.value) || 24)) * 3600)}
              className={inputCls} min={1} max={168} />
            <p className="text-[10px] text-[var(--text-muted)] mt-1">1–168 hours (7 days). Older alerts auto-evicted.</p>
          </div>
        </div>
        {idsStats && (
          <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
            <div className="bg-[var(--bg-primary)] rounded-lg p-3">
              <div className="text-[10px] text-[var(--text-muted)] uppercase">Alerts</div>
              <div className="text-lg font-bold text-cyan-400">{idsStats.count.toLocaleString()}</div>
            </div>
            <div className="bg-[var(--bg-primary)] rounded-lg p-3">
              <div className="text-[10px] text-[var(--text-muted)] uppercase">Memory</div>
              <div className="text-lg font-bold text-blue-400">{idsStats.estimated_mb.toFixed(1)} MB</div>
            </div>
            <div className="bg-[var(--bg-primary)] rounded-lg p-3">
              <div className="text-[10px] text-[var(--text-muted)] uppercase">Usage</div>
              <div className="text-lg font-bold" style={{ color: idsStats.usage_pct > 80 ? "#ef4444" : "#22c55e" }}>
                {idsStats.usage_pct.toFixed(0)}%
              </div>
              <div className="w-full h-1 bg-gray-700 rounded-full mt-1">
                <div className="h-full rounded-full transition-all" style={{ width: `${idsStats.usage_pct}%`, backgroundColor: idsStats.usage_pct > 80 ? "#ef4444" : "#22c55e" }} />
              </div>
            </div>
            <div className="bg-[var(--bg-primary)] rounded-lg p-3">
              <div className="text-[10px] text-[var(--text-muted)] uppercase">Classifications</div>
              <div className="flex flex-wrap gap-1 mt-1 justify-center">
                {(idsStats.by_classification || []).map((c: { classification: string; count: number }) => (
                  <span key={c.classification} className={`text-[9px] px-1.5 py-0.5 rounded ${
                    c.classification === "confirmed" ? "bg-red-500/15 text-red-400" :
                    c.classification === "false_positive" ? "bg-green-500/15 text-green-400" :
                    c.classification === "investigating" ? "bg-yellow-500/15 text-yellow-400" :
                    "bg-gray-700 text-gray-400"
                  }`}>{c.classification}: {c.count}</span>
                ))}
              </div>
            </div>
          </div>
        )}
        <div className="flex items-center gap-3 mt-4">
          <button onClick={saveIdsAlerts} disabled={idsSaving} className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 transition-colors">
            {idsSaving ? "Saving..." : "Save"}
          </button>
          {idsFeedback && (
            <span className={idsFeedback.type === "success" ? "text-green-400 text-xs" : "text-red-400 text-xs"}>
              {idsFeedback.message}
            </span>
          )}
        </div>
      </section>

      {/* AI Providers */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="font-medium">AI / LLM Providers</h2>
            <p className="text-xs text-[var(--text-muted)] mt-0.5">
              Configure AI backends for threat analysis and assisted investigation
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className={`text-xs font-medium ${aiEnabled ? "text-green-400" : "text-[var(--text-muted)]"}`}>
              {aiEnabled ? "Enabled" : "Disabled"}
            </span>
            <button
              onClick={() => saveAiGlobal(!aiEnabled)}
              disabled={aiSaving}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${aiEnabled ? "bg-green-600" : "bg-gray-600"}`}
            >
              <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${aiEnabled ? "translate-x-4" : "translate-x-0.5"}`} />
            </button>
          </div>
        </div>
        <FeedbackBanner feedback={aiFeedback} />
        <div className="space-y-3 mt-3">
          {aiLoading ? (
            <p className="text-sm text-[var(--text-muted)]">Loading...</p>
          ) : (
            <>
              {/* WIP notice */}
              <div className="bg-yellow-500/5 border border-yellow-500/30 rounded-md px-3 py-2">
                <p className="text-xs text-[var(--text-muted)]">
                  <span className="text-yellow-400 font-medium">Preview.</span> AI-assisted threat analysis is in development.
                  Configure your providers now — they&apos;ll be used for automated alert triage, threat classification,
                  and investigation assistance in upcoming releases.
                </p>
              </div>

              {/* Provider cards */}
              {[
                { key: "openai", name: "OpenAI", desc: "GPT-4o, GPT-4 Turbo, GPT-3.5", icon: "O", color: "bg-green-600", defaultEndpoint: "https://api.openai.com/v1", defaultModel: "gpt-4o", needsKey: true },
                { key: "claude", name: "Anthropic Claude", desc: "Claude Sonnet 4, Opus 4, Haiku", icon: "C", color: "bg-orange-600", defaultEndpoint: "https://api.anthropic.com", defaultModel: "claude-sonnet-4-20250514", needsKey: true },
                { key: "lm_studio", name: "LM Studio", desc: "Local models via OpenAI-compatible API", icon: "L", color: "bg-purple-600", defaultEndpoint: "http://localhost:1234/v1", defaultModel: "", needsKey: false },
                { key: "ollama", name: "Ollama", desc: "Local models — llama3, mistral, codellama", icon: "O", color: "bg-blue-600", defaultEndpoint: "http://localhost:11434", defaultModel: "llama3", needsKey: false },
              ].map(prov => {
                const cfg = aiProviders.find(p => p.provider === prov.key);
                const isEditing = aiEditingProvider === prov.key;
                const isActive = aiActiveProvider === prov.key;

                return (
                  <div key={prov.key} className={`bg-[var(--bg-primary)] border rounded-lg overflow-hidden ${
                    isActive && cfg?.enabled ? "border-green-500/30" : "border-[var(--border)]"
                  }`}>
                    <div className="px-4 py-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`w-8 h-8 rounded-lg ${prov.color} flex items-center justify-center text-white text-xs font-bold`}>
                          {prov.icon}
                        </div>
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-medium">{prov.name}</span>
                            {isActive && cfg?.enabled && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30">active</span>
                            )}
                            {cfg?.enabled && !isActive && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">configured</span>
                            )}
                          </div>
                          <p className="text-[11px] text-[var(--text-muted)]">{prov.desc}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {cfg?.enabled && (
                          <button
                            onClick={() => { saveAiGlobal(true, prov.key); }}
                            disabled={aiSaving || isActive}
                            className={`text-[11px] px-2 py-1 rounded border transition-colors ${
                              isActive
                                ? "border-green-500/30 text-green-400 bg-green-500/10 cursor-default"
                                : "border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--accent)]"
                            }`}
                          >
                            {isActive ? "Active" : "Set Active"}
                          </button>
                        )}
                        <button
                          onClick={() => {
                            if (isEditing) { setAiEditingProvider(null); }
                            else {
                              setAiEditingProvider(prov.key);
                              setAiEditKey("");
                              setAiEditEndpoint(cfg?.endpoint || prov.defaultEndpoint);
                              setAiEditModel(cfg?.model || prov.defaultModel);
                              setAiModels([]);
                              setAiTestResult(null);
                            }
                          }}
                          className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                        >
                          {isEditing ? "Cancel" : "Configure"}
                        </button>
                        <button
                          onClick={() => saveAiProvider(prov.key, !cfg?.enabled)}
                          disabled={aiSaving}
                          className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors ${cfg?.enabled ? "bg-green-600" : "bg-gray-600"}`}
                        >
                          <span className={`inline-block h-2.5 w-2.5 transform rounded-full bg-white transition-transform ${cfg?.enabled ? "translate-x-3.5" : "translate-x-0.5"}`} />
                        </button>
                      </div>
                    </div>

                    {/* Edit form */}
                    {isEditing && (
                      <div className="border-t border-[var(--border)] px-4 py-3 space-y-3">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {prov.needsKey && (
                            <div>
                              <label className={labelCls}>API Key {cfg?.api_key_set && !aiEditKey && <span className="text-green-400 normal-case">(set)</span>}</label>
                              <input
                                type="password"
                                value={aiEditKey}
                                onChange={e => setAiEditKey(e.target.value)}
                                placeholder={cfg?.api_key_set ? "(unchanged)" : `Enter ${prov.name} API key`}
                                className={inputCls}
                              />
                            </div>
                          )}
                          <div>
                            <label className={labelCls}>Endpoint URL</label>
                            <input
                              type="text"
                              value={aiEditEndpoint}
                              onChange={e => setAiEditEndpoint(e.target.value)}
                              placeholder={prov.defaultEndpoint}
                              className={inputCls}
                            />
                          </div>
                          <div>
                            <div className="flex items-center justify-between mb-1">
                              <label className={labelCls}>Model</label>
                              <button
                                onClick={() => fetchAiModels(prov.key)}
                                disabled={aiModelsLoading}
                                className="text-[10px] text-[var(--accent)] hover:underline disabled:opacity-50"
                              >
                                {aiModelsLoading ? "Loading..." : "Fetch Models"}
                              </button>
                            </div>
                            {aiModels.length > 0 ? (
                              <select
                                value={aiEditModel}
                                onChange={e => setAiEditModel(e.target.value)}
                                className={inputCls}
                              >
                                <option value="">Select a model...</option>
                                {aiModels.map(m => <option key={m} value={m}>{m}</option>)}
                              </select>
                            ) : (
                              <input
                                type="text"
                                value={aiEditModel}
                                onChange={e => setAiEditModel(e.target.value)}
                                placeholder={prov.defaultModel || "model name"}
                                className={inputCls}
                              />
                            )}
                          </div>
                        </div>
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => testAiConnection(prov.key)}
                              disabled={aiTesting}
                              className="px-3 py-2 text-xs font-medium rounded-md border border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50"
                            >
                              {aiTesting ? "Testing..." : "Test Connection"}
                            </button>
                            {aiTestResult && (
                              <span className={`text-xs font-medium ${aiTestResult.success ? "text-green-400" : "text-red-400"}`}>
                                {aiTestResult.success ? "Connected" : `Failed (${aiTestResult.status_code})`}
                              </span>
                            )}
                          </div>
                          <button
                            onClick={() => saveAiProvider(prov.key)}
                            disabled={aiSaving}
                            className={saveBtnCls}
                          >
                            {aiSaving ? "Saving..." : "Save"}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </>
          )}
        </div>
      </section>

      {/* ================================================================ */}
      {/* System Actions                                                    */}
      {/* ================================================================ */}
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold">System Actions</h2>
        </div>
        <SystemActions />
      </section>
    </div>
  );
}

function SystemActions() {
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [feedback, setFeedback] = useState<SectionFeedback | null>(null);

  const handleReboot = async () => {
    setRebooting(true);
    setFeedback(null);
    try {
      const res = await authFetch("/api/v1/updates/reboot", { method: "POST" });
      const data = await res.json();
      setFeedback({ type: "success", message: data.message || "System rebooting..." });
      setConfirmReboot(false);
    } catch {
      setFeedback({ type: "error", message: "Failed to initiate reboot" });
    } finally {
      setRebooting(false);
    }
  };

  return (
    <div className="p-6 space-y-4">
      <FeedbackBanner feedback={feedback} />
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-[var(--text-primary)] font-medium">Reboot System</p>
          <p className="text-xs text-[var(--text-muted)]">
            Restart the firewall appliance. All active connections will be dropped.
          </p>
        </div>
        {!confirmReboot ? (
          <button
            onClick={() => setConfirmReboot(true)}
            className="px-4 py-2 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors"
          >
            Reboot
          </button>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-xs text-red-400">Are you sure?</span>
            <button
              onClick={handleReboot}
              disabled={rebooting}
              className="px-4 py-2 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors disabled:opacity-50"
            >
              {rebooting ? "Rebooting..." : "Confirm Reboot"}
            </button>
            <button
              onClick={() => setConfirmReboot(false)}
              className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            >
              Cancel
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
