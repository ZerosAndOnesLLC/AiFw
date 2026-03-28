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
        const res = await fetch(`${API}/api/v1/dns`, {
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
        const res = await fetch(`${API}/api/v1/auth/settings`, {
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
        const res = await fetch(`${API}/api/v1/settings/valkey`, { headers: authHeaders() });
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
  }, []);

  // --- Save handlers ---

  const saveMetrics = async () => {
    setMetricsSaving(true);
    setMetricsFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/settings/metrics`, {
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
      const res = await fetch(`${API}/api/v1/settings/api`, {
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
      const res = await fetch(`${API}/api/v1/settings/tls`, {
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
      const res = await fetch(`${API}/api/v1/dns`, {
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
      const res = await fetch(`${API}/api/v1/auth/settings`, {
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

  const saveValkey = async () => {
    setValkeySaving(true);
    setValkeyFeedback(null);
    try {
      const res = await fetch(`${API}/api/v1/settings/valkey`, {
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

          <div className="grid grid-cols-2 gap-4">
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

      {/* API Settings */}
      <section className={sectionCls}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-medium">API Server</h2>
        </div>
        <FeedbackBanner feedback={apiFeedback} />
        <div className="space-y-4 mt-2">
          <div className="grid grid-cols-2 gap-4">
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
              <div className="grid grid-cols-2 gap-4">
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

              <div className="grid grid-cols-2 gap-4">
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

              <div className="grid grid-cols-2 gap-4">
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
    </div>
  );
}
