"use client";

import { useState } from "react";

export default function SettingsPage() {
  const [metricsBackend, setMetricsBackend] = useState("local");
  const [postgresUrl, setPostgresUrl] = useState("");
  const [jwtSecret, setJwtSecret] = useState("auto-generated");
  const [corsOrigins, setCorsOrigins] = useState("*");
  const [apiPort, setApiPort] = useState("8080");
  const [collectionInterval, setCollectionInterval] = useState("1");
  const [retentionDays, setRetentionDays] = useState("365");
  const [minTlsVersion, setMinTlsVersion] = useState("tls12");
  const [blockExpired, setBlockExpired] = useState(true);
  const [blockWeakKeys, setBlockWeakKeys] = useState(true);

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Settings</h1>
        <p className="text-sm text-[var(--text-muted)]">System configuration and preferences</p>
      </div>

      {/* Metrics Backend */}
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5">
        <h2 className="font-medium mb-4">Metrics Storage</h2>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Backend</label>
            <select
              value={metricsBackend}
              onChange={(e) => setMetricsBackend(e.target.value)}
              className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
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
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">PostgreSQL URL</label>
              <input
                type="text"
                value={postgresUrl}
                onChange={(e) => setPostgresUrl(e.target.value)}
                placeholder="postgresql://user:pass@host:5432/aifw_metrics"
                className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] font-mono"
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Collection Interval (sec)</label>
              <input type="number" value={collectionInterval} onChange={(e) => setCollectionInterval(e.target.value)} className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Retention (days)</label>
              <input type="number" value={retentionDays} onChange={(e) => setRetentionDays(e.target.value)} className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]" />
            </div>
          </div>
        </div>
      </section>

      {/* API Settings */}
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5">
        <h2 className="font-medium mb-4">API Server</h2>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Listen Port</label>
              <input type="text" value={apiPort} onChange={(e) => setApiPort(e.target.value)} className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]" />
            </div>
            <div>
              <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">CORS Origins</label>
              <input type="text" value={corsOrigins} onChange={(e) => setCorsOrigins(e.target.value)} className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]" />
            </div>
          </div>
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">JWT Secret</label>
            <input type="password" value={jwtSecret} onChange={(e) => setJwtSecret(e.target.value)} className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]" />
          </div>
        </div>
      </section>

      {/* TLS Policy */}
      <section className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-5">
        <h2 className="font-medium mb-4">TLS Policy</h2>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block mb-1">Minimum TLS Version</label>
            <select value={minTlsVersion} onChange={(e) => setMinTlsVersion(e.target.value)} className="w-full px-3 py-2 text-sm bg-[var(--bg-primary)] border border-[var(--border)] rounded-md text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]">
              <option value="ssl30">SSLv3 (not recommended)</option>
              <option value="tls10">TLS 1.0 (deprecated)</option>
              <option value="tls11">TLS 1.1 (deprecated)</option>
              <option value="tls12">TLS 1.2 (recommended)</option>
              <option value="tls13">TLS 1.3 (strict)</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={blockExpired} onChange={(e) => setBlockExpired(e.target.checked)} className="rounded border-[var(--border)]" />
              Block expired certificates
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={blockWeakKeys} onChange={(e) => setBlockWeakKeys(e.target.checked)} className="rounded border-[var(--border)]" />
              Block weak keys (&lt; 2048 bits)
            </label>
          </div>
        </div>
      </section>

      {/* Save */}
      <div className="flex justify-end">
        <button className="px-6 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-sm font-medium transition-colors">
          Save Settings
        </button>
      </div>
    </div>
  );
}
