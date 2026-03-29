"use client";

import { useState, useEffect, useCallback } from "react";

/* ────────────────────────── Types ────────────────────────── */

interface HttpService {
  id: string;
  name: string;
  service_type: string;
  config_json: string;
  enabled: boolean;
  created_at: string;
}

interface LbServer {
  url: string;
  weight: number;
}

interface LbConfig {
  servers: LbServer[];
  passHostHeader: boolean;
  sticky: {
    cookie: {
      name: string;
      secure: boolean;
      httpOnly: boolean;
      sameSite: string;
    };
  };
  healthCheck: {
    path: string;
    interval: string;
    timeout: string;
    scheme: string;
    followRedirects: boolean;
  };
  serversTransport: string;
}

interface WeightedEntry {
  name: string;
  weight: number;
}

interface WeightedConfig {
  services: WeightedEntry[];
}

interface MirrorEntry {
  name: string;
  percent: number;
}

interface MirroringConfig {
  service: string;
  mirrors: MirrorEntry[];
  mirrorBody: boolean;
}

interface FailoverConfig {
  service: string;
  fallback: string;
  healthCheck: {
    path: string;
    interval: string;
    timeout: string;
  };
}

/* ────────────────────────── Helpers ────────────────────────── */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

const defaultLbConfig: LbConfig = {
  servers: [{ url: "http://10.0.0.1:8080", weight: 1 }],
  passHostHeader: true,
  sticky: { cookie: { name: "srv", secure: true, httpOnly: true, sameSite: "none" } },
  healthCheck: { path: "/health", interval: "30s", timeout: "5s", scheme: "http", followRedirects: false },
  serversTransport: "",
};

const defaultWeightedConfig: WeightedConfig = {
  services: [{ name: "", weight: 1 }],
};

const defaultMirroringConfig: MirroringConfig = {
  service: "",
  mirrors: [{ name: "", percent: 10 }],
  mirrorBody: true,
};

const defaultFailoverConfig: FailoverConfig = {
  service: "",
  fallback: "",
  healthCheck: { path: "/health", interval: "10s", timeout: "3s" },
};

function getDefaultConfig(type: string) {
  switch (type) {
    case "loadBalancer":
      return JSON.parse(JSON.stringify(defaultLbConfig));
    case "weighted":
      return JSON.parse(JSON.stringify(defaultWeightedConfig));
    case "mirroring":
      return JSON.parse(JSON.stringify(defaultMirroringConfig));
    case "failover":
      return JSON.parse(JSON.stringify(defaultFailoverConfig));
    default:
      return JSON.parse(JSON.stringify(defaultLbConfig));
  }
}

function typeBadge(serviceType: string) {
  const styles: Record<string, string> = {
    loadBalancer: "bg-blue-500/20 text-blue-400 border-blue-500/30",
    weighted: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    mirroring: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
    failover: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  };
  const labels: Record<string, string> = {
    loadBalancer: "Load Balancer",
    weighted: "Weighted",
    mirroring: "Mirroring",
    failover: "Failover",
  };
  const cls = styles[serviceType] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`inline-flex items-center rounded border text-[10px] px-1.5 py-0.5 font-medium uppercase tracking-wider ${cls}`}>
      {labels[serviceType] || serviceType}
    </span>
  );
}

function describeService(svc: HttpService): string {
  try {
    const cfg = JSON.parse(svc.config_json);
    switch (svc.service_type) {
      case "loadBalancer": {
        const servers = cfg.servers || [];
        return `${servers.length} server${servers.length !== 1 ? "s" : ""}`;
      }
      case "weighted": {
        const entries = cfg.services || [];
        return entries.map((s: WeightedEntry) => `${s.name}(w${s.weight})`).join(", ") || "--";
      }
      case "mirroring":
        return `primary: ${cfg.service || "--"}, ${(cfg.mirrors || []).length} mirror(s)`;
      case "failover":
        return `primary: ${cfg.service || "--"}, fallback: ${cfg.fallback || "--"}`;
      default:
        return "--";
    }
  } catch {
    return "--";
  }
}

function describeHealthCheck(svc: HttpService): string {
  try {
    const cfg = JSON.parse(svc.config_json);
    const hc = cfg.healthCheck;
    if (!hc || !hc.path) return "--";
    return `${hc.path} (${hc.interval || "?"})`;
  } catch {
    return "--";
  }
}

/* ────────────────────────── Shared styles ────────────────────────── */

const inputCls =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 transition-colors";
const selectCls =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 transition-colors";
const labelCls = "block text-xs text-gray-400 mb-1";

/* ────────────────────────── Collapsible Section ────────────────────────── */

function CollapsibleSection({ title, children }: { title: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-gray-700 rounded-md">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-sm text-gray-300 hover:text-white transition-colors"
      >
        <span className="font-medium">{title}</span>
        <svg
          className={`w-4 h-4 transition-transform ${open ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {open && <div className="px-3 pb-3 space-y-3">{children}</div>}
    </div>
  );
}

/* ────────────────────────── Toggle ────────────────────────── */

function Toggle({ value, onChange, label }: { value: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-sm text-gray-300">{label}</span>
      <button
        type="button"
        onClick={() => onChange(!value)}
        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
          value ? "bg-blue-600" : "bg-gray-600"
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
            value ? "translate-x-6" : "translate-x-1"
          }`}
        />
      </button>
    </div>
  );
}

/* ────────────────────────── Sub-forms ────────────────────────── */

function LoadBalancerForm({ config, setConfig }: { config: LbConfig; setConfig: (c: LbConfig) => void }) {
  const addServer = () => setConfig({ ...config, servers: [...config.servers, { url: "", weight: 1 }] });
  const removeServer = (i: number) => setConfig({ ...config, servers: config.servers.filter((_, idx) => idx !== i) });
  const updateServer = (i: number, field: keyof LbServer, val: string | number) => {
    const servers = [...config.servers];
    servers[i] = { ...servers[i], [field]: val };
    setConfig({ ...config, servers });
  };

  return (
    <div className="space-y-4">
      {/* Servers */}
      <div>
        <label className={labelCls}>Backend Servers</label>
        <div className="space-y-2">
          {config.servers.map((srv, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                type="text"
                value={srv.url}
                onChange={(e) => updateServer(i, "url", e.target.value)}
                placeholder="http://10.0.0.1:8080"
                className={`${inputCls} flex-1`}
              />
              <input
                type="number"
                value={srv.weight}
                onChange={(e) => updateServer(i, "weight", parseInt(e.target.value, 10) || 1)}
                min={1}
                className={`${inputCls} w-20`}
                title="Weight"
              />
              <button
                type="button"
                onClick={() => removeServer(i)}
                className="text-red-400 hover:text-red-300 p-1 transition-colors"
                title="Remove server"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addServer}
          className="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          + Add Server
        </button>
      </div>

      {/* Pass Host Header */}
      <Toggle
        value={config.passHostHeader}
        onChange={(v) => setConfig({ ...config, passHostHeader: v })}
        label="Pass Host Header"
      />

      {/* Servers Transport */}
      <div>
        <label className={labelCls}>Servers Transport</label>
        <input
          type="text"
          value={config.serversTransport}
          onChange={(e) => setConfig({ ...config, serversTransport: e.target.value })}
          placeholder="Optional transport name"
          className={inputCls}
        />
      </div>

      {/* Sticky Sessions */}
      <CollapsibleSection title="Sticky Sessions">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Cookie Name</label>
            <input
              type="text"
              value={config.sticky.cookie.name}
              onChange={(e) =>
                setConfig({
                  ...config,
                  sticky: { cookie: { ...config.sticky.cookie, name: e.target.value } },
                })
              }
              placeholder="srv"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>SameSite</label>
            <select
              value={config.sticky.cookie.sameSite || "none"}
              onChange={(e) =>
                setConfig({
                  ...config,
                  sticky: { cookie: { ...config.sticky.cookie, sameSite: e.target.value } },
                })
              }
              className={selectCls}
            >
              <option value="none">none</option>
              <option value="lax">lax</option>
              <option value="strict">strict</option>
            </select>
          </div>
        </div>
        <Toggle
          value={config.sticky.cookie.secure}
          onChange={(v) =>
            setConfig({
              ...config,
              sticky: { cookie: { ...config.sticky.cookie, secure: v } },
            })
          }
          label="Secure"
        />
        <Toggle
          value={config.sticky.cookie.httpOnly}
          onChange={(v) =>
            setConfig({
              ...config,
              sticky: { cookie: { ...config.sticky.cookie, httpOnly: v } },
            })
          }
          label="HttpOnly"
        />
      </CollapsibleSection>

      {/* Health Check */}
      <CollapsibleSection title="Health Check">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Path</label>
            <input
              type="text"
              value={config.healthCheck.path}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, path: e.target.value } })
              }
              placeholder="/health"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Interval</label>
            <input
              type="text"
              value={config.healthCheck.interval}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, interval: e.target.value } })
              }
              placeholder="30s"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Timeout</label>
            <input
              type="text"
              value={config.healthCheck.timeout}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, timeout: e.target.value } })
              }
              placeholder="5s"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Scheme</label>
            <select
              value={config.healthCheck.scheme || "http"}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, scheme: e.target.value } })
              }
              className={selectCls}
            >
              <option value="http">http</option>
              <option value="https">https</option>
            </select>
          </div>
        </div>
        <Toggle
          value={config.healthCheck.followRedirects || false}
          onChange={(v) =>
            setConfig({ ...config, healthCheck: { ...config.healthCheck, followRedirects: v } })
          }
          label="Follow Redirects"
        />
      </CollapsibleSection>
    </div>
  );
}

function WeightedForm({ config, setConfig }: { config: WeightedConfig; setConfig: (c: WeightedConfig) => void }) {
  const addEntry = () => setConfig({ ...config, services: [...config.services, { name: "", weight: 1 }] });
  const removeEntry = (i: number) => setConfig({ ...config, services: config.services.filter((_, idx) => idx !== i) });
  const updateEntry = (i: number, field: keyof WeightedEntry, val: string | number) => {
    const services = [...config.services];
    services[i] = { ...services[i], [field]: val };
    setConfig({ ...config, services });
  };

  return (
    <div className="space-y-4">
      <div>
        <label className={labelCls}>Weighted Services</label>
        <div className="space-y-2">
          {config.services.map((entry, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                type="text"
                value={entry.name}
                onChange={(e) => updateEntry(i, "name", e.target.value)}
                placeholder="Service name"
                className={`${inputCls} flex-1`}
              />
              <input
                type="number"
                value={entry.weight}
                onChange={(e) => updateEntry(i, "weight", parseInt(e.target.value, 10) || 1)}
                min={0}
                className={`${inputCls} w-20`}
                title="Weight"
              />
              <button
                type="button"
                onClick={() => removeEntry(i)}
                className="text-red-400 hover:text-red-300 p-1 transition-colors"
                title="Remove"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addEntry}
          className="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          + Add Service
        </button>
      </div>
    </div>
  );
}

function MirroringForm({ config, setConfig }: { config: MirroringConfig; setConfig: (c: MirroringConfig) => void }) {
  const addMirror = () => setConfig({ ...config, mirrors: [...config.mirrors, { name: "", percent: 10 }] });
  const removeMirror = (i: number) => setConfig({ ...config, mirrors: config.mirrors.filter((_, idx) => idx !== i) });
  const updateMirror = (i: number, field: keyof MirrorEntry, val: string | number) => {
    const mirrors = [...config.mirrors];
    mirrors[i] = { ...mirrors[i], [field]: val };
    setConfig({ ...config, mirrors });
  };

  return (
    <div className="space-y-4">
      <div>
        <label className={labelCls}>Primary Service</label>
        <input
          type="text"
          value={config.service}
          onChange={(e) => setConfig({ ...config, service: e.target.value })}
          placeholder="primary-svc"
          className={inputCls}
        />
      </div>

      <Toggle
        value={config.mirrorBody}
        onChange={(v) => setConfig({ ...config, mirrorBody: v })}
        label="Mirror Body"
      />

      <div>
        <label className={labelCls}>Mirrors</label>
        <div className="space-y-2">
          {config.mirrors.map((mirror, i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                type="text"
                value={mirror.name}
                onChange={(e) => updateMirror(i, "name", e.target.value)}
                placeholder="Service name"
                className={`${inputCls} flex-1`}
              />
              <input
                type="number"
                value={mirror.percent}
                onChange={(e) => updateMirror(i, "percent", Math.min(100, Math.max(0, parseInt(e.target.value, 10) || 0)))}
                min={0}
                max={100}
                className={`${inputCls} w-24`}
                title="Percent"
              />
              <span className="text-xs text-gray-500">%</span>
              <button
                type="button"
                onClick={() => removeMirror(i)}
                className="text-red-400 hover:text-red-300 p-1 transition-colors"
                title="Remove"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}
        </div>
        <button
          type="button"
          onClick={addMirror}
          className="mt-2 text-xs text-blue-400 hover:text-blue-300 transition-colors"
        >
          + Add Mirror
        </button>
      </div>
    </div>
  );
}

function FailoverForm({ config, setConfig }: { config: FailoverConfig; setConfig: (c: FailoverConfig) => void }) {
  return (
    <div className="space-y-4">
      <div>
        <label className={labelCls}>Primary Service</label>
        <input
          type="text"
          value={config.service}
          onChange={(e) => setConfig({ ...config, service: e.target.value })}
          placeholder="primary-svc"
          className={inputCls}
        />
      </div>

      <div>
        <label className={labelCls}>Fallback Service</label>
        <input
          type="text"
          value={config.fallback}
          onChange={(e) => setConfig({ ...config, fallback: e.target.value })}
          placeholder="backup-svc"
          className={inputCls}
        />
      </div>

      <div>
        <label className={`${labelCls} mt-2`}>Health Check</label>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <label className={labelCls}>Path</label>
            <input
              type="text"
              value={config.healthCheck.path}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, path: e.target.value } })
              }
              placeholder="/health"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Interval</label>
            <input
              type="text"
              value={config.healthCheck.interval}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, interval: e.target.value } })
              }
              placeholder="10s"
              className={inputCls}
            />
          </div>
          <div>
            <label className={labelCls}>Timeout</label>
            <input
              type="text"
              value={config.healthCheck.timeout}
              onChange={(e) =>
                setConfig({ ...config, healthCheck: { ...config.healthCheck, timeout: e.target.value } })
              }
              placeholder="3s"
              className={inputCls}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

/* ────────────────────────── Page ────────────────────────── */

export default function HttpServicesPage() {
  const [services, setServices] = useState<HttpService[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  /* Form state */
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState("loadBalancer");
  const [formEnabled, setFormEnabled] = useState(true);
  const [formConfig, setFormConfig] = useState<LbConfig | WeightedConfig | MirroringConfig | FailoverConfig>(
    getDefaultConfig("loadBalancer")
  );

  /* ── Fetch ─────────────────────────── */

  const fetchServices = useCallback(async () => {
    try {
      setError(null);
      const res = await fetch("/api/v1/reverse-proxy/http/services", { headers: authHeaders() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setServices(Array.isArray(json) ? json : json.data || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load services");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchServices();
  }, [fetchServices]);

  /* ── Modal helpers ─────────────────── */

  function openAdd() {
    setEditingId(null);
    setFormName("");
    setFormType("loadBalancer");
    setFormEnabled(true);
    setFormConfig(getDefaultConfig("loadBalancer"));
    setModalOpen(true);
  }

  function openEdit(svc: HttpService) {
    setEditingId(svc.id);
    setFormName(svc.name);
    setFormType(svc.service_type);
    setFormEnabled(svc.enabled);
    try {
      setFormConfig(JSON.parse(svc.config_json));
    } catch {
      setFormConfig(getDefaultConfig(svc.service_type));
    }
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditingId(null);
  }

  function handleTypeChange(newType: string) {
    setFormType(newType);
    setFormConfig(getDefaultConfig(newType));
  }

  /* ── CRUD ──────────────────────────── */

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (!formName.trim()) return;
    setSaving(true);
    setError(null);

    const body = {
      name: formName.trim(),
      service_type: formType,
      config_json: JSON.stringify(formConfig),
      enabled: formEnabled,
    };

    try {
      const url = editingId
        ? `/api/v1/reverse-proxy/http/services/${editingId}`
        : "/api/v1/reverse-proxy/http/services";
      const method = editingId ? "PUT" : "POST";
      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => null);
        throw new Error(errBody?.message || errBody?.error || `Failed to ${editingId ? "update" : "create"} service`);
      }
      closeModal();
      await fetchServices();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete(id: string) {
    if (!confirm("Delete this service? This action cannot be undone.")) return;
    setError(null);
    try {
      const res = await fetch(`/api/v1/reverse-proxy/http/services/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error("Failed to delete service");
      await fetchServices();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
    }
  }

  async function handleToggleEnabled(svc: HttpService) {
    setError(null);
    try {
      const res = await fetch(`/api/v1/reverse-proxy/http/services/${svc.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({
          name: svc.name,
          service_type: svc.service_type,
          config_json: svc.config_json,
          enabled: !svc.enabled,
        }),
      });
      if (!res.ok) throw new Error("Failed to toggle service");
      setServices((prev) => prev.map((s) => (s.id === svc.id ? { ...s, enabled: !s.enabled } : s)));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Toggle failed");
    }
  }

  /* ── Render ────────────────────────── */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">HTTP Services</h1>
          <p className="text-sm text-gray-400">
            {services.length} service{services.length !== 1 ? "s" : ""} configured
          </p>
        </div>
        <button
          onClick={openAdd}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Service
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase tracking-wider">Type</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase tracking-wider">Health Check</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">Enabled</th>
                <th className="w-24" />
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {services.length === 0 ? (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-gray-500">
                    No HTTP services configured
                  </td>
                </tr>
              ) : (
                services.map((svc) => (
                  <tr key={svc.id} className="hover:bg-gray-700/30 transition-colors">
                    <td className="py-2.5 px-4">
                      <span className="text-white font-medium">{svc.name}</span>
                    </td>
                    <td className="py-2.5 px-4">{typeBadge(svc.service_type)}</td>
                    <td className="py-2.5 px-4">
                      <span className="text-xs text-gray-400 font-mono">{describeService(svc)}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="text-xs text-gray-400 font-mono">{describeHealthCheck(svc)}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      <button
                        onClick={() => handleToggleEnabled(svc)}
                        className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none"
                        style={{ backgroundColor: svc.enabled ? "#22c55e" : "#4b5563" }}
                        title={svc.enabled ? "Disable" : "Enable"}
                      >
                        <span
                          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                            svc.enabled ? "translate-x-[18px]" : "translate-x-[3px]"
                          }`}
                        />
                      </button>
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => openEdit(svc)}
                          className="text-gray-500 hover:text-blue-400 transition-colors p-1"
                          title="Edit"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleDelete(svc.id)}
                          className="text-gray-500 hover:text-red-400 transition-colors p-1"
                          title="Delete"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add/Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-2xl mx-4 shadow-2xl max-h-[90vh] flex flex-col">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between shrink-0">
              <h2 className="text-lg font-semibold text-white">
                {editingId ? "Edit Service" : "Add Service"}
              </h2>
              <button
                onClick={closeModal}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Body (scrollable) */}
            <form onSubmit={handleSave} className="p-6 space-y-5 overflow-y-auto">
              {/* Name */}
              <div>
                <label className={labelCls}>Name *</label>
                <input
                  type="text"
                  required
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="my-service"
                  className={inputCls}
                />
              </div>

              {/* Service Type */}
              <div>
                <label className={labelCls}>Service Type</label>
                <select
                  value={formType}
                  onChange={(e) => handleTypeChange(e.target.value)}
                  className={selectCls}
                >
                  <option value="loadBalancer">Load Balancer</option>
                  <option value="weighted">Weighted</option>
                  <option value="mirroring">Mirroring</option>
                  <option value="failover">Failover</option>
                </select>
              </div>

              {/* Dynamic sub-form */}
              <div className="border-t border-gray-700 pt-4">
                {formType === "loadBalancer" && (
                  <LoadBalancerForm
                    config={formConfig as LbConfig}
                    setConfig={(c) => setFormConfig(c)}
                  />
                )}
                {formType === "weighted" && (
                  <WeightedForm
                    config={formConfig as WeightedConfig}
                    setConfig={(c) => setFormConfig(c)}
                  />
                )}
                {formType === "mirroring" && (
                  <MirroringForm
                    config={formConfig as MirroringConfig}
                    setConfig={(c) => setFormConfig(c)}
                  />
                )}
                {formType === "failover" && (
                  <FailoverForm
                    config={formConfig as FailoverConfig}
                    setConfig={(c) => setFormConfig(c)}
                  />
                )}
              </div>

              {/* Enabled toggle */}
              <div className="border-t border-gray-700 pt-4">
                <Toggle
                  value={formEnabled}
                  onChange={setFormEnabled}
                  label="Enabled"
                />
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-2">
                <button
                  type="submit"
                  disabled={saving || !formName.trim()}
                  className="flex-1 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium px-4 py-2 rounded-md transition-colors"
                >
                  {saving ? "Saving..." : editingId ? "Update Service" : "Create Service"}
                </button>
                <button
                  type="button"
                  onClick={closeModal}
                  className="bg-gray-600 hover:bg-gray-500 text-white text-sm px-4 py-2 rounded-md transition-colors"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
