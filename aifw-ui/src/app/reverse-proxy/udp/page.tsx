"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface UdpRouter {
  id: string;
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: number;
  enabled: boolean;
  created_at: string;
}

interface UdpService {
  id: string;
  name: string;
  service_type: string;
  config_json: string;
  enabled: boolean;
  created_at: string;
}

interface EntryPoint {
  id: string;
  name: string;
  address: string;
  enabled: boolean;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
}

/* -- Router form ---------------------------------------------------- */

interface RouterForm {
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: string;
  enabled: boolean;
}

const defaultRouterForm: RouterForm = {
  name: "",
  rule: "",
  service: "",
  entry_points: "",
  priority: "0",
  enabled: true,
};

/* -- Service form --------------------------------------------------- */

interface ServerEntry {
  address: string;
  weight: string;
}

interface ServiceForm {
  name: string;
  service_type: string;
  enabled: boolean;
  // loadBalancer fields
  servers: ServerEntry[];
  healthCheckInterval: string;
  healthCheckTimeout: string;
  healthCheckPayload: string;
  healthCheckExpectedResponse: string;
  // weighted fields
  weightedRefs: { name: string; weight: string }[];
}

const defaultServiceForm: ServiceForm = {
  name: "",
  service_type: "loadBalancer",
  enabled: true,
  servers: [{ address: "", weight: "1" }],
  healthCheckInterval: "",
  healthCheckTimeout: "",
  healthCheckPayload: "",
  healthCheckExpectedResponse: "",
  weightedRefs: [{ name: "", weight: "1" }],
};

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function buildServiceConfigJson(form: ServiceForm): string {
  if (form.service_type === "weighted") {
    return JSON.stringify({
      weighted: {
        services: form.weightedRefs
          .filter((r) => r.name.trim())
          .map((r) => ({ name: r.name.trim(), weight: parseInt(r.weight, 10) || 1 })),
      },
    });
  }
  const cfg: Record<string, unknown> = {};
  const servers = form.servers
    .filter((s) => s.address.trim())
    .map((s) => {
      const entry: Record<string, unknown> = { address: s.address.trim() };
      const w = parseInt(s.weight, 10);
      if (w && w !== 1) entry.weight = w;
      return entry;
    });
  if (servers.length > 0) cfg.servers = servers;
  if (
    form.healthCheckInterval.trim() ||
    form.healthCheckTimeout.trim() ||
    form.healthCheckPayload.trim() ||
    form.healthCheckExpectedResponse.trim()
  ) {
    const hc: Record<string, string> = {};
    if (form.healthCheckInterval.trim()) hc.interval = form.healthCheckInterval.trim();
    if (form.healthCheckTimeout.trim()) hc.timeout = form.healthCheckTimeout.trim();
    if (form.healthCheckPayload.trim()) hc.payload = form.healthCheckPayload.trim();
    if (form.healthCheckExpectedResponse.trim()) hc.expectedResponse = form.healthCheckExpectedResponse.trim();
    cfg.healthCheck = hc;
  }
  return JSON.stringify(cfg);
}

function parseServiceConfigJson(raw: string, serviceType: string): Partial<ServiceForm> {
  try {
    const obj = JSON.parse(raw || "{}");
    if (serviceType === "weighted" && obj.weighted?.services) {
      return {
        weightedRefs: obj.weighted.services.map((s: { name: string; weight: number }) => ({
          name: s.name,
          weight: String(s.weight),
        })),
      };
    }
    const partial: Partial<ServiceForm> = {};
    if (Array.isArray(obj.servers)) {
      partial.servers = obj.servers.map((s: { address: string; weight?: number }) => ({
        address: s.address || "",
        weight: String(s.weight || 1),
      }));
    }
    if (obj.healthCheck) {
      if (obj.healthCheck.interval) partial.healthCheckInterval = obj.healthCheck.interval;
      if (obj.healthCheck.timeout) partial.healthCheckTimeout = obj.healthCheck.timeout;
      if (obj.healthCheck.payload) partial.healthCheckPayload = obj.healthCheck.payload;
      if (obj.healthCheck.expectedResponse) partial.healthCheckExpectedResponse = obj.healthCheck.expectedResponse;
    }
    return partial;
  } catch {
    return {};
  }
}

/* -- Shared styles --------------------------------------------------- */

const inputCls =
  "w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500";
const selectCls =
  "w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500";
const labelCls = "block text-xs text-[var(--text-muted)] mb-1";

/* -- Page ------------------------------------------------------------ */

export default function UdpPage() {
  /* -- Router state ------------------------------------------------- */
  const [routers, setRouters] = useState<UdpRouter[]>([]);
  const [routerModalOpen, setRouterModalOpen] = useState(false);
  const [editingRouterId, setEditingRouterId] = useState<string | null>(null);
  const [routerForm, setRouterForm] = useState<RouterForm>(defaultRouterForm);
  const [routerSubmitting, setRouterSubmitting] = useState(false);
  const [deleteRouterId, setDeleteRouterId] = useState<string | null>(null);

  /* -- Service state ------------------------------------------------ */
  const [services, setServices] = useState<UdpService[]>([]);
  const [serviceModalOpen, setServiceModalOpen] = useState(false);
  const [editingServiceId, setEditingServiceId] = useState<string | null>(null);
  const [serviceForm, setServiceForm] = useState<ServiceForm>(defaultServiceForm);
  const [serviceSubmitting, setServiceSubmitting] = useState(false);
  const [deleteServiceId, setDeleteServiceId] = useState<string | null>(null);

  /* -- Shared state ------------------------------------------------- */
  const [entrypoints, setEntrypoints] = useState<EntryPoint[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchRouters = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/udp/routers", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setRouters(Array.isArray(body) ? body : body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load UDP routers");
    }
  }, []);

  const fetchServices = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/udp/services", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setServices(Array.isArray(body) ? body : body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load UDP services");
    }
  }, []);

  const fetchEntrypoints = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/entrypoints", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setEntrypoints(Array.isArray(body) ? body : body.data || []);
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchRouters(), fetchServices(), fetchEntrypoints()]);
      setLoading(false);
    })();
  }, [fetchRouters, fetchServices, fetchEntrypoints]);

  /* -- Router CRUD -------------------------------------------------- */

  const openCreateRouter = () => {
    setEditingRouterId(null);
    setRouterForm(defaultRouterForm);
    setRouterModalOpen(true);
  };

  const openEditRouter = (r: UdpRouter) => {
    setEditingRouterId(r.id);
    setRouterForm({
      name: r.name,
      rule: r.rule,
      service: r.service,
      entry_points: r.entry_points,
      priority: String(r.priority),
      enabled: r.enabled,
    });
    setRouterModalOpen(true);
  };

  const closeRouterModal = () => {
    setRouterModalOpen(false);
    setEditingRouterId(null);
    setRouterForm(defaultRouterForm);
  };

  const handleRouterSubmit = async () => {
    if (!routerForm.name.trim()) {
      showFeedback("error", "Name is required");
      return;
    }
    setRouterSubmitting(true);
    try {
      const payload = {
        name: routerForm.name.trim(),
        rule: routerForm.rule.trim(),
        service: routerForm.service.trim(),
        entry_points: routerForm.entry_points.trim(),
        priority: parseInt(routerForm.priority, 10) || 0,
        enabled: routerForm.enabled,
      };
      const url = editingRouterId
        ? `/api/v1/reverse-proxy/udp/routers/${editingRouterId}`
        : "/api/v1/reverse-proxy/udp/routers";
      const method = editingRouterId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(payload) });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }
      showFeedback("success", editingRouterId ? "UDP router updated" : "UDP router created");
      closeRouterModal();
      await fetchRouters();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save UDP router");
    } finally {
      setRouterSubmitting(false);
    }
  };

  const handleDeleteRouter = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/reverse-proxy/udp/routers/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "UDP router deleted");
      setDeleteRouterId(null);
      await fetchRouters();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete UDP router");
    }
  };

  /* -- Service CRUD ------------------------------------------------- */

  const openCreateService = () => {
    setEditingServiceId(null);
    setServiceForm({ ...defaultServiceForm, servers: [{ address: "", weight: "1" }], weightedRefs: [{ name: "", weight: "1" }] });
    setServiceModalOpen(true);
  };

  const openEditService = (s: UdpService) => {
    const parsed = parseServiceConfigJson(s.config_json, s.service_type);
    setEditingServiceId(s.id);
    setServiceForm({
      ...defaultServiceForm,
      name: s.name,
      service_type: s.service_type,
      enabled: s.enabled,
      servers: parsed.servers || [{ address: "", weight: "1" }],
      healthCheckInterval: parsed.healthCheckInterval || "",
      healthCheckTimeout: parsed.healthCheckTimeout || "",
      healthCheckPayload: parsed.healthCheckPayload || "",
      healthCheckExpectedResponse: parsed.healthCheckExpectedResponse || "",
      weightedRefs: parsed.weightedRefs || [{ name: "", weight: "1" }],
    });
    setServiceModalOpen(true);
  };

  const closeServiceModal = () => {
    setServiceModalOpen(false);
    setEditingServiceId(null);
    setServiceForm(defaultServiceForm);
  };

  const handleServiceSubmit = async () => {
    if (!serviceForm.name.trim()) {
      showFeedback("error", "Service name is required");
      return;
    }
    setServiceSubmitting(true);
    try {
      const payload = {
        name: serviceForm.name.trim(),
        service_type: serviceForm.service_type,
        config_json: buildServiceConfigJson(serviceForm),
        enabled: serviceForm.enabled,
      };
      const url = editingServiceId
        ? `/api/v1/reverse-proxy/udp/services/${editingServiceId}`
        : "/api/v1/reverse-proxy/udp/services";
      const method = editingServiceId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(payload) });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || body.message || `HTTP ${res.status}`);
      }
      showFeedback("success", editingServiceId ? "UDP service updated" : "UDP service created");
      closeServiceModal();
      await fetchServices();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save UDP service");
    } finally {
      setServiceSubmitting(false);
    }
  };

  const handleDeleteService = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/reverse-proxy/udp/services/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "UDP service deleted");
      setDeleteServiceId(null);
      await fetchServices();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete UDP service");
    }
  };

  /* -- Server list helpers ------------------------------------------ */

  const addServer = () => {
    setServiceForm((f) => ({ ...f, servers: [...f.servers, { address: "", weight: "1" }] }));
  };

  const removeServer = (idx: number) => {
    setServiceForm((f) => ({ ...f, servers: f.servers.filter((_, i) => i !== idx) }));
  };

  const updateServer = (idx: number, field: keyof ServerEntry, value: string) => {
    setServiceForm((f) => ({
      ...f,
      servers: f.servers.map((s, i) => (i === idx ? { ...s, [field]: value } : s)),
    }));
  };

  /* -- Weighted refs helpers ---------------------------------------- */

  const addWeightedRef = () => {
    setServiceForm((f) => ({ ...f, weightedRefs: [...f.weightedRefs, { name: "", weight: "1" }] }));
  };

  const removeWeightedRef = (idx: number) => {
    setServiceForm((f) => ({ ...f, weightedRefs: f.weightedRefs.filter((_, i) => i !== idx) }));
  };

  const updateWeightedRef = (idx: number, field: "name" | "weight", value: string) => {
    setServiceForm((f) => ({
      ...f,
      weightedRefs: f.weightedRefs.map((r, i) => (i === idx ? { ...r, [field]: value } : r)),
    }));
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading UDP routers &amp; services...
      </div>
    );
  }

  return (
    <div className="space-y-8 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">UDP Routing</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage UDP routers and services for the reverse proxy
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

      {/* ============================================================= */}
      {/* UDP ROUTERS SECTION                                            */}
      {/* ============================================================= */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold">UDP Routers</h2>
            <p className="text-xs text-[var(--text-muted)]">{routers.length} router{routers.length !== 1 ? "s" : ""}</p>
          </div>
          <button
            onClick={openCreateRouter}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Router
          </button>
        </div>

        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          {routers.length === 0 ? (
            <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
              No UDP routers configured
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                    <th className="px-6 py-3">Name</th>
                    <th className="px-6 py-3">Rule</th>
                    <th className="px-6 py-3">Service</th>
                    <th className="px-6 py-3">Entry Points</th>
                    <th className="px-6 py-3">Priority</th>
                    <th className="px-6 py-3">Enabled</th>
                    <th className="px-6 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {routers.map((r) => (
                    <tr key={r.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => openEditRouter(r)}>
                      <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{r.name}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs max-w-[200px] truncate">
                        {r.rule || "-"}
                      </td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{r.service || "-"}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{r.entry_points || "-"}</td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{r.priority}</td>
                      <td className="px-6 py-3">
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full border ${
                            r.enabled
                              ? "bg-green-500/20 text-green-400 border-green-500/30"
                              : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                          }`}
                        >
                          {r.enabled ? "Active" : "Disabled"}
                        </span>
                      </td>
                      <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => setDeleteRouterId(r.id)}
                            title="Delete"
                            className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* ============================================================= */}
      {/* UDP SERVICES SECTION                                           */}
      {/* ============================================================= */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold">UDP Services</h2>
            <p className="text-xs text-[var(--text-muted)]">{services.length} service{services.length !== 1 ? "s" : ""}</p>
          </div>
          <button
            onClick={openCreateService}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2 transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Service
          </button>
        </div>

        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          {services.length === 0 ? (
            <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
              No UDP services configured
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                    <th className="px-6 py-3">Name</th>
                    <th className="px-6 py-3">Type</th>
                    <th className="px-6 py-3">Servers / Refs</th>
                    <th className="px-6 py-3">Enabled</th>
                    <th className="px-6 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {services.map((s) => {
                    let detail = "-";
                    try {
                      const cfg = JSON.parse(s.config_json || "{}");
                      if (s.service_type === "weighted" && cfg.weighted?.services) {
                        detail = cfg.weighted.services.map((r: { name: string }) => r.name).join(", ");
                      } else if (cfg.servers) {
                        detail = cfg.servers.map((sv: { address: string }) => sv.address).join(", ");
                      }
                    } catch {
                      /* ignore */
                    }
                    return (
                      <tr key={s.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => openEditService(s)}>
                        <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{s.name}</td>
                        <td className="px-6 py-3">
                          <span className="text-xs px-2 py-0.5 rounded-full border bg-purple-500/20 text-purple-400 border-purple-500/30">
                            {s.service_type}
                          </span>
                        </td>
                        <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs max-w-[300px] truncate">
                          {detail}
                        </td>
                        <td className="px-6 py-3">
                          <span
                            className={`text-xs px-2 py-0.5 rounded-full border ${
                              s.enabled
                                ? "bg-green-500/20 text-green-400 border-green-500/30"
                                : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                            }`}
                          >
                            {s.enabled ? "Active" : "Disabled"}
                          </span>
                        </td>
                        <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-1">
                            <button
                              onClick={() => setDeleteServiceId(s.id)}
                              title="Delete"
                              className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                              </svg>
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {/* ============================================================= */}
      {/* ROUTER MODAL                                                   */}
      {/* ============================================================= */}
      {routerModalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              {editingRouterId ? "Edit UDP Router" : "Add UDP Router"}
            </h3>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <label className={labelCls}>Name</label>
                <input
                  type="text"
                  value={routerForm.name}
                  onChange={(e) => setRouterForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. dns-router"
                  className={inputCls}
                />
              </div>

              {/* Rule */}
              <div>
                <label className={labelCls}>Rule</label>
                <input
                  type="text"
                  value={routerForm.rule}
                  onChange={(e) => setRouterForm((p) => ({ ...p, rule: e.target.value }))}
                  placeholder="UDP routing rule"
                  className={inputCls}
                />
              </div>

              {/* Service */}
              <div>
                <label className={labelCls}>Service</label>
                <select
                  value={routerForm.service}
                  onChange={(e) => setRouterForm((p) => ({ ...p, service: e.target.value }))}
                  className={selectCls}
                >
                  <option value="">Select a service...</option>
                  {services.map((s) => (
                    <option key={s.id} value={s.name}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Entry Points */}
              <div>
                <label className={labelCls}>Entry Points</label>
                <select
                  value={routerForm.entry_points}
                  onChange={(e) => setRouterForm((p) => ({ ...p, entry_points: e.target.value }))}
                  className={selectCls}
                >
                  <option value="">Select entrypoint...</option>
                  {entrypoints.filter((ep) => ep.enabled).map((ep) => (
                    <option key={ep.id} value={ep.name}>
                      {ep.name} ({ep.address})
                    </option>
                  ))}
                </select>
                <p className="text-[10px] text-[var(--text-muted)] mt-1">
                  For multiple entrypoints, separate with commas after selection.
                </p>
              </div>

              {/* Priority */}
              <div>
                <label className={labelCls}>Priority</label>
                <input
                  type="number"
                  value={routerForm.priority}
                  onChange={(e) => setRouterForm((p) => ({ ...p, priority: e.target.value }))}
                  placeholder="0"
                  className={inputCls}
                />
              </div>

              {/* Enabled */}
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Enabled</label>
                <button
                  type="button"
                  onClick={() => setRouterForm((p) => ({ ...p, enabled: !p.enabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    routerForm.enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      routerForm.enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeRouterModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={handleRouterSubmit}
                disabled={routerSubmitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
              >
                {routerSubmitting ? "Saving..." : editingRouterId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* SERVICE MODAL                                                  */}
      {/* ============================================================= */}
      {serviceModalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-2xl w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">
              {editingServiceId ? "Edit UDP Service" : "Add UDP Service"}
            </h3>

            <div className="space-y-4">
              {/* Name */}
              <div>
                <label className={labelCls}>Name</label>
                <input
                  type="text"
                  value={serviceForm.name}
                  onChange={(e) => setServiceForm((p) => ({ ...p, name: e.target.value }))}
                  placeholder="e.g. dns-backend"
                  className={inputCls}
                />
              </div>

              {/* Service Type */}
              <div>
                <label className={labelCls}>Service Type</label>
                <select
                  value={serviceForm.service_type}
                  onChange={(e) => setServiceForm((p) => ({ ...p, service_type: e.target.value }))}
                  className={selectCls}
                >
                  <option value="loadBalancer">loadBalancer</option>
                  <option value="weighted">weighted</option>
                </select>
              </div>

              {/* loadBalancer fields */}
              {serviceForm.service_type === "loadBalancer" && (
                <>
                  {/* Servers */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <label className="text-xs text-[var(--text-muted)]">Servers</label>
                      <button
                        type="button"
                        onClick={addServer}
                        className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        + Add Server
                      </button>
                    </div>
                    <div className="space-y-2">
                      {serviceForm.servers.map((srv, idx) => (
                        <div key={idx} className="flex items-center gap-2">
                          <input
                            type="text"
                            value={srv.address}
                            onChange={(e) => updateServer(idx, "address", e.target.value)}
                            placeholder="host:port"
                            className={`flex-1 ${inputCls}`}
                          />
                          <input
                            type="number"
                            value={srv.weight}
                            onChange={(e) => updateServer(idx, "weight", e.target.value)}
                            placeholder="1"
                            className={`w-20 ${inputCls}`}
                            title="Weight"
                          />
                          {serviceForm.servers.length > 1 && (
                            <button
                              type="button"
                              onClick={() => removeServer(idx)}
                              className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                            >
                              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Health Check */}
                  <div className="border border-[var(--border)] rounded-md">
                    <div className="px-4 py-2.5 text-sm font-medium text-[var(--text-secondary)]">
                      Health Check
                    </div>
                    <div className="px-4 pb-4 space-y-3">
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <label className={labelCls}>Interval</label>
                          <input
                            type="text"
                            value={serviceForm.healthCheckInterval}
                            onChange={(e) => setServiceForm((p) => ({ ...p, healthCheckInterval: e.target.value }))}
                            placeholder="e.g. 10s"
                            className={inputCls}
                          />
                        </div>
                        <div>
                          <label className={labelCls}>Timeout</label>
                          <input
                            type="text"
                            value={serviceForm.healthCheckTimeout}
                            onChange={(e) => setServiceForm((p) => ({ ...p, healthCheckTimeout: e.target.value }))}
                            placeholder="e.g. 5s"
                            className={inputCls}
                          />
                        </div>
                      </div>
                      <div>
                        <label className={labelCls}>Payload</label>
                        <input
                          type="text"
                          value={serviceForm.healthCheckPayload}
                          onChange={(e) => setServiceForm((p) => ({ ...p, healthCheckPayload: e.target.value }))}
                          placeholder="Health check payload to send"
                          className={inputCls}
                        />
                      </div>
                      <div>
                        <label className={labelCls}>Expected Response</label>
                        <input
                          type="text"
                          value={serviceForm.healthCheckExpectedResponse}
                          onChange={(e) => setServiceForm((p) => ({ ...p, healthCheckExpectedResponse: e.target.value }))}
                          placeholder="Expected response string"
                          className={inputCls}
                        />
                      </div>
                    </div>
                  </div>
                </>
              )}

              {/* weighted fields */}
              {serviceForm.service_type === "weighted" && (
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <label className="text-xs text-[var(--text-muted)]">Service References</label>
                    <button
                      type="button"
                      onClick={addWeightedRef}
                      className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      + Add Reference
                    </button>
                  </div>
                  <div className="space-y-2">
                    {serviceForm.weightedRefs.map((ref, idx) => (
                      <div key={idx} className="flex items-center gap-2">
                        <input
                          type="text"
                          value={ref.name}
                          onChange={(e) => updateWeightedRef(idx, "name", e.target.value)}
                          placeholder="Service name"
                          className={`flex-1 ${inputCls}`}
                        />
                        <input
                          type="number"
                          value={ref.weight}
                          onChange={(e) => updateWeightedRef(idx, "weight", e.target.value)}
                          placeholder="1"
                          className={`w-20 ${inputCls}`}
                          title="Weight"
                        />
                        {serviceForm.weightedRefs.length > 1 && (
                          <button
                            type="button"
                            onClick={() => removeWeightedRef(idx)}
                            className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Enabled */}
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Enabled</label>
                <button
                  type="button"
                  onClick={() => setServiceForm((p) => ({ ...p, enabled: !p.enabled }))}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    serviceForm.enabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      serviceForm.enabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeServiceModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={handleServiceSubmit}
                disabled={serviceSubmitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
              >
                {serviceSubmitting ? "Saving..." : editingServiceId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* DELETE ROUTER CONFIRM MODAL                                    */}
      {/* ============================================================= */}
      {deleteRouterId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">Delete UDP Router</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this UDP router? This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteRouterId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteRouter(deleteRouterId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ============================================================= */}
      {/* DELETE SERVICE CONFIRM MODAL                                   */}
      {/* ============================================================= */}
      {deleteServiceId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-[var(--text-primary)]">Delete UDP Service</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this UDP service? Any routers referencing it will stop working.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteServiceId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteService(deleteServiceId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
