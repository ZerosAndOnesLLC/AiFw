"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import {
  api,
  Gateway,
  GatewayGroup,
  PolicyRule,
  RoutingInstance,
  validateCidr,
  validateInterface,
  validateName,
  validatePortSpec,
} from "../lib";

/* ────────────────────────── Types ────────────────────────── */

interface BlastRadius {
  would_strand_mgmt: boolean;
  new_rules: string[];
  removed_rules: string[];
  affected_flows: Array<{
    src: string;
    dst: string;
    protocol: string;
    current_iface: string | null;
    bytes: number;
  }>;
  validation: { severity: string; message: string }[];
}

interface FormState {
  priority: number;
  name: string;
  status: string;
  ip_version: string;
  iface_in: string;
  src_addr: string;
  dst_addr: string;
  src_port: string;
  dst_port: string;
  protocol: string;
  action_kind: string;
  target_id: string;
  description: string;
}

const defaultForm: FormState = {
  priority: 100,
  name: "",
  status: "active",
  ip_version: "both",
  iface_in: "",
  src_addr: "any",
  dst_addr: "any",
  src_port: "",
  dst_port: "",
  protocol: "any",
  action_kind: "set_gateway",
  target_id: "",
  description: "",
};

/* ────────────────────────── Presets ────────────────────────── */

interface Preset {
  name: string;
  icon: string;
  description: string;
  apply: (form: FormState) => FormState;
}

const PRESETS: Preset[] = [
  {
    name: "Streaming via WAN2",
    icon: "🎬",
    description: "Route Netflix/YouTube/Twitch (TCP 443) via a specific gateway",
    apply: (f) => ({
      ...f,
      name: "streaming-wan2",
      protocol: "tcp",
      dst_port: "443",
      action_kind: "set_gateway",
      description: "Offload streaming to secondary WAN",
    }),
  },
  {
    name: "VoIP on primary",
    icon: "📞",
    description: "Pin SIP/RTP to best-quality gateway group",
    apply: (f) => ({
      ...f,
      name: "voip-primary",
      protocol: "udp",
      dst_port: "5060,10000:20000",
      action_kind: "set_group",
      description: "VoIP routed through lowest-jitter WAN",
    }),
  },
  {
    name: "Work LAN → VPN",
    icon: "🔐",
    description: "Route 10.10.0.0/24 through a secondary routing instance",
    apply: (f) => ({
      ...f,
      name: "work-lan-vpn",
      src_addr: "10.10.0.0/24",
      action_kind: "set_instance",
      description: "Isolate work VLAN on dedicated FIB",
    }),
  },
  {
    name: "DNS → primary",
    icon: "🌐",
    description: "Force DNS (UDP/53) out the primary WAN only",
    apply: (f) => ({
      ...f,
      name: "dns-primary",
      protocol: "udp",
      dst_port: "53",
      action_kind: "set_gateway",
      description: "Predictable DNS resolution path",
    }),
  },
];

/* ────────────────────────── Page ────────────────────────── */

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [groups, setGroups] = useState<GatewayGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const [panelOpen, setPanelOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

  const [blast, setBlast] = useState<BlastRadius | null>(null);
  const [blastLoading, setBlastLoading] = useState(false);

  const [dragId, setDragId] = useState<string | null>(null);
  const [dragOverId, setDragOverId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [p, i, g, grp] = await Promise.all([
        api<{ data: PolicyRule[] }>("GET", "/api/v1/multiwan/policies"),
        api<{ data: RoutingInstance[] }>("GET", "/api/v1/multiwan/instances"),
        api<{ data: Gateway[] }>("GET", "/api/v1/multiwan/gateways"),
        api<{ data: GatewayGroup[] }>("GET", "/api/v1/multiwan/groups"),
      ]);
      setPolicies(p.data);
      setInstances(i.data);
      setGateways(g.data);
      setGroups(grp.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "fetch failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 15_000);
    return () => clearInterval(t);
  }, [refresh]);

  /* ────────── validation ────────── */

  function validateForm(): boolean {
    const e: Record<string, string> = {};
    if (form.priority < 1 || form.priority > 65535) e.priority = "1–65535";
    const n = validateName(form.name);
    if (n) e.name = n;
    if (form.iface_in) {
      const i = validateInterface(form.iface_in);
      if (i) e.iface_in = i;
    }
    const s = validateCidr(form.src_addr);
    if (s) e.src_addr = s;
    const d = validateCidr(form.dst_addr);
    if (d) e.dst_addr = d;
    const sp = validatePortSpec(form.src_port);
    if (sp) e.src_port = sp;
    const dp = validatePortSpec(form.dst_port);
    if (dp) e.dst_port = dp;
    if (!form.target_id) e.target_id = "required";
    if (form.dst_port && form.protocol === "any")
      e.protocol = "must be tcp or udp to match ports";
    setErrs(e);
    return Object.keys(e).length === 0;
  }

  function targetOptions(): { value: string; label: string; state?: string }[] {
    switch (form.action_kind) {
      case "set_instance":
        return instances.map((i) => ({
          value: i.id,
          label: `${i.name} (FIB ${i.fib_number})`,
        }));
      case "set_gateway":
        return gateways.map((g) => ({
          value: g.id,
          label: `${g.name} (${g.interface} → ${g.next_hop})`,
          state: g.state,
        }));
      case "set_group":
        return groups.map((g) => ({
          value: g.id,
          label: `${g.name} (${g.policy})`,
        }));
      default:
        return [];
    }
  }

  /* ────────── CRUD ────────── */

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!validateForm()) return;
    setSubmitting(true);
    setError(null);
    try {
      const body = {
        priority: form.priority,
        name: form.name,
        status: form.status,
        ip_version: form.ip_version,
        iface_in: form.iface_in || null,
        src_addr: form.src_addr,
        dst_addr: form.dst_addr,
        src_port: form.src_port || null,
        dst_port: form.dst_port || null,
        protocol: form.protocol,
        action_kind: form.action_kind,
        target_id: form.target_id,
        description: form.description || null,
      };
      if (editingId) {
        await api("PUT", `/api/v1/multiwan/policies/${editingId}`, body);
      } else {
        await api("POST", "/api/v1/multiwan/policies", body);
      }
      closePanel();
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "save failed");
    } finally {
      setSubmitting(false);
    }
  }

  function openNew() {
    setForm({ ...defaultForm, priority: (policies.length + 1) * 10 });
    setEditingId(null);
    setErrs({});
    setBlast(null);
    setPanelOpen(true);
  }

  function startEdit(p: PolicyRule) {
    setForm({
      priority: p.priority,
      name: p.name,
      status: p.status,
      ip_version: p.ip_version,
      iface_in: p.iface_in || "",
      src_addr: p.src_addr,
      dst_addr: p.dst_addr,
      src_port: p.src_port || "",
      dst_port: p.dst_port || "",
      protocol: p.protocol,
      action_kind: p.action_kind,
      target_id: p.target_id,
      description: p.description || "",
    });
    setEditingId(p.id);
    setErrs({});
    setBlast(null);
    setPanelOpen(true);
  }

  function closePanel() {
    setPanelOpen(false);
    setEditingId(null);
    setForm(defaultForm);
    setErrs({});
    setBlast(null);
  }

  function applyPreset(p: Preset) {
    setForm(p.apply({ ...defaultForm, priority: (policies.length + 1) * 10 }));
    setEditingId(null);
    setErrs({});
    setPanelOpen(true);
  }

  async function toggle(p: PolicyRule) {
    try {
      await api("PUT", `/api/v1/multiwan/policies/${p.id}/toggle`, {
        enabled: p.status !== "active",
      });
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "toggle failed");
    }
  }

  async function duplicate(id: string) {
    try {
      await api("POST", `/api/v1/multiwan/policies/${id}/duplicate`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "duplicate failed");
    }
  }

  async function deletePolicy(id: string) {
    if (!confirm("Delete policy?")) return;
    try {
      await api("DELETE", `/api/v1/multiwan/policies/${id}`);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "delete failed");
    }
  }

  async function applyNow() {
    if (!confirm("Reload pf with current policies?")) return;
    try {
      await api("POST", "/api/v1/multiwan/apply", {});
    } catch (e) {
      setError(e instanceof Error ? e.message : "apply failed");
    }
  }

  async function previewBlast() {
    setBlastLoading(true);
    setBlast(null);
    try {
      const report = await api<{ data: BlastRadius }>(
        "POST",
        "/api/v1/multiwan/preview",
        {
          policies: policies.map((p) => ({
            priority: p.priority,
            name: p.name,
            status: p.status,
            ip_version: p.ip_version,
            iface_in: p.iface_in,
            src_addr: p.src_addr,
            dst_addr: p.dst_addr,
            src_port: p.src_port,
            dst_port: p.dst_port,
            protocol: p.protocol,
            action_kind: p.action_kind,
            target_id: p.target_id,
            description: p.description,
          })),
        },
      );
      setBlast(report.data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "preview failed");
    } finally {
      setBlastLoading(false);
    }
  }

  /* ────────── drag-to-reorder ────────── */

  async function persistOrder(newOrder: PolicyRule[]) {
    setPolicies(newOrder);
    try {
      await api("PUT", "/api/v1/multiwan/policies/reorder", {
        policy_ids: newOrder.map((p) => p.id),
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "reorder failed");
      refresh();
    }
  }

  function handleDrop(overId: string) {
    if (!dragId || dragId === overId) return;
    const fromIdx = policies.findIndex((p) => p.id === dragId);
    const toIdx = policies.findIndex((p) => p.id === overId);
    if (fromIdx < 0 || toIdx < 0) return;
    const next = [...policies];
    const [moved] = next.splice(fromIdx, 1);
    next.splice(toIdx, 0, moved);
    persistOrder(next);
    setDragId(null);
    setDragOverId(null);
  }

  /* ────────── rendering ────────── */

  const visible = useMemo(() => {
    const q = filter.toLowerCase();
    if (!q) return policies;
    return policies.filter((p) => {
      return (
        p.name.toLowerCase().includes(q) ||
        p.src_addr.toLowerCase().includes(q) ||
        p.dst_addr.toLowerCase().includes(q) ||
        p.protocol.toLowerCase().includes(q) ||
        (p.dst_port || "").includes(q) ||
        (p.description || "").toLowerCase().includes(q)
      );
    });
  }, [policies, filter]);

  function targetLabel(p: PolicyRule): {
    text: string;
    color: string;
    health?: string;
  } {
    if (p.action_kind === "set_instance") {
      const i = instances.find((x) => x.id === p.target_id);
      return {
        text: i ? `FIB ${i.fib_number} · ${i.name}` : "?",
        color: "text-cyan-400",
      };
    }
    if (p.action_kind === "set_gateway") {
      const g = gateways.find((x) => x.id === p.target_id);
      return {
        text: g ? g.name : "?",
        color: "text-green-400",
        health: g?.state,
      };
    }
    const g = groups.find((x) => x.id === p.target_id);
    return {
      text: g ? `${g.name} (${g.policy})` : "?",
      color: "text-purple-400",
    };
  }

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto">
      {/* ───────── Header ───────── */}
      <div className="flex flex-wrap gap-3 items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Policy Routing</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Ordered rules. First match wins. Drag rows to change priority.
            All changes are staged until you click Apply.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={previewBlast}
            disabled={blastLoading}
            className="px-3 py-2 rounded bg-purple-600 hover:bg-purple-700 text-white text-sm disabled:opacity-50"
          >
            {blastLoading ? "Previewing…" : "Preview blast radius"}
          </button>
          <button
            onClick={applyNow}
            className="px-3 py-2 rounded bg-green-600 hover:bg-green-700 text-white text-sm"
          >
            Apply to pf
          </button>
          <button
            onClick={openNew}
            className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
          >
            + New policy
          </button>
        </div>
      </div>

      {/* ───────── Error ───────── */}
      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-xs opacity-70 hover:opacity-100">
            ✕
          </button>
        </div>
      )}

      {/* ───────── Blast radius panel ───────── */}
      {blast && (
        <div className="bg-[var(--bg-card)] border border-purple-500/30 rounded-lg p-4 space-y-3">
          <div className="flex justify-between items-start">
            <h2 className="text-lg font-semibold text-white">
              Blast radius
              {blast.would_strand_mgmt && (
                <span className="ml-2 text-xs px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">
                  ⚠ would strand management
                </span>
              )}
            </h2>
            <button
              onClick={() => setBlast(null)}
              className="text-xs text-[var(--text-muted)] hover:text-white"
            >
              Dismiss
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
            <Stat label="New pf rules" value={blast.new_rules.length.toString()} color="green" />
            <Stat
              label="Removed pf rules"
              value={blast.removed_rules.length.toString()}
              color="yellow"
            />
            <Stat
              label="Affected flows"
              value={blast.affected_flows.length.toString()}
              color="blue"
            />
          </div>
          {blast.validation.length > 0 && (
            <div className="space-y-1">
              {blast.validation.map((v, i) => (
                <div
                  key={i}
                  className={`text-xs px-2 py-1 rounded ${
                    v.severity === "error"
                      ? "bg-red-500/10 text-red-400 border border-red-500/20"
                      : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                  }`}
                >
                  [{v.severity}] {v.message}
                </div>
              ))}
            </div>
          )}
          {blast.new_rules.length > 0 && (
            <details className="bg-black/30 rounded p-2">
              <summary className="text-xs text-green-400 cursor-pointer">
                + {blast.new_rules.length} new rules
              </summary>
              <pre className="text-xs font-mono text-green-300 mt-2 whitespace-pre-wrap">
                {blast.new_rules.join("\n")}
              </pre>
            </details>
          )}
          {blast.removed_rules.length > 0 && (
            <details className="bg-black/30 rounded p-2">
              <summary className="text-xs text-yellow-400 cursor-pointer">
                − {blast.removed_rules.length} removed rules
              </summary>
              <pre className="text-xs font-mono text-yellow-300 mt-2 whitespace-pre-wrap">
                {blast.removed_rules.join("\n")}
              </pre>
            </details>
          )}
        </div>
      )}

      {/* ───────── Empty-state presets ───────── */}
      {!loading && policies.length === 0 && !panelOpen && (
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-2">Start with a preset</h2>
          <p className="text-sm text-[var(--text-muted)] mb-4">
            Common policies pre-filled for you. Pick one to open the form, or start blank.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {PRESETS.map((p) => (
              <button
                key={p.name}
                onClick={() => applyPreset(p)}
                className="text-left p-3 rounded border border-[var(--border)] bg-black/20 hover:bg-black/40 hover:border-blue-500/50 transition-colors"
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xl">{p.icon}</span>
                  <span className="text-white font-medium">{p.name}</span>
                </div>
                <p className="text-xs text-[var(--text-muted)]">{p.description}</p>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* ───────── Toolbar: filter ───────── */}
      {policies.length > 0 && (
        <div className="flex gap-2">
          <input
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter by name, src/dst, protocol, port…"
            className="flex-1 px-3 py-2 rounded bg-black/30 border border-[var(--border)] text-white text-sm"
          />
          {filter && (
            <button
              onClick={() => setFilter("")}
              className="px-3 py-2 text-sm text-[var(--text-muted)] hover:text-white"
            >
              Clear
            </button>
          )}
        </div>
      )}

      {/* ───────── Rule list ───────── */}
      {loading ? (
        <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
      ) : policies.length === 0 ? null : visible.length === 0 ? (
        <div className="p-8 text-center text-[var(--text-muted)]">No rules match filter.</div>
      ) : (
        <div className="space-y-2">
          {visible.map((p, idx) => {
            const tgt = targetLabel(p);
            const isDragging = dragId === p.id;
            const isDragOver = dragOverId === p.id;
            const enabled = p.status === "active";
            return (
              <div
                key={p.id}
                draggable
                onDragStart={() => setDragId(p.id)}
                onDragEnd={() => {
                  setDragId(null);
                  setDragOverId(null);
                }}
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOverId(p.id);
                }}
                onDragLeave={() => setDragOverId((curr) => (curr === p.id ? null : curr))}
                onDrop={() => handleDrop(p.id)}
                className={`
                  bg-[var(--bg-card)] border rounded-lg p-3 flex items-center gap-3
                  transition-colors cursor-move
                  ${isDragging ? "opacity-40" : ""}
                  ${isDragOver ? "border-blue-500" : "border-[var(--border)]"}
                  ${!enabled ? "opacity-60" : ""}
                `}
              >
                <div className="text-[var(--text-muted)] text-xs font-mono w-8 flex-shrink-0 text-center">
                  ⋮⋮
                  <div className="mt-1">{idx + 1}</div>
                </div>

                {/* Enable toggle */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    toggle(p);
                  }}
                  className={`flex-shrink-0 w-10 h-5 rounded-full transition-colors ${
                    enabled ? "bg-green-600" : "bg-gray-600"
                  } relative`}
                  title={enabled ? "Disable" : "Enable"}
                >
                  <div
                    className={`absolute top-0.5 w-4 h-4 rounded-full bg-white transition-all ${
                      enabled ? "left-5" : "left-0.5"
                    }`}
                  />
                </button>

                {/* Name + description */}
                <div className="flex-shrink-0 min-w-0 w-48">
                  <div className="text-white font-medium truncate">{p.name}</div>
                  {p.description && (
                    <div className="text-xs text-[var(--text-muted)] truncate">
                      {p.description}
                    </div>
                  )}
                </div>

                {/* Match badges */}
                <div className="flex flex-wrap gap-1 flex-1 min-w-0">
                  {p.iface_in && <Badge color="cyan">in:{p.iface_in}</Badge>}
                  {p.ip_version !== "both" && <Badge color="gray">{p.ip_version}</Badge>}
                  {p.protocol !== "any" && <Badge color="blue">{p.protocol}</Badge>}
                  <Badge color="gray">src:{p.src_addr}</Badge>
                  <Badge color="gray">dst:{p.dst_addr}</Badge>
                  {p.src_port && <Badge color="yellow">sport:{p.src_port}</Badge>}
                  {p.dst_port && <Badge color="yellow">dport:{p.dst_port}</Badge>}
                </div>

                {/* Arrow */}
                <div className="text-[var(--text-muted)] flex-shrink-0">→</div>

                {/* Target */}
                <div className="flex-shrink-0 min-w-0 w-48 text-right">
                  <div className={`font-medium truncate ${tgt.color}`}>
                    {tgt.text}
                    {tgt.health && (
                      <span
                        className={`ml-2 inline-block w-2 h-2 rounded-full ${
                          tgt.health === "up"
                            ? "bg-green-400"
                            : tgt.health === "warning"
                              ? "bg-yellow-400"
                              : tgt.health === "down"
                                ? "bg-red-400"
                                : "bg-gray-400"
                        }`}
                        title={`gateway ${tgt.health}`}
                      />
                    )}
                  </div>
                  <div className="text-xs text-[var(--text-muted)]">{p.action_kind}</div>
                </div>

                {/* Actions */}
                <div className="flex gap-1 flex-shrink-0">
                  <IconButton onClick={() => startEdit(p)} title="Edit">
                    ✎
                  </IconButton>
                  <IconButton onClick={() => duplicate(p.id)} title="Duplicate">
                    ⧉
                  </IconButton>
                  <IconButton
                    onClick={() => deletePolicy(p.id)}
                    title="Delete"
                    color="red"
                  >
                    ✕
                  </IconButton>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ───────── Side panel form ───────── */}
      {panelOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 flex items-stretch justify-end"
          onClick={closePanel}
        >
          <div
            className="w-full max-w-xl bg-[var(--bg-card)] border-l border-[var(--border)] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="sticky top-0 bg-[var(--bg-card)] border-b border-[var(--border)] p-4 flex justify-between items-center z-10">
              <h2 className="text-lg font-bold text-white">
                {editingId ? "Edit policy" : "New policy"}
              </h2>
              <button onClick={closePanel} className="text-[var(--text-muted)] hover:text-white">
                ✕
              </button>
            </div>

            <form onSubmit={submit} className="p-4 space-y-5">
              <Section title="Identity">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Name" err={errs.name} required>
                    <input
                      autoFocus
                      value={form.name}
                      onChange={(e) => setForm({ ...form, name: e.target.value })}
                      className={inputCls(!!errs.name)}
                    />
                  </Field>
                  <Field label="Priority" err={errs.priority} required>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={form.priority}
                      onChange={(e) =>
                        setForm({ ...form, priority: parseInt(e.target.value, 10) || 0 })
                      }
                      className={inputCls(!!errs.priority)}
                    />
                  </Field>
                </div>
                <Field label="Description">
                  <input
                    value={form.description}
                    onChange={(e) => setForm({ ...form, description: e.target.value })}
                    className={inputCls(false)}
                  />
                </Field>
                <label className="flex items-center gap-2 text-sm text-white">
                  <input
                    type="checkbox"
                    checked={form.status === "active"}
                    onChange={(e) =>
                      setForm({ ...form, status: e.target.checked ? "active" : "disabled" })
                    }
                  />
                  Enabled
                </label>
              </Section>

              <Section title="Match">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="IP version">
                    <select
                      value={form.ip_version}
                      onChange={(e) => setForm({ ...form, ip_version: e.target.value })}
                      className={inputCls(false)}
                    >
                      <option value="both">IPv4 + IPv6</option>
                      <option value="v4">IPv4</option>
                      <option value="v6">IPv6</option>
                    </select>
                  </Field>
                  <Field label="Protocol" err={errs.protocol}>
                    <select
                      value={form.protocol}
                      onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                      className={inputCls(!!errs.protocol)}
                    >
                      <option value="any">any</option>
                      <option value="tcp">tcp</option>
                      <option value="udp">udp</option>
                      <option value="icmp">icmp</option>
                    </select>
                  </Field>
                  <Field label="Inbound interface (optional)" err={errs.iface_in}>
                    <input
                      value={form.iface_in}
                      onChange={(e) => setForm({ ...form, iface_in: e.target.value })}
                      placeholder="em_lan"
                      className={inputCls(!!errs.iface_in)}
                    />
                  </Field>
                  <div />
                  <Field label="Source address" err={errs.src_addr} required>
                    <input
                      value={form.src_addr}
                      onChange={(e) => setForm({ ...form, src_addr: e.target.value })}
                      placeholder="10.0.0.0/24 or any"
                      className={inputCls(!!errs.src_addr)}
                    />
                  </Field>
                  <Field label="Destination address" err={errs.dst_addr} required>
                    <input
                      value={form.dst_addr}
                      onChange={(e) => setForm({ ...form, dst_addr: e.target.value })}
                      placeholder="any"
                      className={inputCls(!!errs.dst_addr)}
                    />
                  </Field>
                  <Field label="Source port (optional)" err={errs.src_port}>
                    <input
                      value={form.src_port}
                      onChange={(e) => setForm({ ...form, src_port: e.target.value })}
                      placeholder="any or 1024:65535"
                      className={inputCls(!!errs.src_port)}
                    />
                  </Field>
                  <Field label="Destination port (optional)" err={errs.dst_port}>
                    <input
                      value={form.dst_port}
                      onChange={(e) => setForm({ ...form, dst_port: e.target.value })}
                      placeholder="443 or 80,443"
                      className={inputCls(!!errs.dst_port)}
                    />
                  </Field>
                </div>
              </Section>

              <Section title="Action">
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Action">
                    <select
                      value={form.action_kind}
                      onChange={(e) =>
                        setForm({ ...form, action_kind: e.target.value, target_id: "" })
                      }
                      className={inputCls(false)}
                    >
                      <option value="set_instance">Set routing instance</option>
                      <option value="set_gateway">Route via gateway</option>
                      <option value="set_group">Route via gateway group</option>
                    </select>
                  </Field>
                  <Field label="Target" err={errs.target_id} required>
                    <select
                      value={form.target_id}
                      onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                      className={inputCls(!!errs.target_id)}
                    >
                      <option value="">Select…</option>
                      {targetOptions().map((o) => (
                        <option key={o.value} value={o.value}>
                          {o.label}
                          {o.state && ` — ${o.state}`}
                        </option>
                      ))}
                    </select>
                  </Field>
                </div>
              </Section>

              {/* Live pf preview */}
              <Section title="pf rule preview">
                <pre className="text-xs font-mono text-green-300 bg-black/40 p-3 rounded whitespace-pre-wrap">
                  {pfPreview(form, instances, gateways, groups)}
                </pre>
              </Section>

              <div className="flex gap-2 pt-2 border-t border-[var(--border)]">
                <button
                  type="submit"
                  disabled={submitting}
                  className="flex-1 px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
                >
                  {submitting ? "Saving…" : editingId ? "Save changes" : "Create policy"}
                </button>
                <button
                  type="button"
                  onClick={closePanel}
                  className="px-3 py-2 rounded border border-[var(--border)] text-white text-sm hover:bg-black/30"
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

/* ────────────────────────── Small components ────────────────────────── */

function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: "green" | "yellow" | "blue" | "red";
}) {
  const c = {
    green: "text-green-400",
    yellow: "text-yellow-400",
    blue: "text-blue-400",
    red: "text-red-400",
  }[color];
  return (
    <div className="bg-black/30 border border-[var(--border)] rounded p-3">
      <div className="text-xs text-[var(--text-muted)] uppercase">{label}</div>
      <div className={`text-2xl font-bold ${c}`}>{value}</div>
    </div>
  );
}

function Badge({
  color,
  children,
}: {
  color: "cyan" | "blue" | "yellow" | "gray";
  children: React.ReactNode;
}) {
  const c = {
    cyan: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
    blue: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    yellow: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    gray: "bg-gray-500/10 text-gray-400 border-gray-500/20",
  }[color];
  return (
    <span
      className={`inline-flex items-center text-[10px] px-1.5 py-0.5 rounded border font-mono ${c}`}
    >
      {children}
    </span>
  );
}

function IconButton({
  onClick,
  title,
  color = "default",
  children,
}: {
  onClick: () => void;
  title: string;
  color?: "default" | "red";
  children: React.ReactNode;
}) {
  const c =
    color === "red"
      ? "bg-red-600/70 hover:bg-red-700"
      : "bg-gray-700/60 hover:bg-gray-600";
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      title={title}
      className={`${c} text-white w-7 h-7 flex items-center justify-center rounded text-xs transition-colors`}
    >
      {children}
    </button>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h3 className="text-xs uppercase tracking-wider text-[var(--text-muted)] font-semibold">
        {title}
      </h3>
      <div className="space-y-2">{children}</div>
    </div>
  );
}

function Field({
  label,
  err,
  required,
  children,
}: {
  label: string;
  err?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs text-[var(--text-muted)] mb-1">
        {label}
        {required && <span className="text-red-400 ml-1">*</span>}
      </label>
      {children}
      {err && <p className="text-xs text-red-400 mt-1">{err}</p>}
    </div>
  );
}

function inputCls(hasErr: boolean): string {
  return `w-full px-3 py-2 rounded bg-black/30 border text-white text-sm ${
    hasErr ? "border-red-500" : "border-[var(--border)]"
  }`;
}

/* ────────────────────────── Live pf preview ────────────────────────── */

function pfPreview(
  form: FormState,
  instances: RoutingInstance[],
  gateways: Gateway[],
  groups: GatewayGroup[],
): string {
  if (!form.target_id) return "# select a target to preview emitted pf rule";
  const af = form.ip_version === "v4" ? " inet" : form.ip_version === "v6" ? " inet6" : "";
  const proto = form.protocol !== "any" ? ` proto ${form.protocol}` : "";
  const sport = form.src_port ? ` port ${form.src_port}` : "";
  const dport = form.dst_port ? ` port ${form.dst_port}` : "";
  const label = `pbr:<uuid>`;

  if (form.action_kind === "set_instance") {
    const inst = instances.find((i) => i.id === form.target_id);
    if (!inst) return "# instance not found";
    const iface = form.iface_in || "<iface_in>";
    return `pass in quick on ${iface}${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} rtable ${inst.fib_number} keep state (if-bound) label "${label}"`;
  }

  if (form.action_kind === "set_gateway") {
    const gw = gateways.find((g) => g.id === form.target_id);
    if (!gw) return "# gateway not found";
    return [
      `# anchor aifw-pbr`,
      `pass out quick on ${gw.interface}${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} route-to (${gw.interface} ${gw.next_hop}) keep state (if-bound) label "${label}"`,
      ``,
      `# anchor aifw-mwan-reply`,
      `pass in quick${form.iface_in ? ` on ${form.iface_in}` : ""}${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} reply-to (${gw.interface} ${gw.next_hop}) keep state (if-bound) label "${label}:rep"`,
    ].join("\n");
  }

  if (form.action_kind === "set_group") {
    const grp = groups.find((g) => g.id === form.target_id);
    if (!grp) return "# group not found";
    return `# Emitted per currently-healthy members at apply time, e.g.\npass out quick on <iface>${af}${proto} from ${form.src_addr}${sport} to ${form.dst_addr}${dport} route-to { (em1 gw1) weight N, (em2 gw2) weight M } round-robin${
      grp.sticky === "src" ? " sticky-address" : ""
    } keep state (if-bound) label "${label}:grp"`;
  }

  return "";
}
