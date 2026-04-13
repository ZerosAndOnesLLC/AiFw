"use client";

import { useState, useEffect, useCallback } from "react";
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
  validatePriority,
} from "../lib";

const ACTIONS = [
  { value: "set_instance", label: "Set routing instance (FIB)" },
  { value: "set_gateway", label: "Route through gateway" },
  { value: "set_group", label: "Route through group" },
];

const PROTOS = ["any", "tcp", "udp", "icmp"];
const IP_VERSIONS = [
  { value: "both", label: "IPv4 + IPv6" },
  { value: "v4", label: "IPv4 only" },
  { value: "v6", label: "IPv6 only" },
];

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

export default function PoliciesPage() {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [instances, setInstances] = useState<RoutingInstance[]>([]);
  const [gateways, setGateways] = useState<Gateway[]>([]);
  const [groups, setGroups] = useState<GatewayGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [errs, setErrs] = useState<Record<string, string>>({});
  const [submitting, setSubmitting] = useState(false);

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
  }, [refresh]);

  function validateForm() {
    const e: Record<string, string> = {};
    const p = validatePriority(form.priority);
    if (p) e.priority = p;
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
    setErrs(e);
    return Object.keys(e).length === 0;
  }

  function targetOptions(): { value: string; label: string }[] {
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
      setForm(defaultForm);
      setEditingId(null);
      setShowForm(false);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "save failed");
    } finally {
      setSubmitting(false);
    }
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
    setShowForm(true);
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

  async function previewApply() {
    try {
      const report = await api<{ data: { would_strand_mgmt: boolean; new_rules: string[]; removed_rules: string[]; validation: { severity: string; message: string }[] } }>(
        "POST",
        "/api/v1/multiwan/preview",
        { policies: policies.map((p) => ({
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
          })) },
      );
      alert(
        `New: ${report.data.new_rules.length}\nRemoved: ${report.data.removed_rules.length}\nStrands mgmt: ${report.data.would_strand_mgmt}\n\nValidation:\n${report.data.validation.map((v) => `[${v.severity}] ${v.message}`).join("\n") || "ok"}`,
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : "preview failed");
    }
  }

  async function applyNow() {
    if (!confirm("Reload pf with current policies?")) return;
    try {
      await api("POST", "/api/v1/multiwan/apply", {});
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "apply failed");
    }
  }

  function targetLabel(p: PolicyRule): string {
    if (p.action_kind === "set_instance") {
      const i = instances.find((x) => x.id === p.target_id);
      return i ? `→ FIB ${i.fib_number} (${i.name})` : p.target_id;
    }
    if (p.action_kind === "set_gateway") {
      const g = gateways.find((x) => x.id === p.target_id);
      return g ? `→ ${g.name}` : p.target_id;
    }
    const g = groups.find((x) => x.id === p.target_id);
    return g ? `→ group ${g.name}` : p.target_id;
  }

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-white">Policy Routing</h1>
          <p className="text-sm text-[var(--text-muted)] mt-1">
            Steer traffic to a gateway, group, or FIB based on 5-tuple + interface + metadata.
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={previewApply}
            className="px-3 py-2 rounded bg-purple-600 hover:bg-purple-700 text-white text-sm"
          >
            Preview blast radius
          </button>
          <button
            onClick={applyNow}
            className="px-3 py-2 rounded bg-green-600 hover:bg-green-700 text-white text-sm"
          >
            Apply now
          </button>
          <button
            onClick={() => {
              setShowForm(!showForm);
              if (showForm) {
                setEditingId(null);
                setForm(defaultForm);
              }
            }}
            className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm"
          >
            {showForm ? "Cancel" : "+ New policy"}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20">
          {error}
        </div>
      )}

      {showForm && (
        <form
          onSubmit={submit}
          className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3"
        >
          <h2 className="text-lg font-semibold text-white">
            {editingId ? "Edit" : "New"} policy
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <Field label="Name" err={errs.name}>
              <input
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                className={inputCls(!!errs.name)}
              />
            </Field>
            <Field label="Priority" err={errs.priority}>
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
            <Field label="Status">
              <select
                value={form.status}
                onChange={(e) => setForm({ ...form, status: e.target.value })}
                className={inputCls(false)}
              >
                <option value="active">Active</option>
                <option value="disabled">Disabled</option>
              </select>
            </Field>
            <Field label="IP Version">
              <select
                value={form.ip_version}
                onChange={(e) => setForm({ ...form, ip_version: e.target.value })}
                className={inputCls(false)}
              >
                {IP_VERSIONS.map((v) => (
                  <option key={v.value} value={v.value}>
                    {v.label}
                  </option>
                ))}
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
            <Field label="Protocol">
              <select
                value={form.protocol}
                onChange={(e) => setForm({ ...form, protocol: e.target.value })}
                className={inputCls(false)}
              >
                {PROTOS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Source address" err={errs.src_addr}>
              <input
                value={form.src_addr}
                onChange={(e) => setForm({ ...form, src_addr: e.target.value })}
                placeholder="10.0.0.0/24 or any"
                className={inputCls(!!errs.src_addr)}
              />
            </Field>
            <Field label="Destination address" err={errs.dst_addr}>
              <input
                value={form.dst_addr}
                onChange={(e) => setForm({ ...form, dst_addr: e.target.value })}
                placeholder="any"
                className={inputCls(!!errs.dst_addr)}
              />
            </Field>
            <Field label="Destination port (optional)" err={errs.dst_port}>
              <input
                value={form.dst_port}
                onChange={(e) => setForm({ ...form, dst_port: e.target.value })}
                placeholder="443 or 80:443"
                className={inputCls(!!errs.dst_port)}
              />
            </Field>
            <Field label="Action">
              <select
                value={form.action_kind}
                onChange={(e) =>
                  setForm({ ...form, action_kind: e.target.value, target_id: "" })
                }
                className={inputCls(false)}
              >
                {ACTIONS.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Target" err={errs.target_id}>
              <select
                value={form.target_id}
                onChange={(e) => setForm({ ...form, target_id: e.target.value })}
                className={inputCls(!!errs.target_id)}
              >
                <option value="">Select…</option>
                {targetOptions().map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Description">
              <input
                value={form.description}
                onChange={(e) => setForm({ ...form, description: e.target.value })}
                className={inputCls(false)}
              />
            </Field>
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-2 rounded bg-blue-600 hover:bg-blue-700 text-white text-sm disabled:opacity-50"
          >
            {submitting ? "Saving…" : editingId ? "Save changes" : "Create"}
          </button>
        </form>
      )}

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-8 text-center text-[var(--text-muted)]">Loading…</div>
        ) : policies.length === 0 ? (
          <div className="p-8 text-center text-[var(--text-muted)]">No policies yet.</div>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-black/20 text-[var(--text-muted)] text-xs uppercase">
              <tr>
                <th className="text-left px-4 py-2">Priority</th>
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">Match</th>
                <th className="text-left px-4 py-2">Action</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-right px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {policies.map((p) => (
                <tr key={p.id} className="border-t border-[var(--border)]">
                  <td className="px-4 py-3 text-cyan-400 font-mono">{p.priority}</td>
                  <td className="px-4 py-3 text-white font-medium">{p.name}</td>
                  <td className="px-4 py-3 text-xs text-[var(--text-muted)] font-mono">
                    {p.protocol} {p.src_addr} → {p.dst_addr}
                    {p.dst_port && ` :${p.dst_port}`}
                    {p.iface_in && ` on ${p.iface_in}`}
                  </td>
                  <td className="px-4 py-3 text-green-400 text-xs">
                    {targetLabel(p)}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`text-xs px-2 py-1 rounded border ${
                        p.status === "active"
                          ? "bg-green-500/10 text-green-400 border-green-500/30"
                          : "bg-gray-500/10 text-gray-400 border-gray-500/30"
                      }`}
                    >
                      {p.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right space-x-1">
                    <button
                      onClick={() => startEdit(p)}
                      className="text-xs px-2 py-1 rounded bg-blue-600/80 hover:bg-blue-700 text-white"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => deletePolicy(p.id)}
                      className="text-xs px-2 py-1 rounded bg-red-600/80 hover:bg-red-700 text-white"
                    >
                      Del
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

function inputCls(hasErr: boolean): string {
  return `w-full px-3 py-2 rounded bg-black/30 border text-white text-sm ${
    hasErr ? "border-red-500" : "border-[var(--border)]"
  }`;
}

function Field({
  label,
  err,
  children,
}: {
  label: string;
  err?: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs text-[var(--text-muted)] mb-1">{label}</label>
      {children}
      {err && <p className="text-xs text-red-400 mt-1">{err}</p>}
    </div>
  );
}
