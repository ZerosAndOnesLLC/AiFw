"use client";

import { useState, useMemo } from "react";
import Help, { HelpBanner } from "../Help";
import {
  FormState,
  PolicyRule,
  Preset,
  defaultForm,
  targetLabel,
  validatePolicyForm,
} from "@/lib/api/multiwan-policies";
import { useMultiwanPolicies } from "@/hooks/useMultiwanPolicies";
import { BlastRadiusPanel } from "./components/BlastRadiusPanel";
import { PolicyFormPanel } from "./components/PolicyFormPanel";
import { PolicyList } from "./components/PolicyList";
import { PresetGrid } from "./components/PresetGrid";

export default function PoliciesPage() {
  const {
    policies,
    instances,
    gateways,
    groups,
    loading,
    error,
    clearError,
    submitting,
    savePolicy,
    toggle,
    duplicate,
    removePolicy,
    applyNow,
    blast,
    blastLoading,
    previewBlast,
    dismissBlast,
    persistOrder,
  } = useMultiwanPolicies();

  const [filter, setFilter] = useState("");

  const [panelOpen, setPanelOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<FormState>(defaultForm);
  const [errs, setErrs] = useState<Record<string, string>>({});

  /* ────────── form panel ────────── */

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const errors = validatePolicyForm(form);
    setErrs(errors);
    if (Object.keys(errors).length > 0) return;
    await savePolicy(editingId, form, closePanel);
  }

  function openNew() {
    setForm({ ...defaultForm, priority: (policies.length + 1) * 10 });
    setEditingId(null);
    setErrs({});
    dismissBlast();
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
    dismissBlast();
    setPanelOpen(true);
  }

  function closePanel() {
    setPanelOpen(false);
    setEditingId(null);
    setForm(defaultForm);
    setErrs({});
    dismissBlast();
  }

  function applyPreset(p: Preset) {
    setForm(p.apply({ ...defaultForm, priority: (policies.length + 1) * 10 }));
    setEditingId(null);
    setErrs({});
    setPanelOpen(true);
  }

  /* ────────── drag-to-reorder ────────── */

  function handleReorder(dragId: string, overId: string) {
    const fromIdx = policies.findIndex((p) => p.id === dragId);
    const toIdx = policies.findIndex((p) => p.id === overId);
    if (fromIdx < 0 || toIdx < 0) return;
    const next = [...policies];
    const [moved] = next.splice(fromIdx, 1);
    next.splice(toIdx, 0, moved);
    persistOrder(next);
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

  return (
    <div className="p-6 space-y-5 max-w-7xl mx-auto">
      {/* ───────── Header ───────── */}
      <div className="flex flex-wrap gap-3 items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            Policy Routing
            <Help title="Policy routing" size="md">
              <p>
                Policies match traffic on the usual 5-tuple plus interface and
                ip-version, and steer matched traffic to one of three targets:
              </p>
              <ul className="list-disc ml-5 space-y-1">
                <li>
                  <b>Set routing instance</b> — traffic joins a FIB. pf uses
                  <code> rtable N</code>. Clean isolation.
                </li>
                <li>
                  <b>Route via gateway</b> — pf emits{" "}
                  <code>route-to (if gw)</code> with a paired <code>reply-to</code>{" "}
                  for return traffic. State is iface-bound.
                </li>
                <li>
                  <b>Route via group</b> — emits a weighted{" "}
                  <code>route-to &#123; ... &#125;</code> that picks from currently
                  healthy group members.
                </li>
              </ul>
              <p className="text-blue-400">
                Rules are evaluated top to bottom — first match wins. Drag to
                reorder.
              </p>
            </Help>
          </h1>
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
            title="Dry-run: show which pf rules change + which live flows would move"
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

      <HelpBanner title="How policy routing works" storageKey="mwan-policies">
        <p>
          Every policy generates one or two pf rules that live in AiFw-managed
          anchors evaluated before the normal firewall:
        </p>
        <ul className="list-disc ml-5 space-y-1">
          <li>
            <code>aifw-pbr</code> — policy-routing (route-to / rtable) rules
          </li>
          <li>
            <code>aifw-mwan-reply</code> — paired reply-to rules so return
            packets come back via the same WAN
          </li>
        </ul>
        <p>
          Rules always use <code>keep state (if-bound)</code> so an established
          flow doesn&apos;t silently fail over to a different WAN mid-stream.
        </p>
        <p>
          <b>Preview blast radius</b> before applying — it shows the exact pf
          rule diff and which currently-open flows would be affected. Especially
          important before sweeping policies (e.g. <code>src=any</code>) that
          could move your admin session.
        </p>
      </HelpBanner>

      {/* ───────── Error ───────── */}
      {error && (
        <div className="p-3 text-sm rounded-md border text-red-400 bg-red-500/10 border-red-500/20 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={clearError} className="text-xs opacity-70 hover:opacity-100">
            ✕
          </button>
        </div>
      )}

      {/* ───────── Blast radius panel ───────── */}
      {blast && <BlastRadiusPanel blast={blast} onDismiss={dismissBlast} />}

      {/* ───────── Empty-state presets ───────── */}
      {!loading && policies.length === 0 && !panelOpen && (
        <PresetGrid onApply={applyPreset} />
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
        <PolicyList
          rules={visible}
          targetLabelFor={(p) => targetLabel(p, instances, gateways, groups)}
          onToggle={toggle}
          onEdit={startEdit}
          onDuplicate={duplicate}
          onDelete={removePolicy}
          onReorder={handleReorder}
        />
      )}

      {/* ───────── Side panel form ───────── */}
      {panelOpen && (
        <PolicyFormPanel
          form={form}
          setForm={setForm}
          errs={errs}
          editingId={editingId}
          submitting={submitting}
          instances={instances}
          gateways={gateways}
          groups={groups}
          onSubmit={submit}
          onClose={closePanel}
        />
      )}
    </div>
  );
}
