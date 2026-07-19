"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import type { Rule } from "@/lib/api";
import type { RuleForm } from "@/lib/api/rules";
import { defaultForm, getScheduleName, ruleToForm } from "@/lib/api/rules";
import { useRules } from "@/hooks/useRules";
import { RuleFormModal } from "./components/RuleFormModal";
import { RulesTable } from "./components/RulesTable";
import { SystemRulesPanel } from "./components/SystemRulesPanel";

export default function RulesPage() {
  const searchParams = useSearchParams();
  const urlInterface = searchParams.get("interface");
  const {
    rules,
    interfaces,
    schedules,
    gateways,
    systemRules,
    loading,
    error,
    setError,
    submitting,
    blockLogging,
    blockLoggingPending,
    moveRule,
    toggleBlockLogging,
    applyBlockLogging,
    saveRule,
    deleteRule,
    toggleStatus,
  } = useRules();

  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<RuleForm>(defaultForm);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [interfaceFilter, setInterfaceFilter] = useState<string>(urlInterface || "all");
  // Sync filter with URL param
  useEffect(() => { queueMicrotask(() => setInterfaceFilter(urlInterface || "all")); }, [urlInterface]);

  /* ── Edit existing rule ────────────────────────────────────────── */

  const handleEdit = (rule: Rule) => {
    setForm(ruleToForm(rule));
    setEditingId(rule.id);
    setShowModal(true);
  };

  const handleClone = (rule: Rule) => {
    handleEdit(rule);
    setEditingId(null); // null = create new (not editing existing)
  };

  /* ── Cancel form ───────────────────────────────────────────────── */

  const handleCancel = () => {
    setForm(defaultForm);
    setEditingId(null);
    setShowModal(false);
  };

  /* ── Form submit ───────────────────────────────────────────────── */

  // On success the hook resets the form / closes the modal (same
  // sequence as cancel) before refreshing the rule list.
  const handleSubmit = () => saveRule(form, editingId, handleCancel);

  /* ── Filtered rules ───────────────────────────────────────────── */

  const filteredRules = interfaceFilter === "all"
    ? rules
    : rules.filter((r) => (r.interface || "any") === interfaceFilter);

  const inboundRules = filteredRules.filter((r) => r.direction === "in");
  const outboundRules = filteredRules.filter((r) => r.direction === "out");

  /* ── Render ────────────────────────────────────────────────────── */

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Firewall Rules</h1>
          <p className="text-sm text-gray-400">
            {rules.length} rule{rules.length !== 1 ? "s" : ""} &middot;{" "}
            {rules.filter((r) => r.status === "active").length} active
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <label className="flex items-center gap-2 text-xs text-gray-400 cursor-pointer" title="Toggle logging on all block rules for performance testing">
              <button
                onClick={() => toggleBlockLogging(!blockLogging)}
                className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${blockLogging ? "bg-green-500" : "bg-gray-600"}`}
              >
                <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${blockLogging ? "translate-x-[18px]" : "translate-x-[3px]"}`} />
              </button>
              Block Logging
            </label>
            {blockLoggingPending && (
              <button onClick={applyBlockLogging} className="px-2 py-1 text-[10px] bg-purple-600 hover:bg-purple-700 text-white rounded">
                Apply
              </button>
            )}
          </div>
          <button
            onClick={() => {
              setForm(defaultForm);
              setEditingId(null);
              setShowModal(true);
            }}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
            </svg>
            Add Rule
          </button>
        </div>
      </div>

      {/* Error Banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* ─── Interface Filter Tabs ─────────────────────────────────── */}
      <div className="flex items-center gap-1 flex-wrap">
        <button
          onClick={() => setInterfaceFilter("all")}
          className={`px-3 py-1.5 text-xs font-medium rounded-full transition-colors ${
            interfaceFilter === "all"
              ? "bg-blue-600 text-white"
              : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-300 border border-gray-700"
          }`}
        >
          All
        </button>
        {interfaces.map((iface) => (
          <button
            key={iface.name}
            onClick={() => setInterfaceFilter(iface.name)}
            className={`px-3 py-1.5 text-xs font-medium rounded-full transition-colors ${
              interfaceFilter === iface.name
                ? "bg-blue-600 text-white"
                : "bg-gray-800 text-gray-400 hover:bg-gray-700 hover:text-gray-300 border border-gray-700"
            }`}
          >
            {iface.name}
            {iface.description ? ` (${iface.description})` : ""}
          </button>
        ))}
      </div>

      {/* ─── Rules Tables (grouped by direction) ────────────────── */}
      {loading ? (
        <div className="text-center py-12 text-gray-400">Loading rules...</div>
      ) : filteredRules.length === 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg text-center py-12 text-gray-400">
          {interfaceFilter === "all" ? "No firewall rules configured" : `No rules for interface "${interfaceFilter}"`}
        </div>
      ) : (
        <>
          {/* Inbound Rules */}
          <RulesTable
            title="Inbound Rules"
            icon={<svg className="w-4 h-4 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M19 14l-7 7m0 0l-7-7m7 7V3" /></svg>}
            sectionRules={inboundRules}
            allRules={rules}
            onMove={moveRule}
            onToggleStatus={toggleStatus}
            onEdit={handleEdit}
            onClone={handleClone}
            onDelete={deleteRule}
            getScheduleName={(id) => getScheduleName(schedules, id)}
          />
          {/* Outbound Rules */}
          <RulesTable
            title="Outbound Rules"
            icon={<svg className="w-4 h-4 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>}
            sectionRules={outboundRules}
            allRules={rules}
            onMove={moveRule}
            onToggleStatus={toggleStatus}
            onEdit={handleEdit}
            onClone={handleClone}
            onDelete={deleteRule}
            getScheduleName={(id) => getScheduleName(schedules, id)}
          />
        </>
      )}

      {/* ─── Add/Edit Rule Modal ───────────────────────────────────── */}
      {showModal && (
        <RuleFormModal
          form={form}
          setForm={setForm}
          editingId={editingId}
          submitting={submitting}
          interfaces={interfaces}
          schedules={schedules}
          gateways={gateways}
          onSubmit={handleSubmit}
          onCancel={handleCancel}
        />
      )}

      {/* ─── Active PF Rules (collapsible) ───────────────────────────── */}
      <SystemRulesPanel systemRules={systemRules} />
    </div>
  );
}
