"use client";

import type { Dispatch, SetStateAction } from "react";
import type { EntryPoint, RouterForm, UdpService } from "@/lib/api/reverse-proxy/udp";

/* -- Shared styles --------------------------------------------------- */

const inputCls =
  "w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500";
const selectCls =
  "w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500";
const labelCls = "block text-xs text-[var(--text-muted)] mb-1";

interface RouterModalProps {
  form: RouterForm;
  setForm: Dispatch<SetStateAction<RouterForm>>;
  services: UdpService[];
  entrypoints: EntryPoint[];
  editing: boolean;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}

export function RouterModal({ form, setForm, services, entrypoints, editing, submitting, onCancel, onSubmit }: RouterModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">
          {editing ? "Edit UDP Router" : "Add UDP Router"}
        </h3>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className={labelCls}>Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="e.g. dns-router"
              className={inputCls}
            />
          </div>

          {/* Rule */}
          <div>
            <label className={labelCls}>Rule</label>
            <input
              type="text"
              value={form.rule}
              onChange={(e) => setForm((p) => ({ ...p, rule: e.target.value }))}
              placeholder="UDP routing rule"
              className={inputCls}
            />
          </div>

          {/* Service */}
          <div>
            <label className={labelCls}>Service</label>
            <select
              value={form.service}
              onChange={(e) => setForm((p) => ({ ...p, service: e.target.value }))}
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
              value={form.entry_points}
              onChange={(e) => setForm((p) => ({ ...p, entry_points: e.target.value }))}
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
              value={form.priority}
              onChange={(e) => setForm((p) => ({ ...p, priority: e.target.value }))}
              placeholder="0"
              className={inputCls}
            />
          </div>

          {/* Enabled */}
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">Enabled</label>
            <button
              type="button"
              onClick={() => setForm((p) => ({ ...p, enabled: !p.enabled }))}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                form.enabled ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  form.enabled ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            Cancel
          </button>
          <button
            onClick={onSubmit}
            disabled={submitting}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
          >
            {submitting ? "Saving..." : editing ? "Update" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
