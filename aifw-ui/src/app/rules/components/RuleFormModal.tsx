"use client";

import { Dispatch, SetStateAction } from "react";
import type { InterfaceInfo, RuleForm, Schedule } from "@/lib/api/rules";
import {
  ACTIONS,
  IP_VERSIONS,
  PROTOCOLS,
  STATE_TYPES,
  SUBNET_MASKS,
  protocolShowsPorts,
} from "@/lib/api/rules";

/* ─── Tailwind helpers ──────────────────────────────────────────── */

const inputClass =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
const selectClass =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500";
const labelClass = "block text-xs font-medium text-gray-400 mb-1";
const sectionTitle = "text-xs font-semibold text-gray-300 uppercase tracking-wider mb-2";
const checkboxLabel = "flex items-center gap-2 text-sm text-gray-300 cursor-pointer select-none";

/* ─── Add/Edit rule modal ───────────────────────────────────────── */

export function RuleFormModal({
  form,
  setForm,
  editingId,
  submitting,
  interfaces,
  schedules,
  onSubmit,
  onCancel,
}: {
  form: RuleForm;
  setForm: Dispatch<SetStateAction<RuleForm>>;
  editingId: string | null;
  submitting: boolean;
  interfaces: InterfaceInfo[];
  schedules: Schedule[];
  onSubmit: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onCancel}
      />
      {/* Modal content */}
      <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto bg-gray-800 border border-gray-700 rounded-xl shadow-2xl m-4">
        <div className="sticky top-0 bg-gray-800 border-b border-gray-700 px-6 py-4 flex items-center justify-between z-10">
          <h3 className="text-lg font-semibold text-white">
            {editingId ? "Edit Rule" : "Add Rule"}
          </h3>
          <button
            onClick={onCancel}
            className="p-1.5 text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-700"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        <div className="p-6 space-y-5">
          {/* Row 1: Action, Disabled, Interface, Direction, IP Version, Protocol */}
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
            <div>
              <label className={labelClass}>Action</label>
              <select
                value={form.action}
                onChange={(e) => setForm((f) => ({ ...f, action: e.target.value }))}
                className={selectClass}
              >
                {ACTIONS.map((a) => (
                  <option key={a.value} value={a.value}>{a.label}</option>
                ))}
              </select>
            </div>
            <div className="flex items-end pb-1">
              <label className={checkboxLabel}>
                <input
                  type="checkbox"
                  checked={form.disabled}
                  onChange={(e) => setForm((f) => ({ ...f, disabled: e.target.checked }))}
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                />
                Disabled
              </label>
            </div>
            <div>
              <label className={labelClass}>Interface</label>
              <select
                value={form.interface}
                onChange={(e) => setForm((f) => ({ ...f, interface: e.target.value }))}
                className={selectClass}
              >
                <option value="any">any</option>
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name}{iface.description ? ` (${iface.description})` : ""}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelClass}>Direction</label>
              <select
                value={form.direction}
                onChange={(e) => setForm((f) => ({ ...f, direction: e.target.value }))}
                className={selectClass}
              >
                <option value="in">In</option>
                <option value="out">Out</option>
              </select>
            </div>
            <div>
              <label className={labelClass}>IP Version</label>
              <select
                value={form.ip_version}
                onChange={(e) => setForm((f) => ({ ...f, ip_version: e.target.value }))}
                className={selectClass}
              >
                {IP_VERSIONS.map((v) => (
                  <option key={v.value} value={v.value}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelClass}>Protocol</label>
              <select
                value={form.protocol}
                onChange={(e) => setForm((f) => ({ ...f, protocol: e.target.value }))}
                className={selectClass}
              >
                {PROTOCOLS.map((p) => (
                  <option key={p.value} value={p.value}>{p.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Source / Destination — side-by-side 2-column grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
            {/* ── Source ────────────────────────────────────────────── */}
            <div className="bg-gray-900/60 border border-gray-700/60 rounded-lg p-4">
              <h4 className={sectionTitle}>Source</h4>
              <div className="space-y-3">
                <div>
                  <label className={labelClass}>Type</label>
                  <select
                    value={form.src_type}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        src_type: e.target.value as "any" | "address",
                        src_addr: e.target.value === "any" ? "" : f.src_addr,
                      }))
                    }
                    className={selectClass}
                  >
                    <option value="any">Any</option>
                    <option value="address">Address / Network</option>
                  </select>
                </div>
                {form.src_type === "address" && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="col-span-2">
                      <label className={labelClass}>IP Address</label>
                      <input
                        type="text"
                        value={form.src_addr}
                        onChange={(e) => setForm((f) => ({ ...f, src_addr: e.target.value }))}
                        placeholder="192.168.1.0"
                        className={inputClass}
                      />
                    </div>
                    <div>
                      <label className={labelClass}>Mask</label>
                      <select
                        value={form.src_mask}
                        onChange={(e) => setForm((f) => ({ ...f, src_mask: e.target.value }))}
                        className={selectClass}
                      >
                        {SUBNET_MASKS.map((m) => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-4">
                  <label className={checkboxLabel}>
                    <input
                      type="checkbox"
                      checked={form.src_invert}
                      onChange={(e) => setForm((f) => ({ ...f, src_invert: e.target.checked }))}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                    />
                    NOT (invert match)
                  </label>
                </div>
                {protocolShowsPorts(form.protocol) && (
                  <div>
                    <label className={labelClass}>Port / Range</label>
                    <input
                      type="text"
                      value={form.src_port}
                      onChange={(e) => setForm((f) => ({ ...f, src_port: e.target.value }))}
                      placeholder="e.g. 1024 or 1024-65535"
                      className={inputClass}
                    />
                  </div>
                )}
              </div>
            </div>

            {/* ── Destination ──────────────────────────────────────── */}
            <div className="bg-gray-900/60 border border-gray-700/60 rounded-lg p-4">
              <h4 className={sectionTitle}>Destination</h4>
              <div className="space-y-3">
                <div>
                  <label className={labelClass}>Type</label>
                  <select
                    value={form.dst_type}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        dst_type: e.target.value as "any" | "address",
                        dst_addr: e.target.value === "any" ? "" : f.dst_addr,
                      }))
                    }
                    className={selectClass}
                  >
                    <option value="any">Any</option>
                    <option value="address">Address / Network</option>
                  </select>
                </div>
                {form.dst_type === "address" && (
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="col-span-2">
                      <label className={labelClass}>IP Address</label>
                      <input
                        type="text"
                        value={form.dst_addr}
                        onChange={(e) => setForm((f) => ({ ...f, dst_addr: e.target.value }))}
                        placeholder="10.0.0.0"
                        className={inputClass}
                      />
                    </div>
                    <div>
                      <label className={labelClass}>Mask</label>
                      <select
                        value={form.dst_mask}
                        onChange={(e) => setForm((f) => ({ ...f, dst_mask: e.target.value }))}
                        className={selectClass}
                      >
                        {SUBNET_MASKS.map((m) => (
                          <option key={m} value={m}>{m}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-4">
                  <label className={checkboxLabel}>
                    <input
                      type="checkbox"
                      checked={form.dst_invert}
                      onChange={(e) => setForm((f) => ({ ...f, dst_invert: e.target.checked }))}
                      className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                    />
                    NOT (invert match)
                  </label>
                </div>
                {protocolShowsPorts(form.protocol) && (
                  <div>
                    <label className={labelClass}>Port / Range</label>
                    <input
                      type="text"
                      value={form.dst_port}
                      onChange={(e) => setForm((f) => ({ ...f, dst_port: e.target.value }))}
                      placeholder="e.g. 443 or 80-443"
                      className={inputClass}
                    />
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Row 3: Label, Description, Gateway, State, Schedule */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
            <div>
              <label className={labelClass}>Label</label>
              <input
                type="text"
                value={form.label}
                onChange={(e) => setForm((f) => ({ ...f, label: e.target.value }))}
                placeholder="Rule label"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Description</label>
              <input
                type="text"
                value={form.description}
                onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
                placeholder="Optional description"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Gateway</label>
              <input
                type="text"
                value={form.gateway}
                onChange={(e) => setForm((f) => ({ ...f, gateway: e.target.value }))}
                placeholder="Policy routing gateway"
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>State Type</label>
              <select
                value={form.state_tracking}
                onChange={(e) => setForm((f) => ({ ...f, state_tracking: e.target.value }))}
                className={selectClass}
              >
                {STATE_TYPES.map((s) => (
                  <option key={s.value} value={s.value}>{s.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className={labelClass}>Schedule</label>
              <select
                value={form.schedule_id}
                onChange={(e) => setForm((f) => ({ ...f, schedule_id: e.target.value }))}
                className={selectClass}
              >
                <option value="">None</option>
                {schedules.map((s) => (
                  <option key={s.id} value={s.id}>{s.name}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Log checkbox */}
          <div className="pt-2">
            <label className={checkboxLabel}>
              <input
                type="checkbox"
                checked={form.log}
                onChange={(e) => setForm((f) => ({ ...f, log: e.target.checked }))}
                className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
              />
              Log packets matching this rule
            </label>
          </div>
        </div>

        {/* Modal footer */}
        <div className="sticky bottom-0 bg-gray-800 border-t border-gray-700 px-6 py-4 flex items-center justify-end gap-3">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onSubmit}
            disabled={submitting}
            className="px-5 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
          >
            {submitting ? "Saving..." : editingId ? "Save Changes" : "Add Rule"}
          </button>
        </div>
      </div>
    </div>
  );
}
