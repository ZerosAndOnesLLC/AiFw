"use client";

import type { Dispatch, SetStateAction } from "react";
import { ServiceForm, ServerEntry } from "@/lib/api/reverse-proxy/tcp";
import { inputCls, selectCls, labelCls } from "./formStyles";

interface ServiceModalProps {
  editingServiceId: string | null;
  form: ServiceForm;
  setForm: Dispatch<SetStateAction<ServiceForm>>;
  submitting: boolean;
  onClose: () => void;
  onSubmit: () => void;
  addServer: () => void;
  removeServer: (idx: number) => void;
  updateServer: (idx: number, field: keyof ServerEntry, value: string | boolean) => void;
  addWeightedRef: () => void;
  removeWeightedRef: (idx: number) => void;
  updateWeightedRef: (idx: number, field: "name" | "weight", value: string) => void;
}

export function ServiceModal({
  editingServiceId,
  form,
  setForm,
  submitting,
  onClose,
  onSubmit,
  addServer,
  removeServer,
  updateServer,
  addWeightedRef,
  removeWeightedRef,
  updateWeightedRef,
}: ServiceModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-2xl w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">
          {editingServiceId ? "Edit TCP Service" : "Add TCP Service"}
        </h3>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className={labelCls}>Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="e.g. db-backend"
              className={inputCls}
            />
          </div>

          {/* Service Type */}
          <div>
            <label className={labelCls}>Service Type</label>
            <select
              value={form.service_type}
              onChange={(e) => setForm((p) => ({ ...p, service_type: e.target.value }))}
              className={selectCls}
            >
              <option value="loadBalancer">loadBalancer</option>
              <option value="weighted">weighted</option>
            </select>
          </div>

          {/* loadBalancer fields */}
          {form.service_type === "loadBalancer" && (
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
                  {form.servers.map((srv, idx) => (
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
                      <button
                        type="button"
                        onClick={() => updateServer(idx, "tls", !srv.tls)}
                        title={srv.tls ? "TLS enabled" : "TLS disabled"}
                        className={`px-2 py-2 text-xs rounded-md border transition-colors ${
                          srv.tls
                            ? "bg-blue-500/20 border-blue-500/30 text-blue-400"
                            : "bg-[var(--bg-secondary)] border-[var(--border)] text-[var(--text-muted)]"
                        }`}
                      >
                        TLS
                      </button>
                      {form.servers.length > 1 && (
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
                <div className="px-4 pb-4 grid grid-cols-2 gap-3">
                  <div>
                    <label className={labelCls}>Interval</label>
                    <input
                      type="text"
                      value={form.healthCheckInterval}
                      onChange={(e) => setForm((p) => ({ ...p, healthCheckInterval: e.target.value }))}
                      placeholder="e.g. 10s"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Timeout</label>
                    <input
                      type="text"
                      value={form.healthCheckTimeout}
                      onChange={(e) => setForm((p) => ({ ...p, healthCheckTimeout: e.target.value }))}
                      placeholder="e.g. 5s"
                      className={inputCls}
                    />
                  </div>
                </div>
              </div>

              {/* Proxy Protocol */}
              <div>
                <label className={labelCls}>Proxy Protocol Version</label>
                <select
                  value={form.proxyProtocol}
                  onChange={(e) => setForm((p) => ({ ...p, proxyProtocol: e.target.value }))}
                  className={selectCls}
                >
                  <option value="none">None</option>
                  <option value="1">Version 1</option>
                  <option value="2">Version 2</option>
                </select>
              </div>
            </>
          )}

          {/* weighted fields */}
          {form.service_type === "weighted" && (
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
                {form.weightedRefs.map((ref, idx) => (
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
                    {form.weightedRefs.length > 1 && (
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
            onClick={onClose}
            className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-[var(--text-primary)]"
          >
            Cancel
          </button>
          <button
            onClick={onSubmit}
            disabled={submitting}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 transition-colors"
          >
            {submitting ? "Saving..." : editingServiceId ? "Update" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
