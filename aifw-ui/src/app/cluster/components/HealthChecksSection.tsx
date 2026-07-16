"use client";

import { useState } from "react";
import {
  type HcFormState,
  type HealthCheck,
  defaultHcForm,
} from "@/lib/api/cluster";
import { ConfirmDialog } from "./ConfirmDialog";
import { FormCard } from "./FormCard";
import { PencilIcon } from "./PencilIcon";
import { SectionHeader } from "./SectionHeader";
import { TrashIcon } from "./TrashIcon";
import { btnDanger, btnEdit, inputCls, labelCls, selectCls } from "./styles";

// ============================================================
// Health checks
// ============================================================

export function HealthChecksSection({
  healthChecks,
  saving,
  onSave,
  onDelete,
}: {
  healthChecks: HealthCheck[];
  saving: boolean;
  /// `onSaved` is invoked only when the save succeeded (before reload).
  onSave: (
    form: HcFormState,
    editingHcId: string | null,
    onSaved: () => void
  ) => void;
  /// `onDeleted` is invoked only when the delete succeeded (before reload).
  onDelete: (h: HealthCheck, onDeleted: () => void) => void;
}) {
  const [showHcForm, setShowHcForm] = useState(false);
  const [hcForm, setHcForm] = useState<HcFormState>(defaultHcForm);
  const [editingHcId, setEditingHcId] = useState<string | null>(null);
  const [deleteHcConfirm, setDeleteHcConfirm] = useState<HealthCheck | null>(
    null
  );

  const openAddHc = () => {
    setHcForm(defaultHcForm);
    setEditingHcId(null);
    setShowHcForm(true);
  };

  const openEditHc = (h: HealthCheck) => {
    setHcForm({
      name: h.name,
      check_type: h.check_type,
      target: h.target,
      interval_secs: String(h.interval_secs),
      timeout_secs: String(h.timeout_secs),
      failures_before_down: String(h.failures_before_down),
      enabled: h.enabled,
    });
    setEditingHcId(h.id);
    setShowHcForm(true);
  };

  return (
    <section>
      {deleteHcConfirm && (
        <ConfirmDialog
          message={`Delete health check "${deleteHcConfirm.name}"?`}
          onConfirm={() =>
            onDelete(deleteHcConfirm, () => setDeleteHcConfirm(null))
          }
          onCancel={() => setDeleteHcConfirm(null)}
        />
      )}

      <SectionHeader
        title="Health Checks"
        onAdd={openAddHc}
        addLabel="Add Check"
      />

      {showHcForm && (
        <FormCard
          title={editingHcId ? "Edit Health Check" : "New Health Check"}
          onCancel={() => setShowHcForm(false)}
          onSave={() => onSave(hcForm, editingHcId, () => setShowHcForm(false))}
          saving={saving}
        >
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            <div>
              <label className={labelCls}>Name</label>
              <input
                type="text"
                value={hcForm.name}
                onChange={(e) =>
                  setHcForm((f) => ({ ...f, name: e.target.value }))
                }
                placeholder="e.g. wan-ping"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Check Type</label>
              <select
                value={hcForm.check_type}
                onChange={(e) =>
                  setHcForm((f) => ({ ...f, check_type: e.target.value }))
                }
                className={selectCls}
              >
                <option value="ping">Ping (ICMP)</option>
                <option value="tcp_port">TCP Port</option>
                <option value="http_get">HTTP GET (2xx)</option>
                <option value="pf_status">pf Status</option>
                <option value="process_running">Process Running</option>
              </select>
            </div>
            <div>
              <label className={labelCls}>
                Target{" "}
                <span className="text-gray-500">
                  (IP, host:port, URL, or process name)
                </span>
              </label>
              <input
                type="text"
                value={hcForm.target}
                onChange={(e) =>
                  setHcForm((f) => ({ ...f, target: e.target.value }))
                }
                placeholder={
                  hcForm.check_type === "ping"
                    ? "8.8.8.8"
                    : hcForm.check_type === "tcp_port"
                      ? "10.0.0.1:22"
                      : hcForm.check_type === "http_get"
                        ? "http://10.0.0.1/health"
                        : hcForm.check_type === "process_running"
                          ? "rdhcpd"
                          : ""
                }
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Interval (secs)</label>
              <input
                type="number"
                value={hcForm.interval_secs}
                onChange={(e) =>
                  setHcForm((f) => ({ ...f, interval_secs: e.target.value }))
                }
                placeholder="10"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Timeout (secs)</label>
              <input
                type="number"
                value={hcForm.timeout_secs}
                onChange={(e) =>
                  setHcForm((f) => ({ ...f, timeout_secs: e.target.value }))
                }
                placeholder="5"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Failures before down</label>
              <input
                type="number"
                value={hcForm.failures_before_down}
                onChange={(e) =>
                  setHcForm((f) => ({
                    ...f,
                    failures_before_down: e.target.value,
                  }))
                }
                placeholder="3"
                className={inputCls}
              />
            </div>
            <div className="flex items-end pb-0.5">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={hcForm.enabled}
                  onChange={(e) =>
                    setHcForm((f) => ({ ...f, enabled: e.target.checked }))
                  }
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Enabled</span>
              </label>
            </div>
          </div>
        </FormCard>
      )}

      {healthChecks.length === 0 && !showHcForm ? (
        <div className="text-sm text-[var(--text-muted)]">
          No health checks configured.
        </div>
      ) : healthChecks.length > 0 ? (
        <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Name
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Type
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Target
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Interval
                </th>
                <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                  Status
                </th>
                <th className="w-20"></th>
              </tr>
            </thead>
            <tbody>
              {healthChecks.map((h) => (
                <tr
                  key={h.id}
                  className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                >
                  <td className="py-2.5 px-4 font-mono">{h.name}</td>
                  <td className="py-2.5 px-4">{h.check_type}</td>
                  <td className="py-2.5 px-4 font-mono text-xs">
                    {h.target || "—"}
                  </td>
                  <td className="py-2.5 px-4">{h.interval_secs}s</td>
                  <td className="py-2.5 px-4">
                    <span
                      className={
                        h.enabled
                          ? "text-green-400 text-xs"
                          : "text-gray-500 text-xs"
                      }
                    >
                      {h.enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                  <td className="py-2.5 px-2">
                    <div className="flex items-center gap-1">
                      <button
                        onClick={() => openEditHc(h)}
                        className={btnEdit}
                        title="Edit"
                      >
                        <PencilIcon />
                      </button>
                      <button
                        onClick={() => setDeleteHcConfirm(h)}
                        className={btnDanger}
                        title="Delete"
                      >
                        <TrashIcon />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </section>
  );
}
