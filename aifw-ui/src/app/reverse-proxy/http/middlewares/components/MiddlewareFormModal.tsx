"use client";

import { useState } from "react";
import {
  HttpMiddleware,
  HttpMiddlewareBody,
  MIDDLEWARE_CATEGORIES,
  defaultConfigForType,
} from "@/lib/api/reverse-proxy/middlewares";
import { Toggle } from "./Toggle";
import { MiddlewareTypeForm } from "./MiddlewareTypeForm";

/* ── Create / Edit Modal ──────────────────────────────────────── */

/// Owns the form field state. Mounted fresh on every open (the page
/// renders it conditionally), so state initializers replace the old
/// openCreate/openEdit reset logic.
export function MiddlewareFormModal({
  editing,
  submitting,
  onClose,
  onSubmit,
}: {
  editing: HttpMiddleware | null;
  submitting: boolean;
  onClose: () => void;
  onSubmit: (body: HttpMiddlewareBody) => void;
}) {
  // Form state
  const [formName, setFormName] = useState(editing ? editing.name : "");
  const [formType, setFormType] = useState(editing ? editing.middleware_type : "rateLimit");
  const [formConfig, setFormConfig] = useState<any>(() => {
    if (editing) {
      try {
        return JSON.parse(editing.config_json);
      } catch {
        return defaultConfigForType(editing.middleware_type);
      }
    }
    return defaultConfigForType("rateLimit");
  });
  const [formEnabled, setFormEnabled] = useState(editing ? editing.enabled : true);

  function handleTypeChange(newType: string) {
    setFormType(newType);
    setFormConfig(defaultConfigForType(newType));
  }

  /* ── Config update helper ──────────────────────────────────── */

  function updateConfig(key: string, value: any) {
    setFormConfig((prev: any) => ({ ...prev, [key]: value }));
  }

  function handleSubmit() {
    if (!formName.trim()) return;
    onSubmit({
      name: formName.trim(),
      middleware_type: formType,
      config_json: JSON.stringify(formConfig),
      enabled: formEnabled,
    });
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-lg mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        {/* Modal header */}
        <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between flex-shrink-0">
          <h2 className="text-lg font-semibold text-white">
            {editing ? "Edit Middleware" : "Add Middleware"}
          </h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white transition-colors"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Modal body (scrollable) */}
        <div className="p-6 space-y-4 overflow-y-auto flex-1">
          {/* Name */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Name *</label>
            <input
              type="text"
              value={formName}
              onChange={(e) => setFormName(e.target.value)}
              placeholder="my-middleware"
              className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Middleware Type */}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Middleware Type</label>
            <select
              value={formType}
              onChange={(e) => handleTypeChange(e.target.value)}
              disabled={!!editing}
              className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 disabled:opacity-60"
            >
              {Object.entries(MIDDLEWARE_CATEGORIES).map(([cat, info]) => (
                <optgroup key={cat} label={info.label}>
                  {info.types.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </optgroup>
              ))}
            </select>
          </div>

          {/* Type-specific config */}
          <div className="border-t border-gray-700 pt-4">
            <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider mb-3">
              Configuration
            </h3>
            <MiddlewareTypeForm
              formType={formType}
              formConfig={formConfig}
              updateConfig={updateConfig}
              setFormConfig={setFormConfig}
            />
          </div>

          {/* Enabled toggle */}
          <div className="border-t border-gray-700 pt-4">
            <Toggle
              label="Enabled"
              checked={formEnabled}
              onChange={setFormEnabled}
            />
          </div>
        </div>

        {/* Modal footer */}
        <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-end gap-2 flex-shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium rounded-md bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !formName.trim()}
            className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
          >
            {submitting ? "Saving..." : editing ? "Update" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
