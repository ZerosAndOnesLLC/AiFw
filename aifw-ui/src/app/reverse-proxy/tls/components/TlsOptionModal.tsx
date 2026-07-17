"use client";

import type { Dispatch, SetStateAction } from "react";
import { TlsOptionForm, tlsVersions, clientAuthTypes } from "@/lib/api/reverse-proxy/tls";

interface TlsOptionModalProps {
  editingId: string | null;
  form: TlsOptionForm;
  setForm: Dispatch<SetStateAction<TlsOptionForm>>;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}

export function TlsOptionModal({ editingId, form, setForm, submitting, onCancel, onSubmit }: TlsOptionModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">
          {editingId ? "Edit TLS Option" : "Add TLS Option"}
        </h3>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="e.g. modern, intermediate"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Min Version */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Min Version</label>
            <select
              value={form.minVersion}
              onChange={(e) => setForm((p) => ({ ...p, minVersion: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              {tlsVersions.map((v) => (
                <option key={v} value={v}>
                  {v || "(none)"}
                </option>
              ))}
            </select>
          </div>

          {/* Max Version */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Max Version</label>
            <select
              value={form.maxVersion}
              onChange={(e) => setForm((p) => ({ ...p, maxVersion: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              {tlsVersions.map((v) => (
                <option key={v} value={v}>
                  {v || "(none)"}
                </option>
              ))}
            </select>
          </div>

          {/* Cipher Suites */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Cipher Suites (one per line)</label>
            <textarea
              value={form.cipherSuites}
              onChange={(e) => setForm((p) => ({ ...p, cipherSuites: e.target.value }))}
              rows={4}
              placeholder={"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\nTLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>

          {/* SNI Strict */}
          <div className="flex items-center justify-between">
            <label className="text-sm text-[var(--text-secondary)]">SNI Strict</label>
            <button
              type="button"
              onClick={() => setForm((p) => ({ ...p, sniStrict: !p.sniStrict }))}
              className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                form.sniStrict ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                  form.sniStrict ? "translate-x-6" : "translate-x-1"
                }`}
              />
            </button>
          </div>

          {/* Client Auth Type */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Client Auth Type</label>
            <select
              value={form.clientAuthType}
              onChange={(e) => setForm((p) => ({ ...p, clientAuthType: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              {clientAuthTypes.map((v) => (
                <option key={v} value={v}>
                  {v || "(none)"}
                </option>
              ))}
            </select>
          </div>

          {/* Client Auth CA Files */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Client Auth CA Files (one path per line)</label>
            <textarea
              value={form.clientAuthCaFiles}
              onChange={(e) => setForm((p) => ({ ...p, clientAuthCaFiles: e.target.value }))}
              rows={3}
              placeholder={"/path/to/ca1.pem\n/path/to/ca2.pem"}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 font-mono"
            />
          </div>

          {/* ALPN Protocols */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">ALPN Protocols (comma-separated)</label>
            <input
              type="text"
              value={form.alpnProtocols}
              onChange={(e) => setForm((p) => ({ ...p, alpnProtocols: e.target.value }))}
              placeholder="h2, http/1.1"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
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
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
          >
            {submitting ? "Saving..." : editingId ? "Update" : "Create"}
          </button>
        </div>
      </div>
    </div>
  );
}
