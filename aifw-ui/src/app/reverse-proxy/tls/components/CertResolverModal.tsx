"use client";

import type { Dispatch, SetStateAction } from "react";
import { CertResolverForm, caServerPresets } from "@/lib/api/reverse-proxy/tls";

interface CertResolverModalProps {
  editingId: string | null;
  form: CertResolverForm;
  setForm: Dispatch<SetStateAction<CertResolverForm>>;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}

export function CertResolverModal({ editingId, form, setForm, submitting, onCancel, onSubmit }: CertResolverModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">
          {editingId ? "Edit Certificate Resolver" : "Add Certificate Resolver"}
        </h3>

        <div className="space-y-4">
          {/* Name */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="e.g. letsencrypt"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* ACME Section Header */}
          <h4 className="text-sm font-medium text-[var(--text-secondary)] pt-1">ACME</h4>

          {/* Email */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Email</label>
            <input
              type="text"
              value={form.email}
              onChange={(e) => setForm((p) => ({ ...p, email: e.target.value }))}
              placeholder="admin@example.com"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Storage */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Storage Path</label>
            <input
              type="text"
              value={form.storage}
              onChange={(e) => setForm((p) => ({ ...p, storage: e.target.value }))}
              placeholder="/usr/local/etc/trafficcop/acme.json"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* CA Server */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">CA Server</label>
            <select
              value={form.caServerPreset}
              onChange={(e) => setForm((p) => ({ ...p, caServerPreset: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              {Object.entries(caServerPresets).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </div>

          {/* Custom CA Server URL */}
          {form.caServerPreset === "custom" && (
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Custom CA Server URL</label>
              <input
                type="text"
                value={form.caServerCustom}
                onChange={(e) => setForm((p) => ({ ...p, caServerCustom: e.target.value }))}
                placeholder="https://acme.example.com/directory"
                className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          )}

          {/* Key Type */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Key Type</label>
            <select
              value={form.keyType}
              onChange={(e) => setForm((p) => ({ ...p, keyType: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="RSA2048">RSA2048</option>
              <option value="RSA4096">RSA4096</option>
              <option value="EC256">EC256</option>
              <option value="EC384">EC384</option>
            </select>
          </div>

          {/* Challenge Type */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Challenge Type</label>
            <select
              value={form.challengeType}
              onChange={(e) => setForm((p) => ({ ...p, challengeType: e.target.value }))}
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500"
            >
              <option value="HTTP-01">HTTP-01</option>
              <option value="TLS-ALPN-01">TLS-ALPN-01</option>
              <option value="DNS-01">DNS-01</option>
            </select>
          </div>

          {/* HTTP-01 fields */}
          {form.challengeType === "HTTP-01" && (
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Entry Point</label>
              <input
                type="text"
                value={form.httpEntryPoint}
                onChange={(e) => setForm((p) => ({ ...p, httpEntryPoint: e.target.value }))}
                placeholder="web"
                className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
              />
            </div>
          )}

          {/* DNS-01 fields */}
          {form.challengeType === "DNS-01" && (
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Provider</label>
                <input
                  type="text"
                  value={form.dnsProvider}
                  onChange={(e) => setForm((p) => ({ ...p, dnsProvider: e.target.value }))}
                  placeholder="e.g. cloudflare, route53"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">Resolvers (comma-separated)</label>
                <input
                  type="text"
                  value={form.dnsResolvers}
                  onChange={(e) => setForm((p) => ({ ...p, dnsResolvers: e.target.value }))}
                  placeholder="1.1.1.1:53, 8.8.8.8:53"
                  className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Disable Propagation Check</label>
                <button
                  type="button"
                  onClick={() =>
                    setForm((p) => ({
                      ...p,
                      dnsDisablePropagationCheck: !p.dnsDisablePropagationCheck,
                    }))
                  }
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    form.dnsDisablePropagationCheck ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      form.dnsDisablePropagationCheck ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>
          )}
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
