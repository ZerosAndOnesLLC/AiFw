"use client";

import type { Dispatch, SetStateAction } from "react";
import { TlsCertForm } from "@/lib/api/reverse-proxy/tls";

interface TlsCertModalProps {
  editingId: string | null;
  form: TlsCertForm;
  setForm: Dispatch<SetStateAction<TlsCertForm>>;
  submitting: boolean;
  onCancel: () => void;
  onSubmit: () => void;
}

export function TlsCertModal({ editingId, form, setForm, submitting, onCancel, onSubmit }: TlsCertModalProps) {
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6 max-w-lg w-full mx-4 space-y-4 max-h-[90vh] overflow-y-auto">
        <h3 className="text-lg font-semibold text-[var(--text-primary)]">
          {editingId ? "Edit Certificate" : "Add Certificate"}
        </h3>

        <div className="space-y-4">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm((p) => ({ ...p, name: e.target.value }))}
              placeholder="e.g. my-cert"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Cert File</label>
            <input
              type="text"
              value={form.certFile}
              onChange={(e) => setForm((p) => ({ ...p, certFile: e.target.value }))}
              placeholder="/path/to/cert.pem"
              className="w-full px-3 py-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Key File</label>
            <input
              type="text"
              value={form.keyFile}
              onChange={(e) => setForm((p) => ({ ...p, keyFile: e.target.value }))}
              placeholder="/path/to/key.pem"
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
