"use client";

import { TlsCert } from "@/lib/api/reverse-proxy/tls";

interface TlsCertsSectionProps {
  certs: TlsCert[];
  onAdd: () => void;
  onEdit: (cert: TlsCert) => void;
  onDelete: (id: string) => void;
}

export function TlsCertsSection({ certs, onAdd, onEdit, onDelete }: TlsCertsSectionProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
        <h2 className="text-lg font-semibold">TLS Certificates</h2>
        <button
          onClick={onAdd}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Certificate
        </button>
      </div>
      {certs.length === 0 ? (
        <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
          No TLS certificates configured. Click &quot;Add Certificate&quot; to create one.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                <th className="px-6 py-3">Name</th>
                <th className="px-6 py-3">Cert File</th>
                <th className="px-6 py-3">Key File</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {certs.map((cert) => (
                <tr key={cert.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => onEdit(cert)}>
                  <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{cert.name}</td>
                  <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">{cert.cert_file}</td>
                  <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">{cert.key_file}</td>
                  <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onDelete(cert.id)}
                        title="Delete"
                        className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                        </svg>
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
