"use client";

import { CertResolver, parseCertResolverDisplay } from "@/lib/api/reverse-proxy/tls";

interface CertResolversSectionProps {
  resolvers: CertResolver[];
  onAdd: () => void;
  onEdit: (r: CertResolver) => void;
  onDelete: (id: string) => void;
}

export function CertResolversSection({ resolvers, onAdd, onEdit, onDelete }: CertResolversSectionProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
        <h2 className="text-lg font-semibold">Certificate Resolvers</h2>
        <button
          onClick={onAdd}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Resolver
        </button>
      </div>
      {resolvers.length === 0 ? (
        <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
          No certificate resolvers configured. Click &quot;Add Resolver&quot; to create one.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                <th className="px-6 py-3">Name</th>
                <th className="px-6 py-3">Email</th>
                <th className="px-6 py-3">Challenge Type</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {resolvers.map((r) => {
                const display = parseCertResolverDisplay(r.config_json);
                return (
                  <tr key={r.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => onEdit(r)}>
                    <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{r.name}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{display.email}</td>
                    <td className="px-6 py-3">
                      <span className="text-xs px-2 py-0.5 rounded-full border bg-blue-500/20 text-blue-400 border-blue-500/30">
                        {display.challengeType}
                      </span>
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => onDelete(r.id)}
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
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
