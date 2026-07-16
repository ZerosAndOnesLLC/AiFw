"use client";

import { TlsOption, parseTlsOptionDisplay } from "@/lib/api/reverse-proxy/tls";

interface TlsOptionsSectionProps {
  tlsOptions: TlsOption[];
  onAdd: () => void;
  onEdit: (opt: TlsOption) => void;
  onDelete: (id: string) => void;
}

export function TlsOptionsSection({ tlsOptions, onAdd, onEdit, onDelete }: TlsOptionsSectionProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
        <h2 className="text-lg font-semibold">TLS Options</h2>
        <button
          onClick={onAdd}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add TLS Option
        </button>
      </div>
      {tlsOptions.length === 0 ? (
        <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
          No TLS options configured. Click &quot;Add TLS Option&quot; to create one.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                <th className="px-6 py-3">Name</th>
                <th className="px-6 py-3">Min Version</th>
                <th className="px-6 py-3">Max Version</th>
                <th className="px-6 py-3">SNI Strict</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {tlsOptions.map((opt) => {
                const display = parseTlsOptionDisplay(opt.config_json);
                return (
                  <tr key={opt.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => onEdit(opt)}>
                    <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{opt.name}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{display.minVersion}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{display.maxVersion}</td>
                    <td className="px-6 py-3">
                      {display.sniStrict ? (
                        <span className="text-xs px-2 py-0.5 rounded-full border bg-green-500/20 text-green-400 border-green-500/30">
                          Yes
                        </span>
                      ) : (
                        <span className="text-[var(--text-muted)]">-</span>
                      )}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => onDelete(opt.id)}
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
