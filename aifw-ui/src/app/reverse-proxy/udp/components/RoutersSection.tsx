"use client";

import type { UdpRouter } from "@/lib/api/reverse-proxy/udp";

interface RoutersSectionProps {
  routers: UdpRouter[];
  onAdd: () => void;
  onEdit: (router: UdpRouter) => void;
  onDelete: (id: string) => void;
}

export function RoutersSection({ routers, onAdd, onEdit, onDelete }: RoutersSectionProps) {
  return (
    <section>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold">UDP Routers</h2>
          <p className="text-xs text-[var(--text-muted)]">{routers.length} router{routers.length !== 1 ? "s" : ""}</p>
        </div>
        <button
          onClick={onAdd}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Router
        </button>
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {routers.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No UDP routers configured
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Rule</th>
                  <th className="px-6 py-3">Service</th>
                  <th className="px-6 py-3">Entry Points</th>
                  <th className="px-6 py-3">Priority</th>
                  <th className="px-6 py-3">Enabled</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {routers.map((r) => (
                  <tr key={r.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => onEdit(r)}>
                    <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{r.name}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs max-w-[200px] truncate">
                      {r.rule || "-"}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{r.service || "-"}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{r.entry_points || "-"}</td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] text-xs">{r.priority}</td>
                    <td className="px-6 py-3">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full border ${
                          r.enabled
                            ? "bg-green-500/20 text-green-400 border-green-500/30"
                            : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                        }`}
                      >
                        {r.enabled ? "Active" : "Disabled"}
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
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
