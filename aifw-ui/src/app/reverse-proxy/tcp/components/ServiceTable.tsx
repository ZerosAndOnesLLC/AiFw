"use client";

import { TcpService } from "@/lib/api/reverse-proxy/tcp";

interface ServiceTableProps {
  services: TcpService[];
  onAdd: () => void;
  onEdit: (service: TcpService) => void;
  onDelete: (id: string) => void;
}

export function ServiceTable({ services, onAdd, onEdit, onDelete }: ServiceTableProps) {
  return (
    <section>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-lg font-semibold">TCP Services</h2>
          <p className="text-xs text-[var(--text-muted)]">{services.length} service{services.length !== 1 ? "s" : ""}</p>
        </div>
        <button
          onClick={onAdd}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Service
        </button>
      </div>

      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {services.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No TCP services configured
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Name</th>
                  <th className="px-6 py-3">Type</th>
                  <th className="px-6 py-3">Servers / Refs</th>
                  <th className="px-6 py-3">Enabled</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {services.map((s) => {
                  let detail = "-";
                  try {
                    const cfg = JSON.parse(s.config_json || "{}");
                    if (s.service_type === "weighted" && cfg.weighted?.services) {
                      detail = cfg.weighted.services.map((r: { name: string }) => r.name).join(", ");
                    } else if (cfg.servers) {
                      detail = cfg.servers.map((sv: { address: string }) => sv.address).join(", ");
                    }
                  } catch {
                    /* ignore */
                  }
                  return (
                    <tr key={s.id} className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer" onClick={() => onEdit(s)}>
                      <td className="px-6 py-3 text-[var(--text-primary)] font-medium">{s.name}</td>
                      <td className="px-6 py-3">
                        <span className="text-xs px-2 py-0.5 rounded-full border bg-purple-500/20 text-purple-400 border-purple-500/30">
                          {s.service_type}
                        </span>
                      </td>
                      <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs max-w-[300px] truncate">
                        {detail}
                      </td>
                      <td className="px-6 py-3">
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full border ${
                            s.enabled
                              ? "bg-green-500/20 text-green-400 border-green-500/30"
                              : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                          }`}
                        >
                          {s.enabled ? "Active" : "Disabled"}
                        </span>
                      </td>
                      <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => onDelete(s.id)}
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
    </section>
  );
}
