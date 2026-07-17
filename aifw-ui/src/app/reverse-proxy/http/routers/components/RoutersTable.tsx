"use client";

import { type HttpRouter, parseJsonArray } from "@/lib/api/reverse-proxy/routers";

const chipCls =
  "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/15 text-blue-400 border border-blue-500/30";

interface RoutersTableProps {
  routers: HttpRouter[];
  deletingId: string | null;
  onEdit: (router: HttpRouter) => void;
  onDelete: (id: string) => void;
  onToggleEnabled: (router: HttpRouter) => void;
}

export function RoutersTable({ routers, deletingId, onEdit, onDelete, onToggleEnabled }: RoutersTableProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Name</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Rule</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Entry Points</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Service</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Middlewares</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-20">Priority</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-16">TLS</th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-20">Enabled</th>
              <th className="w-24"></th>
            </tr>
          </thead>
          <tbody>
            {routers.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-12 text-[var(--text-muted)]">
                  No HTTP routers configured
                </td>
              </tr>
            ) : (
              routers.map((router) => {
                const eps = parseJsonArray(router.entry_points);
                const mws = parseJsonArray(router.middlewares);
                const hasTls = !!router.tls_json;

                return (
                  <tr
                    key={router.id}
                    className="border-b border-[var(--border)] hover:bg-[var(--bg-secondary)] transition-colors cursor-pointer"
                    onClick={() => onEdit(router)}
                  >
                    {/* Name */}
                    <td className="py-2.5 px-3">
                      <span className="font-medium text-[var(--text-primary)]">{router.name}</span>
                    </td>
                    {/* Rule (truncated) */}
                    <td className="py-2.5 px-3 max-w-[260px]">
                      <span
                        className="font-mono text-xs text-[var(--text-secondary)] truncate block"
                        title={router.rule}
                      >
                        {router.rule.length > 60 ? router.rule.substring(0, 60) + "..." : router.rule}
                      </span>
                    </td>
                    {/* Entry Points */}
                    <td className="py-2.5 px-3">
                      <div className="flex flex-wrap gap-1">
                        {eps.map((ep) => (
                          <span key={ep} className={chipCls}>{ep}</span>
                        ))}
                        {eps.length === 0 && <span className="text-xs text-[var(--text-muted)]">-</span>}
                      </div>
                    </td>
                    {/* Service */}
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-[var(--text-secondary)]">{router.service || "-"}</span>
                    </td>
                    {/* Middlewares */}
                    <td className="py-2.5 px-3">
                      <div className="flex flex-wrap gap-1">
                        {mws.map((mw) => (
                          <span
                            key={mw}
                            className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30"
                          >
                            {mw}
                          </span>
                        ))}
                        {mws.length === 0 && <span className="text-xs text-[var(--text-muted)]">-</span>}
                      </div>
                    </td>
                    {/* Priority */}
                    <td className="py-2.5 px-3 text-center">
                      <span className="text-xs text-[var(--text-secondary)] font-mono">{router.priority}</span>
                    </td>
                    {/* TLS */}
                    <td className="py-2.5 px-3 text-center">
                      {hasTls ? (
                        <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/30">
                          TLS
                        </span>
                      ) : (
                        <span className="text-xs text-[var(--text-muted)]">-</span>
                      )}
                    </td>
                    {/* Enabled toggle */}
                    <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onToggleEnabled(router)}
                        className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none"
                        style={{
                          backgroundColor: router.enabled ? "#2563eb" : "#4b5563",
                        }}
                        title={router.enabled ? "Disable" : "Enable"}
                      >
                        <span
                          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                            router.enabled ? "translate-x-[18px]" : "translate-x-[3px]"
                          }`}
                        />
                      </button>
                    </td>
                    {/* Actions */}
                    <td className="py-2.5 px-2" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => onEdit(router)}
                          className="text-[var(--text-muted)] hover:text-blue-400 transition-colors p-1"
                          title="Edit"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                          </svg>
                        </button>
                        <button
                          onClick={() => onDelete(router.id)}
                          disabled={deletingId === router.id}
                          className="text-[var(--text-muted)] hover:text-red-400 transition-colors p-1 disabled:opacity-50"
                          title="Delete"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
