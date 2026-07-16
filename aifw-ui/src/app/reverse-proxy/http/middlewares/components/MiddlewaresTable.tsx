"use client";

import { HttpMiddleware, fmtDate } from "@/lib/api/reverse-proxy/middlewares";
import { TypeBadge } from "./TypeBadge";

/* ── Middlewares table ────────────────────────────────────────── */

export function MiddlewaresTable({
  middlewares,
  deletingId,
  onEdit,
  onDelete,
  onToggleEnabled,
}: {
  middlewares: HttpMiddleware[];
  deletingId: string | null;
  onEdit: (mw: HttpMiddleware) => void;
  onDelete: (mw: HttpMiddleware) => void;
  onToggleEnabled: (mw: HttpMiddleware) => void;
}) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-[var(--border)]">
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                Name
              </th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                Type
              </th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                Enabled
              </th>
              <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                Created
              </th>
              <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            {middlewares.length === 0 ? (
              <tr>
                <td colSpan={5} className="text-center py-12 text-[var(--text-muted)]">
                  No HTTP middlewares configured
                </td>
              </tr>
            ) : (
              middlewares.map((mw) => (
                <tr
                  key={mw.id}
                  className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
                  onClick={() => onEdit(mw)}
                >
                  <td className="py-2.5 px-3 font-medium text-[var(--text-primary)]">
                    {mw.name}
                  </td>
                  <td className="py-2.5 px-3">
                    <TypeBadge mtype={mw.middleware_type} />
                  </td>
                  <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => onToggleEnabled(mw)}
                      className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none"
                      style={{
                        backgroundColor: mw.enabled ? "#22c55e" : "#4b5563",
                      }}
                      title={mw.enabled ? "Disable" : "Enable"}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                          mw.enabled ? "translate-x-[18px]" : "translate-x-[3px]"
                        }`}
                      />
                    </button>
                  </td>
                  <td className="py-2.5 px-3 text-xs text-[var(--text-muted)]">
                    {fmtDate(mw.created_at)}
                  </td>
                  <td className="py-2.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onEdit(mw)}
                        className="text-[var(--text-muted)] hover:text-blue-400 transition-colors p-1"
                        title="Edit"
                      >
                        <svg
                          className="w-4 h-4"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                          strokeWidth={1.5}
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"
                          />
                        </svg>
                      </button>
                      <button
                        onClick={() => onDelete(mw)}
                        disabled={deletingId === mw.id}
                        className="text-[var(--text-muted)] hover:text-red-400 disabled:opacity-40 transition-colors p-1"
                        title="Delete"
                      >
                        {deletingId === mw.id ? (
                          <span className="text-xs">...</span>
                        ) : (
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                            strokeWidth={1.5}
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                            />
                          </svg>
                        )}
                      </button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
