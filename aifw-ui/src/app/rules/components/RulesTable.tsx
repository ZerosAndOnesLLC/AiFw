"use client";

import type { Rule } from "@/lib/api/rules";
import { actionLabel, formatAddrPort, ipVersionLabel } from "@/lib/api/rules";
import StatusBadge from "@/components/StatusBadge";

/* ─── Reusable rules table section ──────────────────────────────── */

export function RulesTable({
  title,
  icon,
  sectionRules,
  allRules,
  onMove,
  onToggleStatus,
  onEdit,
  onClone,
  onDelete,
  getScheduleName,
}: {
  title: string;
  icon: React.ReactNode;
  sectionRules: Rule[];
  allRules: Rule[];
  onMove: (id: string, dir: "up" | "down") => void;
  onToggleStatus: (rule: Rule) => void;
  onEdit: (rule: Rule) => void;
  onClone: (rule: Rule) => void;
  onDelete: (id: string) => void;
  getScheduleName: (id?: string) => string | null;
}) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-700 flex items-center gap-2">
        {icon}
        <h3 className="text-sm font-semibold text-white">{title}</h3>
        <span className="text-xs text-gray-500 ml-1">({sectionRules.length})</span>
      </div>
      {sectionRules.length === 0 ? (
        <div className="text-center py-8 text-gray-500 text-sm">No {title.toLowerCase()}</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 bg-gray-800/80">
                <th className="w-6"></th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">On</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-16">#</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Action</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">IP Ver</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-24">Interface</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-20">Proto</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Source</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Destination</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Schedule</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider">Label</th>
                <th className="text-right py-3 px-3 text-xs font-medium text-gray-400 uppercase tracking-wider w-28">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sectionRules.map((rule) => {
                const globalIdx = allRules.findIndex(r => r.id === rule.id);
                return (
                  <tr
                    key={rule.id}
                    onClick={() => onEdit(rule)}
                    className={`border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors cursor-pointer ${
                      rule.status === "disabled" ? "opacity-50" : ""
                    }`}
                  >
                    <td className="py-1 px-1 w-8" onClick={e => e.stopPropagation()}>
                      <div className="flex flex-col items-center gap-0">
                        <button onClick={() => onMove(rule.id, "up")} disabled={globalIdx === 0}
                          className="text-gray-600 hover:text-white disabled:opacity-20 disabled:cursor-default p-0.5" title="Move up">
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 15l7-7 7 7" /></svg>
                        </button>
                        <span className="text-[9px] text-gray-600">{globalIdx + 1}</span>
                        <button onClick={() => onMove(rule.id, "down")} disabled={globalIdx === allRules.length - 1}
                          className="text-gray-600 hover:text-white disabled:opacity-20 disabled:cursor-default p-0.5" title="Move down">
                          <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" /></svg>
                        </button>
                      </div>
                    </td>
                    <td className="py-2.5 px-3" onClick={e => e.stopPropagation()}>
                      <button
                        onClick={() => onToggleStatus(rule)}
                        className="relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none"
                        style={{ backgroundColor: rule.status === "active" ? "#22c55e" : "#4b5563" }}
                        title={rule.status === "active" ? "Disable rule" : "Enable rule"}
                      >
                        <span
                          className="pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out"
                          style={{ transform: rule.status === "active" ? "translateX(16px)" : "translateX(0)" }}
                        />
                      </button>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-gray-300">{rule.priority}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <StatusBadge status={actionLabel(rule.action)} />
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{ipVersionLabel(rule.ip_version)}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-400">{rule.interface || "*"}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-400 uppercase">{rule.protocol}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-300">
                        {formatAddrPort(rule.rule_match.src_addr, rule.rule_match.src_port, rule.rule_match.src_invert)}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="font-mono text-xs text-gray-300">
                        {formatAddrPort(rule.rule_match.dst_addr, rule.rule_match.dst_port, rule.rule_match.dst_invert)}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{getScheduleName(rule.schedule_id) || "-"}</span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="text-xs text-gray-400">{rule.label || "-"}</span>
                    </td>
                    <td className="py-2.5 px-3" onClick={e => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => onClone(rule)}
                          className="p-1.5 text-gray-400 hover:text-purple-400 transition-colors rounded hover:bg-gray-700"
                          title="Clone rule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" />
                          </svg>
                        </button>
                        <button
                          onClick={() => onEdit(rule)}
                          className="p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700"
                          title="Edit rule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                          </svg>
                        </button>
                        <button
                          onClick={() => onDelete(rule.id)}
                          className="p-1.5 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700"
                          title="Delete rule"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
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
