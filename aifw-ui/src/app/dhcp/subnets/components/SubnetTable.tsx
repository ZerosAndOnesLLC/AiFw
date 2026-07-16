"use client";

import { type DhcpSubnet, fmtDate, fmtSeconds } from "@/lib/api/dhcp-subnets";

export interface SubnetTableProps {
  subnets: DhcpSubnet[];
  /** Row click — opens the edit modal. */
  onEdit: (subnet: DhcpSubnet) => void;
  /** Trash button — opens the delete confirm dialog. */
  onDelete: (id: string) => void;
}

export function SubnetTable({ subnets, onEdit, onDelete }: SubnetTableProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      {subnets.length === 0 ? (
        <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
          No subnets configured. Click &quot;Add Subnet&quot; to create one.
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                <th className="px-6 py-3">Network</th>
                <th className="px-6 py-3">Type</th>
                <th className="px-6 py-3">Pool Range</th>
                <th className="px-6 py-3">Gateway</th>
                <th className="px-6 py-3">Lease Time</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">Created</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {subnets.map((subnet) => (
                <tr
                  key={subnet.id}
                  className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer"
                  onClick={() => onEdit(subnet)}
                >
                  <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                    {subnet.network}
                  </td>
                  <td className="px-6 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full border ${
                      subnet.subnet_type === "prefix-delegation"
                        ? "bg-purple-500/20 text-purple-400 border-purple-500/30"
                        : subnet.network.includes(":")
                          ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/30"
                          : "bg-blue-500/20 text-blue-400 border-blue-500/30"
                    }`}>
                      {subnet.subnet_type === "prefix-delegation" ? "PD" : subnet.network.includes(":") ? "v6" : "v4"}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                    {subnet.subnet_type === "prefix-delegation"
                      ? `/${subnet.delegated_length || "?"}`
                      : `${subnet.pool_start} - ${subnet.pool_end}`}
                  </td>
                  <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                    {subnet.gateway}
                  </td>
                  <td className="px-6 py-3 text-[var(--text-secondary)]">
                    {subnet.lease_time ? fmtSeconds(subnet.lease_time) : "Default"}
                    {subnet.renewal_time && <span className="text-[10px] text-gray-500 ml-1">(T1:{fmtSeconds(subnet.renewal_time)})</span>}
                  </td>
                  <td className="px-6 py-3">
                    <span
                      className={`text-xs px-2 py-0.5 rounded-full border ${
                        subnet.enabled
                          ? "bg-green-500/20 text-green-400 border-green-500/30"
                          : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                      }`}
                    >
                      {subnet.enabled ? "Enabled" : "Disabled"}
                    </span>
                  </td>
                  <td className="px-6 py-3 text-[var(--text-secondary)]">
                    {fmtDate(subnet.created_at)}
                  </td>
                  <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={() => onDelete(subnet.id)}
                        title="Delete Subnet"
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
