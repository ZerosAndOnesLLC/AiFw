"use client";

import { UpdateHistoryEntry } from "@/lib/api/updates";

const statusBadgeColor = (s: string) => {
  switch (s.toLowerCase()) {
    case "success":
    case "completed":
      return "bg-green-500/15 text-green-400 border-green-500/30";
    case "failed":
    case "error":
      return "bg-red-500/15 text-red-400 border-red-500/30";
    case "running":
    case "in_progress":
      return "bg-blue-500/15 text-blue-400 border-blue-500/30";
    default:
      return "bg-gray-500/15 text-gray-400 border-gray-500/30";
  }
};

interface UpdateHistoryCardProps {
  history: UpdateHistoryEntry[];
}

export function UpdateHistoryCard({ history }: UpdateHistoryCardProps) {
  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      <div className="p-4 border-b border-[var(--border)]">
        <h2 className="text-lg font-semibold">Update History</h2>
        <p className="text-xs text-[var(--text-muted)]">Last 50 update operations</p>
      </div>

      {history.length === 0 ? (
        <div className="p-8 text-center text-sm text-[var(--text-muted)]">No update history yet</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-[var(--text-muted)] uppercase tracking-wider border-b border-[var(--border)]">
                <th className="text-left px-4 py-3 font-medium">Action</th>
                <th className="text-left px-4 py-3 font-medium">Details</th>
                <th className="text-left px-4 py-3 font-medium">Status</th>
                <th className="text-left px-4 py-3 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {history.map((entry) => (
                <tr
                  key={entry.id}
                  className="border-b border-[var(--border)] last:border-b-0 hover:bg-[var(--bg-secondary)] transition-colors"
                >
                  <td className="px-4 py-3 text-[var(--text-primary)] font-medium whitespace-nowrap">
                    {entry.action}
                  </td>
                  <td className="px-4 py-3 text-[var(--text-secondary)] max-w-xs truncate">
                    {entry.details}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${statusBadgeColor(entry.status)}`}
                    >
                      {entry.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[var(--text-muted)] whitespace-nowrap text-xs">
                    {new Date(entry.created_at).toLocaleString()}
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
