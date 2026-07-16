"use client";

import { useState } from "react";
import { UpdateStatus } from "@/lib/api/updates";

interface PendingPackagesCardProps {
  status: UpdateStatus;
}

export function PendingPackagesCard({ status }: PendingPackagesCardProps) {
  const [pkgsExpanded, setPkgsExpanded] = useState(false);

  return (
    <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
      <button
        onClick={() => setPkgsExpanded(!pkgsExpanded)}
        className="w-full flex items-center justify-between p-4 text-left hover:bg-[var(--bg-secondary)] transition-colors rounded-lg"
      >
        <div className="flex items-center gap-2">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Pending Packages</h2>
          <span className="text-xs text-[var(--text-muted)]">({status.pending_pkg_count})</span>
        </div>
        <svg
          className={`w-4 h-4 text-[var(--text-muted)] transition-transform duration-200 ${pkgsExpanded ? "rotate-180" : ""}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      {pkgsExpanded && (
        <div className="px-4 pb-4 border-t border-[var(--border)]">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-1 pt-3">
            {status.pending_packages.map((pkg) => (
              <div
                key={pkg}
                className="text-xs text-[var(--text-secondary)] font-mono bg-[var(--bg-secondary)] rounded px-2 py-1"
              >
                {pkg}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
