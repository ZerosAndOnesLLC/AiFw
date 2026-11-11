"use client";

import { useCallback, useState } from "react";
import { usePolling } from "@/lib/usePolling";
import { getClusterStatus, type ClusterStatus } from "@/lib/api/cluster";

const ROLE_LABEL: Record<string, string> = {
  primary: "MASTER",
  secondary: "BACKUP",
  split: "SPLIT",
  init: "INITIALISING",
  standalone: "STANDALONE",
};

export default function StatusBanner() {
  const [s, setS] = useState<ClusterStatus | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      // Tolerant poller: failures (incl. 401) just leave the banner hidden,
      // so don't bounce to /login from here.
      setS(await getClusterStatus());
    } catch {}
  }, []);

  usePolling(fetchStatus, 5000);

  if (!s) return null;
  // Green only when this node is MASTER *and* nothing needs attention — a
  // master with an unreachable peer or split brain is not healthy HA.
  const problems = s.warnings.length > 0;
  const colour = s.split_brain
    ? "bg-red-500/10 border-red-500/50 text-red-300"
    : s.role === "standalone"
      ? "bg-gray-500/10 border-gray-500/40 text-gray-300"
      : problems
        ? "bg-amber-500/10 border-amber-500/40 text-amber-200"
        : s.role === "primary"
          ? "bg-green-500/10 border-green-500/40 text-green-300"
          : "bg-blue-500/10 border-blue-500/40 text-blue-300";

  const held = s.demotion.reasons;

  return (
    <div className={`border rounded-lg px-4 py-3 ${colour}`}>
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div className="font-semibold">
            {ROLE_LABEL[s.role] ?? s.role.toUpperCase()}
            {s.configured_role !== "standalone" && (
              <span className="ml-2 text-xs font-normal opacity-70">
                configured {s.configured_role}
              </span>
            )}
          </div>
          <div className="text-xs opacity-70">
            {s.pfsync_state_count.toLocaleString()} states &middot; peer{" "}
            {s.peer_reachable ? "answering" : "NOT ANSWERING"}
            {s.carp.pfsync?.syncok === false && " · pfsync syncing"}
          </div>
        </div>
        {held.length > 0 && (
          <div className="text-xs">
            Demoted: {held.join(", ")}
            {s.demotion.maintenance && " (maintenance mode)"}
          </div>
        )}
      </div>
      {s.warnings.length > 0 && (
        <ul className="mt-2 text-xs list-disc pl-5 space-y-0.5">
          {s.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
