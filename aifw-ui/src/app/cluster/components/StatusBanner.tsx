"use client";

import { useCallback, useState } from "react";
import { api } from "@/lib/api";
import { usePolling } from "@/lib/usePolling";

type Status = {
  role: string;
  peer_reachable: boolean;
  pfsync_state_count: number;
  last_snapshot_hash: string | null;
};

export default function StatusBanner() {
  const [s, setS] = useState<Status | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      // Tolerant poller: failures (incl. 401) just leave the banner hidden,
      // so don't bounce to /login from here.
      const j = await api.get<Status>("/api/v1/cluster/status", { noAuthRedirect: true });
      setS(j);
    } catch {}
  }, []);

  usePolling(fetchStatus, 5000);

  if (!s) return null;
  const isMaster = s.role === "primary";
  const colour = isMaster
    ? "bg-green-500/10 border-green-500/40 text-green-300"
    : s.role === "standalone"
      ? "bg-gray-500/10 border-gray-500/40 text-gray-300"
      : "bg-blue-500/10 border-blue-500/40 text-blue-300";

  return (
    <div className={`border rounded-lg px-4 py-3 ${colour}`}>
      <div className="flex items-center justify-between gap-4">
        <div>
          <div className="font-semibold">{s.role.toUpperCase()}</div>
          <div className="text-xs opacity-70">
            {s.pfsync_state_count} pfsync states &middot; peer{" "}
            {s.peer_reachable ? "reachable" : "UNREACHABLE"}
          </div>
        </div>
      </div>
    </div>
  );
}
