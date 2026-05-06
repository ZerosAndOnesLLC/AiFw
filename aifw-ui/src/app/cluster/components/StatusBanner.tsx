"use client";

import { useEffect, useState } from "react";

type Status = {
  role: string;
  peer_reachable: boolean;
  pfsync_state_count: number;
  last_snapshot_hash: string | null;
};

export default function StatusBanner() {
  const [s, setS] = useState<Status | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchStatus = async () => {
      try {
        const r = await fetch("/api/v1/cluster/status", {
          credentials: "include",
        });
        if (!r.ok) return;
        const j: Status = await r.json();
        if (!cancelled) setS(j);
      } catch {}
    };
    fetchStatus();
    const id = setInterval(fetchStatus, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

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
