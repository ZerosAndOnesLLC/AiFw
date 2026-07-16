"use client";

import { AifwUpdateInfo } from "@/lib/api/updates";

interface RestartPendingBannerProps {
  info: AifwUpdateInfo;
  onRestart: () => void;
}

export function RestartPendingBanner({ info, onRestart }: RestartPendingBannerProps) {
  return (
    <div className="flex items-center justify-between gap-4 px-4 py-3 rounded-lg border border-yellow-500/40 bg-yellow-500/10 text-yellow-200">
      <div className="text-sm">
        <span className="font-semibold">Restart pending.</span>{" "}
        v{info.current_version} is installed but services are still running v
        {info.running_version || "the previous version"}. Restart now to activate.
      </div>
      <button
        onClick={onRestart}
        className="px-3 py-1.5 bg-yellow-500/20 hover:bg-yellow-500/30 text-yellow-100 text-sm rounded-md border border-yellow-500/40 whitespace-nowrap"
      >
        Restart now
      </button>
    </div>
  );
}
