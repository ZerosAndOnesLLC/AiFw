"use client";

interface RestartOverlayProps {
  countdown: number;
}

// Restart overlay — blocks the page during service restart
export function RestartOverlay({ countdown }: RestartOverlayProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--bg-primary)]/95 backdrop-blur-sm">
      <div className="text-center space-y-6 max-w-md px-6">
        <div className="w-16 h-16 mx-auto border-4 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
        <div>
          <h2 className="text-xl font-bold text-[var(--text-primary)]">
            {countdown > 0 ? "Upgrading..." : "Almost ready..."}
          </h2>
          <p className="text-sm text-[var(--text-muted)] mt-2">
            Services are restarting with the new version.
            {countdown > 0 && (
              <> This may take up to 2 minutes. <span className="font-mono font-bold text-[var(--accent)]">{countdown}s</span> remaining</>
            )}
          </p>
        </div>
        <div className="w-full h-1.5 bg-[var(--bg-card)] rounded-full overflow-hidden">
          <div
            className="h-full bg-[var(--accent)] rounded-full transition-all duration-1000 ease-linear"
            style={{ width: `${Math.max(5, ((120 - countdown) / 120) * 100)}%` }}
          />
        </div>
        <p className="text-xs text-[var(--text-muted)]">
          The page will automatically refresh when the API is back online.
        </p>
      </div>
    </div>
  );
}
