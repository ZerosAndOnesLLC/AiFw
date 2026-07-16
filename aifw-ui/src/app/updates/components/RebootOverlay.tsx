"use client";

// Reboot overlay — sticks until the browser fails to reach the API
// long enough that we know the box has gone down. We don't try to
// poll-back-up here; the operator will reload manually after the
// box comes back, or close the tab.
export function RebootOverlay() {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-[var(--bg-primary)]/95 backdrop-blur-sm">
      <div className="text-center space-y-6 max-w-md px-6">
        <div className="w-16 h-16 mx-auto border-4 border-yellow-500 border-t-transparent rounded-full animate-spin" />
        <h2 className="text-xl font-bold text-[var(--text-primary)]">Rebooting...</h2>
        <p className="text-sm text-[var(--text-muted)]">
          The system will go down in about a minute. The page will become unreachable
          until the appliance finishes booting (typically 1–2 minutes).
          Refresh manually once it&apos;s back.
        </p>
        <p className="text-xs text-[var(--text-muted)]">
          To cancel, run <code className="font-mono">shutdown -c</code> on the console.
        </p>
      </div>
    </div>
  );
}
