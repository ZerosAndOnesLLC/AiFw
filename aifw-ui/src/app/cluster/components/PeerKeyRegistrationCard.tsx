"use client";

import { useState } from "react";

// ============================================================
// SEC-H12: register the inbound peer key so the master can push here
// ============================================================

export function PeerKeyRegistrationCard({
  highlight,
  busy,
  peerKeyMsg,
  onDismissMsg,
  onRegister,
}: {
  /// True when the health summary reports the inbound peer key missing.
  highlight: boolean | undefined;
  busy: boolean;
  peerKeyMsg: string | null;
  onDismissMsg: () => void;
  /// `onRegistered` is invoked only when registration succeeded.
  onRegister: (key: string, onRegistered: () => void) => void;
}) {
  const [peerKeyInput, setPeerKeyInput] = useState("");

  return (
    <div
      className={`rounded p-3 text-sm ${
        highlight
          ? "bg-yellow-500/10 border border-yellow-500/40"
          : "bg-[var(--bg-card)] border border-[var(--border)]"
      }`}
    >
      <div className="font-semibold mb-1">Register Peer Key</div>
      <div className="text-xs opacity-80 mb-2">
        Paste the peer key generated on the master (via &quot;Generate Peer
        Key&quot; for this node) so this node accepts snapshot / cert pushes
        from it. A broad HaManage key is no longer accepted.
      </div>
      <div className="flex gap-2">
        <input
          type="password"
          value={peerKeyInput}
          onChange={(e) => setPeerKeyInput(e.target.value)}
          placeholder="Paste peer API key"
          className="flex-1 bg-[var(--bg-input)] border border-[var(--border)] rounded px-2 py-1.5 text-sm font-mono"
        />
        <button
          onClick={() => onRegister(peerKeyInput, () => setPeerKeyInput(""))}
          disabled={busy || !peerKeyInput.trim()}
          className="px-3 py-1.5 rounded bg-[var(--accent)] hover:opacity-90 disabled:opacity-50 whitespace-nowrap text-sm"
        >
          Register
        </button>
      </div>
      {peerKeyMsg && (
        <div className="text-xs text-green-400 mt-2 flex justify-between">
          <span>{peerKeyMsg}</span>
          <button onClick={onDismissMsg} className="underline">
            dismiss
          </button>
        </div>
      )}
    </div>
  );
}
