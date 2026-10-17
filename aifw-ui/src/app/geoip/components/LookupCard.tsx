"use client";

import { useState } from "react";
import { GeoIpLookup } from "@/lib/api/geoip";
import { inputCls, saveBtnCls } from "@/app/settings/components/sectionStyles";

export function LookupCard({
  dbLoaded,
  onLookup,
}: {
  dbLoaded: boolean;
  onLookup: (ip: string) => Promise<GeoIpLookup>;
}) {
  const [ip, setIp] = useState("");
  const [result, setResult] = useState<GeoIpLookup | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = ip.trim();
    setError("");
    setResult(null);
    if (!q) return;
    setBusy(true);
    try {
      setResult(await onLookup(q));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Lookup failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={run} className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-3">
      <div>
        <h3 className="text-sm font-medium">Look up an address</h3>
        <p className="text-xs text-[var(--text-muted)]">Which country the loaded database maps an IP to.</p>
      </div>
      <div className="flex gap-2">
        <input
          aria-label="IP address"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          placeholder="203.0.113.42 or 2001:db8::1"
          className={inputCls}
        />
        <button type="submit" disabled={busy || !ip.trim()} className={saveBtnCls}>
          {busy ? "…" : "Lookup"}
        </button>
      </div>
      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">{error}</div>
      )}
      {result && (
        <div className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md p-3 text-sm space-y-1">
          <div className="flex items-center justify-between">
            <span className="font-mono">{result.ip}</span>
            {result.country ? (
              <span className="font-mono text-base font-bold">{result.country}</span>
            ) : (
              <span className="text-xs px-2 py-0.5 rounded bg-gray-500/20 text-gray-400 border border-gray-500/30">
                not in database
              </span>
            )}
          </div>
          {result.network && (
            <div className="text-xs text-[var(--text-muted)]">
              Network <span className="font-mono text-[var(--text-secondary)]">{result.network}</span>
            </div>
          )}
          {!result.country && !dbLoaded && (
            <div className="text-xs text-amber-300">No database is loaded, so nothing can match.</div>
          )}
        </div>
      )}
    </form>
  );
}
