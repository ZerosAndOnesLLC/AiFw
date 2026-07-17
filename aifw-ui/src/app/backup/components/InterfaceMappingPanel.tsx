"use client";

import { countDroppedEntries, type ImportPreview } from "@/lib/api/backup";

/* ===================== Interface mapping panel ===================== */

export function InterfaceMappingPanel({
  preview,
  map,
  onMapChange,
}: {
  preview: ImportPreview;
  map: Record<string, string>;
  onMapChange: (m: Record<string, string>) => void;
}) {
  const drop = countDroppedEntries(preview, map);
  const dropTotal = drop.rules + drop.nat + drop.wireguard + drop.carp + drop.queues + drop.rate_limits + (drop.pfsync ? 1 : 0);
  const anyDropped = preview.interfaces_missing.some(m => map[m] === "__drop__");

  const setChoice = (iface: string, value: string) => {
    onMapChange({ ...map, [iface]: value });
  };

  return (
    <div className="space-y-3 bg-amber-500/5 border border-amber-500/30 rounded-lg p-4">
      <div className="text-sm text-amber-300 font-semibold">
        NIC name mismatch — map {preview.interfaces_missing.length} missing interface(s)
      </div>
      <div className="space-y-2">
        {preview.interfaces_missing.map(missing => {
          const choice = map[missing] ?? "__keep__";
          return (
            <div key={missing} className="flex items-center gap-3 p-2.5 bg-[var(--bg-primary)] rounded border border-[var(--border)]">
              <div className="font-mono text-sm font-semibold text-amber-400 w-24 shrink-0">{missing}</div>
              <div className="text-[var(--text-muted)] text-xs">&rarr;</div>
              <select
                value={choice}
                onChange={e => setChoice(missing, e.target.value)}
                className="flex-1 px-2 py-1.5 bg-[var(--bg-card)] border border-[var(--border)] rounded text-sm"
              >
                <option value="__keep__">Keep as &ldquo;{missing}&rdquo; (virtual / will be created)</option>
                <option value="__drop__">Drop all entries referencing this interface</option>
                <optgroup label="Map to local interface">
                  {preview.interfaces_present.map(iface => {
                    const details: string[] = [];
                    if (iface.mac) details.push(iface.mac);
                    if (iface.ipv4) details.push(iface.ipv4 + (iface.ipv4_mode === "dhcp" ? " (DHCP)" : ""));
                    if (!iface.ipv4 && iface.ipv4_mode === "dhcp") details.push("DHCP");
                    if (iface.status) details.push(iface.status);
                    const label = details.length > 0 ? `${iface.name} — ${details.join(" · ")}` : iface.name;
                    return <option key={iface.name} value={iface.name}>{label}</option>;
                  })}
                </optgroup>
              </select>
            </div>
          );
        })}
      </div>
      {anyDropped && (
        <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded p-2.5">
          <span className="font-semibold">Warning:</span> entries using dropped interfaces will be permanently removed on apply.
          {dropTotal > 0 && (
            <>
              {" "}Upper bound: {drop.rules} rule(s), {drop.nat} NAT, {drop.wireguard} WG tunnel(s), {drop.carp} CARP VIP(s), {drop.queues} queue(s), {drop.rate_limits} rate-limit(s){drop.pfsync ? ", pfsync" : ""}.
            </>
          )}
        </div>
      )}
    </div>
  );
}
