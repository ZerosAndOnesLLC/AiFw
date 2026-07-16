"use client";

import type { ChangeEvent, Dispatch, RefObject, SetStateAction } from "react";
import type { CommitConfirmStatus, OpnsensePreview } from "@/lib/api/backup";
import { btnPrimary, btnSecondary } from "./styles";

/* ===================== OPNsense Import Tab ================ */

export function OpnsenseImportTab({
  commitConfirm,
  handleCommitConfirm,
  opnXml,
  opnFileRef,
  handleOpnFileSelect,
  handleOpnPreview,
  cancelOpnUpload,
  opnPreview,
  opnIfaceMap,
  setOpnIfaceMap,
  handleOpnRefreshPlan,
  opnImportSystemSettings,
  setOpnImportSystemSettings,
  opnImporting,
  handleOpnImport,
  cancelOpnPreview,
}: {
  commitConfirm: CommitConfirmStatus | null;
  handleCommitConfirm: () => void;
  opnXml: string;
  opnFileRef: RefObject<HTMLInputElement | null>;
  handleOpnFileSelect: (e: ChangeEvent<HTMLInputElement>) => void;
  handleOpnPreview: () => void;
  cancelOpnUpload: () => void;
  opnPreview: Record<string, unknown> | null;
  opnIfaceMap: Record<string, string>;
  setOpnIfaceMap: Dispatch<SetStateAction<Record<string, string>>>;
  handleOpnRefreshPlan: () => void;
  opnImportSystemSettings: boolean;
  setOpnImportSystemSettings: (v: boolean) => void;
  opnImporting: boolean;
  handleOpnImport: () => void;
  cancelOpnPreview: () => void;
}) {
  return (
    <div className="space-y-5">
      {/* Commit Confirm Banner */}
      {commitConfirm && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-semibold text-amber-400">Pending Config Change — Confirm Required</p>
              <p className="text-xs text-amber-300 mt-1">
                {commitConfirm.description}. If you do not confirm within <strong>{commitConfirm.seconds_remaining}s</strong>, the configuration will automatically revert to the previous state.
              </p>
              <p className="text-xs text-amber-300/70 mt-1">
                If your network configuration changed, log in at the new IP address to confirm.
              </p>
            </div>
            <button onClick={handleCommitConfirm}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded font-medium whitespace-nowrap">
              Confirm Config
            </button>
          </div>
        </div>
      )}

      <div>
        <h2 className="text-lg font-semibold">Import from OPNsense</h2>
        <p className="text-xs text-[var(--text-muted)] mt-1">
          Upload an OPNsense/pfSense <code className="bg-[var(--bg-primary)] px-1 rounded">config.xml</code> backup file.
          AiFw will validate and show a summary before importing.
        </p>
      </div>

      {/* Step 1: Upload */}
      <div className="space-y-3">
        <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block">Step 1: Upload config.xml</label>
        <input ref={opnFileRef} type="file" accept=".xml" onChange={handleOpnFileSelect}
          className="block w-full text-sm text-[var(--text-secondary)] file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:text-sm file:font-medium file:bg-[var(--accent)] file:text-white hover:file:bg-[var(--accent-hover)]" />

        {opnXml && !opnPreview && (
          <div className="flex gap-3">
            <button onClick={handleOpnPreview} className={btnPrimary}>Analyze Config</button>
            <button onClick={cancelOpnUpload}
              className={btnSecondary}>Cancel</button>
          </div>
        )}
      </div>

      {/* Step 2: Preview + Interface Mapping + Dry-run plan */}
      {opnPreview && (() => {
        const p = opnPreview as OpnsensePreview;
        if (!p.valid) {
          return (
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-sm text-red-400">
              {p.error || "This does not appear to be a valid OPNsense/pfSense configuration file."}
            </div>
          );
        }
        const counts = p.counts ?? {};
        const sys = p.system ?? {};
        const diff = p.diff ?? {};
        const plan = p.plan ?? {};
        const needMapping = !!p.interfaces_need_mapping;
        const allMapped = (p.interfaces_found ?? []).every(i => (opnIfaceMap[i] ?? "").length > 0);
        const planRules = plan.rules ?? [];
        const planNat = plan.nat ?? [];
        const planAliases = plan.aliases ?? [];
        const planRoutes = plan.routes ?? [];
        const skipReasonSummary = (item: Record<string, unknown>) => (item.skip_reason as string | undefined) ?? "";
        return (
          <div className="space-y-4">
            {/* Counts */}
            <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block">Step 2: Review Summary</label>
            <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4 space-y-2 text-sm">
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Source</span><span>{p.kind} {p.version ?? ""}</span></div>
              {sys.hostname && <div className="flex justify-between"><span className="text-[var(--text-muted)]">Hostname</span><span>{sys.hostname}</span></div>}
              {sys.domain && <div className="flex justify-between"><span className="text-[var(--text-muted)]">Domain</span><span>{sys.domain}</span></div>}
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Firewall Rules</span><span className="font-mono">{counts.rules ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Aliases</span><span className="font-mono">{counts.aliases ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">NAT (port-forward / outbound / 1:1)</span><span className="font-mono">{counts.nat_port_forwards ?? 0} / {counts.nat_outbound ?? 0} / {counts.nat_one_to_one ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">Static Routes</span><span className="font-mono">{counts.static_routes ?? 0}</span></div>
              <div className="flex justify-between"><span className="text-[var(--text-muted)]">DNS Servers</span><span className="font-mono">{(sys.dns_servers ?? []).join(", ") || "none"}</span></div>
            </div>

            {/* Conflict / diff warnings */}
            {((diff.alias_name_collisions?.length ?? 0) > 0 ||
              (diff.duplicate_rule_signatures ?? 0) > 0 ||
              (diff.nat_external_port_collisions?.length ?? 0) > 0) && (
              <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 text-xs text-yellow-300 space-y-1">
                <p className="font-semibold text-yellow-200">Conflicts to review:</p>
                {(diff.alias_name_collisions?.length ?? 0) > 0 && (
                  <p>• Alias names already in AiFw: {diff.alias_name_collisions!.join(", ")}</p>
                )}
                {(diff.duplicate_rule_signatures ?? 0) > 0 && (
                  <p>• {diff.duplicate_rule_signatures} duplicate rule signatures inside the upload</p>
                )}
                {(diff.nat_external_port_collisions?.length ?? 0) > 0 && (
                  <p>• NAT port collisions: {diff.nat_external_port_collisions!.join(", ")}</p>
                )}
              </div>
            )}

            {/* Skipped — items the import will not apply */}
            {(p.skipped?.length ?? 0) > 0 && (
              <div className="bg-orange-500/10 border border-orange-500/20 rounded-lg p-3 text-xs text-orange-300 space-y-1">
                <p className="font-semibold text-orange-200">Items the import will skip:</p>
                {(p.skipped ?? []).map((s, i) => <p key={i}>• {s}</p>)}
              </div>
            )}

            {/* Interface Mapping */}
            {needMapping && (
              <div className="space-y-2">
                <label className="text-xs text-[var(--text-muted)] uppercase tracking-wider block">Step 3: Map Interfaces</label>
                <p className="text-xs text-amber-300">
                  The config references interfaces that don&apos;t match this system. Map each one, then refresh the dry-run plan to see how rules will translate.
                </p>
                <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-3 space-y-2">
                  {(p.interfaces_found ?? []).map((ci) => (
                    <div key={ci} className="flex items-center gap-3">
                      <span className="text-xs font-mono text-amber-400 w-20">{ci}</span>
                      <span className="text-xs text-[var(--text-muted)]">→</span>
                      <select value={opnIfaceMap[ci] || ""} onChange={(e) => setOpnIfaceMap(prev => ({ ...prev, [ci]: e.target.value }))}
                        className="bg-[var(--bg-primary)] border border-[var(--border)] rounded px-2 py-1 text-xs text-white">
                        <option value="">-- select --</option>
                        {(p.interfaces_system ?? []).map((si) => (
                          <option key={si} value={si}>{si}</option>
                        ))}
                      </select>
                    </div>
                  ))}
                </div>
                <button onClick={handleOpnRefreshPlan} disabled={!allMapped} className={btnSecondary}>
                  Refresh Dry-Run Plan
                </button>
              </div>
            )}

            {/* Dry-run plan: per-item view of what import will create */}
            <details open className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
              <summary className="cursor-pointer px-4 py-2 text-sm font-medium">
                Dry-run plan ({planRules.length} rules · {planNat.length} NAT · {planAliases.length} aliases · {planRoutes.length} routes)
              </summary>
              <div className="px-4 pb-4 pt-2 space-y-3 text-xs">
                {planAliases.length > 0 && (
                  <div>
                    <p className="font-semibold mb-1">Aliases</p>
                    <div className="space-y-1 font-mono">
                      {planAliases.map((a, i) => (
                        <div key={i} className={skipReasonSummary(a) ? "text-orange-300" : ""}>
                          {String(a.kind)} <span className="text-cyan-300">{String(a.name)}</span> → {(a.entries as string[] | undefined)?.join(", ") || "(none)"}
                          {skipReasonSummary(a) && <span className="ml-2 text-orange-400">[skip: {skipReasonSummary(a)}]</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {planRules.length > 0 && (
                  <div>
                    <p className="font-semibold mb-1">Rules</p>
                    <div className="space-y-1 font-mono">
                      {planRules.map((r, i) => (
                        <div key={i} className={skipReasonSummary(r) ? "text-orange-300" : ""}>
                          {String(r.action)} {String(r.direction)} {String(r.ip_version)} {r.interface ? `on ${r.interface}` : ""} {String(r.protocol)} from {String(r.src)}{r.src_port ? `:${r.src_port}` : ""} to {String(r.dst)}{r.dst_port ? `:${r.dst_port}` : ""} {r.label ? `// ${r.label}` : ""}
                          {skipReasonSummary(r) && <span className="ml-2 text-orange-400">[skip: {skipReasonSummary(r)}]</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {planNat.length > 0 && (
                  <div>
                    <p className="font-semibold mb-1">NAT</p>
                    <div className="space-y-1 font-mono">
                      {planNat.map((n, i) => (
                        <div key={i} className={skipReasonSummary(n) ? "text-orange-300" : ""}>
                          {String(n.kind)} on {String(n.interface)} {String(n.protocol)} {String(n.src)} → {String(n.redirect)} (matches {String(n.dst)}) {n.label ? `// ${n.label}` : ""}
                          {skipReasonSummary(n) && <span className="ml-2 text-orange-400">[skip: {skipReasonSummary(n)}]</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {planRoutes.length > 0 && (
                  <div>
                    <p className="font-semibold mb-1">Static Routes</p>
                    <div className="space-y-1 font-mono">
                      {planRoutes.map((r, i) => (
                        <div key={i} className={skipReasonSummary(r) ? "text-orange-300" : ""}>
                          {String(r.network)} via {String(r.gateway)} ({String(r.gateway_name)})
                          {skipReasonSummary(r) && <span className="ml-2 text-orange-400">[skip: {skipReasonSummary(r)}]</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </details>

            {/* System settings opt-in */}
            <label className="flex items-start gap-2 text-xs text-[var(--text-secondary)] cursor-pointer">
              <input
                type="checkbox"
                checked={opnImportSystemSettings}
                onChange={(e) => setOpnImportSystemSettings(e.target.checked)}
                className="mt-0.5"
              />
              <span>
                <span className="font-medium">Also import system settings</span>
                <span className="block text-[var(--text-muted)] mt-0.5">
                  When checked, the OPNsense hostname, domain, and DNS upstreams will replace the AiFw values. Off by default — most migrations want rules and aliases without renaming the appliance.
                </span>
              </span>
            </label>

            {/* Confirm Import */}
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3 text-xs text-yellow-300">
              Confirm to apply. A pre-import snapshot is saved to config history first, and rules + NAT + aliases + routes are wrapped in commit-confirm — if you don&apos;t confirm within the timeout, those revert automatically.
            </div>
            <div className="flex gap-3">
              <button onClick={handleOpnImport} disabled={opnImporting || (needMapping && !allMapped)} className={btnPrimary}>
                {opnImporting ? "Importing..." : "Confirm & Import"}
              </button>
              <button onClick={cancelOpnPreview}
                className={btnSecondary}>Cancel</button>
            </div>
          </div>
        );
      })()}
    </div>
  );
}
