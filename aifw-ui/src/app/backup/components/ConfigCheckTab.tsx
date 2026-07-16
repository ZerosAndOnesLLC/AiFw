"use client";

import type { ConfigCheck } from "@/lib/api/backup";
import { btnPrimary } from "./styles";

/* ===================== Config Check Tab ================ */

export function ConfigCheckTab({
  check,
  checking,
  runCheck,
}: {
  check: ConfigCheck | null;
  checking: boolean;
  runCheck: () => void;
}) {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">Configuration Validator</h2>
          <p className="text-xs text-[var(--text-muted)]">Checks firewall rules, NAT, DNS, VPN, and pf status for common issues</p>
        </div>
        <button onClick={runCheck} disabled={checking} className={btnPrimary}>
          {checking ? "Checking..." : "Run Check"}
        </button>
      </div>

      {check && (
        <div className="space-y-4">
          {/* Overall status */}
          <div className={`flex items-center gap-3 p-4 rounded-lg border ${
            check.valid
              ? "bg-green-500/10 border-green-500/20"
              : "bg-red-500/10 border-red-500/20"
          }`}>
            <div className={`w-10 h-10 rounded-full flex items-center justify-center text-lg ${
              check.valid ? "bg-green-500/20 text-green-400" : "bg-red-500/20 text-red-400"
            }`}>
              {check.valid ? "\u2713" : "\u2717"}
            </div>
            <div>
              <div className={`font-semibold ${check.valid ? "text-green-400" : "text-red-400"}`}>
                {check.valid ? "Configuration Valid" : "Issues Found"}
              </div>
              <div className="text-xs text-[var(--text-muted)]">
                {check.errors.length} errors, {check.warnings.length} warnings, {check.info.length} info
              </div>
            </div>
          </div>

          {/* Errors */}
          {check.errors.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider">Errors</h3>
              {check.errors.map((e, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 bg-red-500/10 border border-red-500/20 rounded text-sm text-red-300">
                  <span className="text-red-400 mt-0.5">&#x2716;</span> {e}
                </div>
              ))}
            </div>
          )}

          {/* Warnings */}
          {check.warnings.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs font-semibold text-yellow-400 uppercase tracking-wider">Warnings</h3>
              {check.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 bg-yellow-500/10 border border-yellow-500/20 rounded text-sm text-yellow-300">
                  <span className="text-yellow-400 mt-0.5">&#x26A0;</span> {w}
                </div>
              ))}
            </div>
          )}

          {/* Info */}
          {check.info.length > 0 && (
            <div className="space-y-1">
              <h3 className="text-xs font-semibold text-blue-400 uppercase tracking-wider">Info</h3>
              {check.info.map((inf, i) => (
                <div key={i} className="flex items-start gap-2 p-2.5 bg-blue-500/10 border border-blue-500/20 rounded text-sm text-blue-300">
                  <span className="text-blue-400 mt-0.5">&#x2139;</span> {inf}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
