"use client";

import type { Dispatch, SetStateAction } from "react";
import type { ResolverConfig } from "@/lib/api/dns";

interface CustomTabProps {
  config: ResolverConfig;
  setConfig: Dispatch<SetStateAction<ResolverConfig>>;
}

export function CustomTab({ config, setConfig }: CustomTabProps) {
  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1.5">
          {config.backend === "rdns" ? "Custom rDNS Configuration" : "Custom Unbound Configuration"}
        </label>
        <p className="text-[10px] text-[var(--text-muted)] mb-2">
          {config.backend === "rdns"
            ? "Raw TOML lines appended to the generated rdns.toml. Use with caution."
            : "Raw unbound.conf lines appended to the generated configuration. Use with caution."}
        </p>
        <textarea
          value={config.custom_options}
          onChange={(e) => setConfig((p) => ({ ...p, custom_options: e.target.value }))}
          rows={12}
          placeholder={config.backend === "rdns" ? "# Custom rDNS TOML..." : "# Custom unbound options..."}
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 font-mono focus:outline-none focus:border-blue-500"
        />
      </div>
    </div>
  );
}
