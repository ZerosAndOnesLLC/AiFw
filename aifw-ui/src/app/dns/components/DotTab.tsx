"use client";

import type { Dispatch, SetStateAction } from "react";
import type { ResolverConfig } from "@/lib/api/dns";
import { ToggleRow } from "./ToggleRow";

interface DotTabProps {
  config: ResolverConfig;
  setConfig: Dispatch<SetStateAction<ResolverConfig>>;
  upstreamInput: string;
  setUpstreamInput: (value: string) => void;
  addToList: (field: keyof ResolverConfig, value: string) => void;
  removeFromList: (field: keyof ResolverConfig, index: number) => void;
}

export function DotTab({
  config,
  setConfig,
  upstreamInput,
  setUpstreamInput,
  addToList,
  removeFromList,
}: DotTabProps) {
  return (
    <div className="space-y-5">
      {/* DoT enable */}
      <ToggleRow
        checked={config.dot_enabled}
        onToggle={() => setConfig((p) => ({ ...p, dot_enabled: !p.dot_enabled }))}
        label="Enable DNS over TLS"
      />

      {/* DoT upstream servers */}
      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1.5">
          Upstream DoT Servers
        </label>
        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={upstreamInput}
            onChange={(e) => setUpstreamInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                addToList("dot_upstream", upstreamInput);
                setUpstreamInput("");
              }
            }}
            placeholder="e.g. 1.1.1.1@853#cloudflare-dns.com"
            className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={() => {
              addToList("dot_upstream", upstreamInput);
              setUpstreamInput("");
            }}
            className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
          >
            Add
          </button>
        </div>
        {config.dot_upstream.length > 0 && (
          <div className="space-y-1">
            {config.dot_upstream.map((server, i) => (
              <div
                key={i}
                className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md"
              >
                <span className="text-xs font-mono text-[var(--text-secondary)]">{server}</span>
                <button
                  onClick={() => removeFromList("dot_upstream", i)}
                  className="text-red-400 hover:text-red-300 text-xs ml-2"
                >
                  Remove
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
