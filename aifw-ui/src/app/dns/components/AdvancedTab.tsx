"use client";

import type { Dispatch, SetStateAction } from "react";
import type { ResolverConfig } from "@/lib/api/dns";
import { ToggleRow } from "./ToggleRow";

interface AdvancedTabProps {
  config: ResolverConfig;
  setConfig: Dispatch<SetStateAction<ResolverConfig>>;
  privateAddrInput: string;
  setPrivateAddrInput: (value: string) => void;
  addToList: (field: keyof ResolverConfig, value: string) => void;
  removeFromList: (field: keyof ResolverConfig, index: number) => void;
}

export function AdvancedTab({
  config,
  setConfig,
  privateAddrInput,
  setPrivateAddrInput,
  addToList,
  removeFromList,
}: AdvancedTabProps) {
  return (
    <div className="space-y-5">
      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1">Outgoing Interface</label>
        <input
          type="text"
          value={config.outgoing_interface}
          onChange={(e) => setConfig((p) => ({ ...p, outgoing_interface: e.target.value }))}
          placeholder="Leave blank for auto"
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <h3 className="text-sm font-medium text-[var(--text-secondary)]">Safety</h3>
      <div className="flex items-start gap-3 p-3 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md">
        <button
          type="button"
          onClick={() => setConfig((p) => ({ ...p, probe_enabled: !p.probe_enabled }))}
          className={`shrink-0 mt-0.5 relative w-11 h-6 rounded-full transition-colors ${
            config.probe_enabled ? "bg-blue-600" : "bg-gray-600"
          }`}
          aria-label="Toggle post-switch DNS probe"
        >
          <span
            className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
              config.probe_enabled ? "translate-x-5" : ""
            }`}
          />
        </button>
        <div className="flex-1">
          <div className="text-sm text-[var(--text-primary)] font-medium">
            Probe :53 after backend switch
          </div>
          <p className="text-xs text-[var(--text-muted)] mt-1">
            When enabled (recommended), a real DNS query is sent to 127.0.0.1:53 after starting a resolver; if it doesn&apos;t answer within 8 seconds, the previous backend is automatically restored. Also drives the live health dot in the status bar. Disable only for debugging or if the probe itself is giving false negatives.
          </p>
        </div>
      </div>

      <h3 className="text-sm font-medium text-[var(--text-secondary)]">Cache & Threading</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">
            Threads
            {config.backend === "rdns" && (
              <span className="ml-2 text-[10px] text-[var(--text-muted)]">(Unbound only — rDNS uses SO_REUSEPORT workers)</span>
            )}
          </label>
          <input
            type="number"
            value={config.num_threads}
            onChange={(e) => setConfig((p) => ({ ...p, num_threads: Number(e.target.value) }))}
            disabled={config.backend === "rdns"}
            title={config.backend === "rdns" ? "rDNS does not use thread count; see SO_REUSEPORT workers in rDNS config" : ""}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
          />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Message Cache Size (MB)</label>
          <input
            type="number"
            value={config.msg_cache_size}
            onChange={(e) => setConfig((p) => ({ ...p, msg_cache_size: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">RRset Cache Size (MB)</label>
          <input
            type="number"
            value={config.rrset_cache_size}
            onChange={(e) => setConfig((p) => ({ ...p, rrset_cache_size: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      <h3 className="text-sm font-medium text-[var(--text-secondary)]">TTL Settings</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Cache Max TTL (seconds)</label>
          <input
            type="number"
            value={config.cache_max_ttl}
            onChange={(e) => setConfig((p) => ({ ...p, cache_max_ttl: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Cache Min TTL (seconds)</label>
          <input
            type="number"
            value={config.cache_min_ttl}
            onChange={(e) => setConfig((p) => ({ ...p, cache_min_ttl: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Infra Host TTL (seconds)</label>
          <input
            type="number"
            value={config.infra_host_ttl}
            onChange={(e) => setConfig((p) => ({ ...p, infra_host_ttl: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Prefetch */}
        <ToggleRow
          checked={config.prefetch}
          onToggle={() => setConfig((p) => ({ ...p, prefetch: !p.prefetch }))}
          label="Prefetch"
        />
        {/* Prefetch Key */}
        <ToggleRow
          checked={config.prefetch_key}
          onToggle={() => setConfig((p) => ({ ...p, prefetch_key: !p.prefetch_key }))}
          label="Prefetch DNSKEY"
        />
      </div>

      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1">Max Query Timeout (ms)</label>
        <input
          type="number"
          min={0}
          max={60000}
          value={config.query_timeout_ms}
          onChange={(e) => setConfig((p) => ({ ...p, query_timeout_ms: Number(e.target.value) }))}
          placeholder="0 = defaults (UDP 3000, TCP/DoT 30000)"
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <p className="mt-1 text-[11px] text-[var(--text-muted)]">
          Keep under 5000 for UDP so stub resolvers retry before giving up. 0 leaves rDNS per-transport defaults in place.
        </p>
      </div>

      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1">Unwanted Reply Threshold</label>
        <input
          type="number"
          value={config.unwanted_reply_threshold}
          onChange={(e) => setConfig((p) => ({ ...p, unwanted_reply_threshold: Number(e.target.value) }))}
          placeholder="0 = disabled"
          className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <p className="text-[10px] text-[var(--text-muted)] mt-1">Number of unwanted replies to trigger defensive action. 0 to disable.</p>
      </div>

      <h3 className="text-sm font-medium text-[var(--text-secondary)]">Logging</h3>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <ToggleRow
          checked={config.log_queries}
          onToggle={() => setConfig((p) => ({ ...p, log_queries: !p.log_queries }))}
          label="Log Queries"
        />
        <ToggleRow
          checked={config.log_replies}
          onToggle={() => setConfig((p) => ({ ...p, log_replies: !p.log_replies }))}
          label="Log Replies"
        />
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Log Verbosity</label>
          <select
            value={config.log_verbosity}
            onChange={(e) => setConfig((p) => ({ ...p, log_verbosity: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          >
            {[0, 1, 2, 3, 4, 5].map((v) => (
              <option key={v} value={v}>Level {v}</option>
            ))}
          </select>
        </div>
      </div>

      <h3 className="text-sm font-medium text-[var(--text-secondary)]">Privacy & Security</h3>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <ToggleRow
          checked={config.hide_identity}
          onToggle={() => setConfig((p) => ({ ...p, hide_identity: !p.hide_identity }))}
          label="Hide Identity"
        />
        <ToggleRow
          checked={config.hide_version}
          onToggle={() => setConfig((p) => ({ ...p, hide_version: !p.hide_version }))}
          label="Hide Version"
        />
      </div>

      <ToggleRow
        checked={config.rebind_protection}
        onToggle={() => setConfig((p) => ({ ...p, rebind_protection: !p.rebind_protection }))}
        label="DNS Rebind Protection"
      />

      {/* Private addresses */}
      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1.5">
          Private Addresses (rebind protection exemptions)
        </label>
        <div className="flex gap-2 mb-2">
          <input
            type="text"
            value={privateAddrInput}
            onChange={(e) => setPrivateAddrInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                addToList("private_addresses", privateAddrInput);
                setPrivateAddrInput("");
              }
            }}
            placeholder="e.g. 10.0.0.0/8"
            className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={() => {
              addToList("private_addresses", privateAddrInput);
              setPrivateAddrInput("");
            }}
            className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md"
          >
            Add
          </button>
        </div>
        {config.private_addresses.length > 0 && (
          <div className="space-y-1">
            {config.private_addresses.map((addr, i) => (
              <div
                key={i}
                className="flex items-center justify-between px-3 py-1.5 bg-gray-900 border border-gray-700 rounded-md"
              >
                <span className="text-xs font-mono text-[var(--text-secondary)]">{addr}</span>
                <button
                  onClick={() => removeFromList("private_addresses", i)}
                  className="text-red-400 hover:text-red-300 text-xs"
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
