"use client";

import type { Dispatch, SetStateAction } from "react";
import type { ResolverConfig } from "@/lib/api/dns";
import { ToggleRow } from "./ToggleRow";

const LOCAL_ZONE_TYPES = [
  "transparent",
  "typetransparent",
  "static",
  "redirect",
  "deny",
  "refuse",
  "inform",
  "inform_deny",
  "inform_redirect",
  "always_transparent",
  "always_refuse",
  "always_nxdomain",
  "nodefault",
];

interface GeneralTabProps {
  config: ResolverConfig;
  setConfig: Dispatch<SetStateAction<ResolverConfig>>;
  interfaces: string[];
  isAllInterfaces: boolean;
  toggleInterface: (name: string) => void;
}

export function GeneralTab({ config, setConfig, interfaces, isAllInterfaces, toggleInterface }: GeneralTabProps) {
  return (
    <div className="space-y-5">
      {/* Backend selector */}
      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-2">DNS Backend</label>
        <div className="flex gap-2">
          {[
            { value: "rdns", label: "rDNS", desc: "High-performance resolver with DNSSEC, RPZ, DoT" },
            { value: "unbound", label: "Unbound", desc: "Traditional recursive resolver" },
          ].map((opt) => (
            <button
              key={opt.value}
              onClick={() => setConfig((p) => ({ ...p, backend: opt.value }))}
              className={`flex-1 px-4 py-3 rounded-lg border text-left transition-colors ${
                config.backend === opt.value
                  ? "bg-blue-600/15 border-blue-500/50 text-blue-400"
                  : "bg-gray-900 border-gray-700 text-[var(--text-secondary)] hover:border-gray-500"
              }`}
            >
              <div className="text-sm font-medium">{opt.label}</div>
              <div className="text-[10px] text-[var(--text-muted)] mt-0.5">{opt.desc}</div>
            </button>
          ))}
        </div>
      </div>

      {/* Enable toggle */}
      <ToggleRow
        checked={config.enabled}
        onToggle={() => setConfig((p) => ({ ...p, enabled: !p.enabled }))}
        label="Enable DNS Resolver"
      />

      {/* Listen interfaces */}
      <div>
        <label className="block text-xs text-[var(--text-muted)] mb-1.5">
          Listen Interfaces
        </label>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => toggleInterface("__all__")}
            className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
              isAllInterfaces
                ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                : "bg-gray-900 border-gray-700 text-[var(--text-secondary)] hover:border-gray-500"
            }`}
          >
            All
          </button>
          {interfaces.map((iface) => {
            const selected = !isAllInterfaces && config.listen_interfaces.includes(iface);
            return (
              <button
                key={iface}
                onClick={() => toggleInterface(iface)}
                className={`px-3 py-1.5 text-xs rounded-md border transition-colors ${
                  selected
                    ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                    : "bg-gray-900 border-gray-700 text-[var(--text-secondary)] hover:border-gray-500"
                }`}
              >
                {iface}
              </button>
            );
          })}
        </div>
        <p className="text-xs text-[var(--text-muted)] mt-1">
          {isAllInterfaces ? "Listening on all interfaces (0.0.0.0)" : `Listening on ${config.listen_interfaces.length} selected interface(s)`}
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Port */}
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Listen Port</label>
          <input
            type="number"
            value={config.port}
            onChange={(e) => setConfig((p) => ({ ...p, port: Number(e.target.value) }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          />
        </div>

        {/* Local zone type */}
        <div>
          <label className="block text-xs text-[var(--text-muted)] mb-1">Local Zone Type</label>
          <select
            value={config.local_zone_type}
            onChange={(e) => setConfig((p) => ({ ...p, local_zone_type: e.target.value }))}
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
          >
            {LOCAL_ZONE_TYPES.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </div>
      </div>

      {/* DNSSEC toggle */}
      <ToggleRow
        checked={config.dnssec}
        onToggle={() => setConfig((p) => ({ ...p, dnssec: !p.dnssec }))}
        label="DNSSEC Validation"
      />

      {/* DNS64 toggle */}
      <ToggleRow
        checked={config.dns64}
        onToggle={() => setConfig((p) => ({ ...p, dns64: !p.dns64 }))}
        label="DNS64"
      />

      {/* Register DHCP leases */}
      <ToggleRow
        checked={config.register_dhcp}
        onToggle={() => setConfig((p) => ({ ...p, register_dhcp: !p.register_dhcp }))}
        label="Register DHCP Leases in DNS"
      />

      {/* DHCP domain */}
      {config.register_dhcp && (
        <div className="max-w-xs">
          <label className="block text-xs text-[var(--text-muted)] mb-1.5">
            DHCP Lease Domain
          </label>
          <input
            type="text"
            value={config.dhcp_domain || ""}
            onChange={(e) => setConfig((p) => ({ ...p, dhcp_domain: e.target.value }))}
            placeholder="local"
            className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
          <p className="text-[10px] text-[var(--text-muted)] mt-1">
            DHCP clients will be registered as hostname.{config.dhcp_domain || "local"}
          </p>
        </div>
      )}
    </div>
  );
}
