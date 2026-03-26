"use client";

import { useState } from "react";
import Card from "@/components/Card";
import StatusBadge from "@/components/StatusBadge";

interface GeoRule {
  id: string;
  countryCode: string;
  countryName: string;
  action: "block" | "allow";
  label: string;
  tableName: string;
  cidrs: number;
}

interface LookupResult {
  ip: string;
  country: string;
  countryCode: string;
  action: "block" | "allow";
  cidr: string;
  table: string;
}

const demoRules: GeoRule[] = [
  { id: "gr-01", countryCode: "CN", countryName: "China", action: "block", label: "Block all Chinese IPs", tableName: "geoip_cn" , cidrs: 8432 },
  { id: "gr-02", countryCode: "RU", countryName: "Russia", action: "block", label: "Block Russian federation", tableName: "geoip_ru", cidrs: 6218 },
  { id: "gr-03", countryCode: "KP", countryName: "North Korea", action: "block", label: "Block DPRK ranges", tableName: "geoip_kp", cidrs: 12 },
  { id: "gr-04", countryCode: "IR", countryName: "Iran", action: "block", label: "Block Iranian IPs", tableName: "geoip_ir", cidrs: 1847 },
  { id: "gr-05", countryCode: "US", countryName: "United States", action: "allow", label: "Allow US traffic", tableName: "geoip_us", cidrs: 72410 },
  { id: "gr-06", countryCode: "CA", countryName: "Canada", action: "allow", label: "Allow Canadian traffic", tableName: "geoip_ca", cidrs: 14832 },
  { id: "gr-07", countryCode: "GB", countryName: "United Kingdom", action: "allow", label: "Allow UK traffic", tableName: "geoip_gb", cidrs: 21540 },
  { id: "gr-08", countryCode: "DE", countryName: "Germany", action: "allow", label: "Allow German traffic", tableName: "geoip_de", cidrs: 18720 },
  { id: "gr-09", countryCode: "AU", countryName: "Australia", action: "allow", label: "Allow Australian traffic", tableName: "geoip_au", cidrs: 9410 },
  { id: "gr-10", countryCode: "JP", countryName: "Japan", action: "allow", label: "Allow Japanese traffic", tableName: "geoip_jp", cidrs: 15280 },
  { id: "gr-11", countryCode: "NG", countryName: "Nigeria", action: "block", label: "Block Nigerian IPs", tableName: "geoip_ng", cidrs: 2104 },
  { id: "gr-12", countryCode: "BR", countryName: "Brazil", action: "block", label: "Block Brazilian IPs", tableName: "geoip_br", cidrs: 11320 },
];

const demoLookupResults: Record<string, LookupResult> = {
  "203.0.113.42": { ip: "203.0.113.42", country: "China", countryCode: "CN", action: "block", cidr: "203.0.112.0/20", table: "geoip_cn" },
  "198.51.100.17": { ip: "198.51.100.17", country: "Russia", countryCode: "RU", action: "block", cidr: "198.51.96.0/19", table: "geoip_ru" },
  "8.8.8.8": { ip: "8.8.8.8", country: "United States", countryCode: "US", action: "allow", cidr: "8.8.8.0/24", table: "geoip_us" },
  "1.1.1.1": { ip: "1.1.1.1", country: "Australia", countryCode: "AU", action: "allow", cidr: "1.1.1.0/24", table: "geoip_au" },
};

export default function GeoIpPage() {
  const [rules, setRules] = useState<GeoRule[]>(demoRules);
  const [lookupIp, setLookupIp] = useState("");
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null);
  const [lookupError, setLookupError] = useState("");
  const [newCountryCode, setNewCountryCode] = useState("");
  const [newAction, setNewAction] = useState<"block" | "allow">("block");

  const blockedCountries = rules.filter((r) => r.action === "block").length;
  const allowedCountries = rules.filter((r) => r.action === "allow").length;
  const totalCidrs = rules.reduce((sum, r) => sum + r.cidrs, 0);

  function handleLookup() {
    setLookupError("");
    setLookupResult(null);

    const trimmed = lookupIp.trim();
    if (!trimmed) {
      setLookupError("Enter an IP address");
      return;
    }

    const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    if (!ipPattern.test(trimmed)) {
      setLookupError("Invalid IPv4 address format");
      return;
    }

    const result = demoLookupResults[trimmed];
    if (result) {
      setLookupResult(result);
    } else {
      setLookupResult({
        ip: trimmed,
        country: "Unknown",
        countryCode: "??",
        action: "allow",
        cidr: "N/A",
        table: "none",
      });
    }
  }

  function handleAddRule() {
    const code = newCountryCode.trim().toUpperCase();
    if (!code || code.length !== 2) return;

    if (rules.some((r) => r.countryCode === code)) return;

    const newRule: GeoRule = {
      id: `gr-${rules.length + 1}`,
      countryCode: code,
      countryName: code,
      action: newAction,
      label: `${newAction === "block" ? "Block" : "Allow"} ${code} traffic`,
      tableName: `geoip_${code.toLowerCase()}`,
      cidrs: Math.floor(Math.random() * 5000) + 100,
    };
    setRules([...rules, newRule]);
    setNewCountryCode("");
  }

  function handleDeleteRule(id: string) {
    setRules(rules.filter((r) => r.id !== id));
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold">Geo-IP Filtering</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Country-level traffic filtering using MaxMind GeoIP databases and pf tables
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        <Card title="Countries Blocked" value={blockedCountries} color="red" subtitle="active block rules" />
        <Card title="Countries Allowed" value={allowedCountries} color="green" subtitle="active allow rules" />
        <Card title="CIDRs Loaded" value={totalCidrs.toLocaleString()} color="cyan" subtitle="across all tables" />
      </div>

      {/* Geo-IP Rules Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between">
          <h3 className="text-sm font-medium">Geo-IP Rules</h3>
          <span className="text-xs text-[var(--text-muted)]">{rules.length} rules</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)]">
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Country</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Code</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Action</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Label</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Table</th>
                <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">CIDRs</th>
                <th className="w-10"></th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => (
                <tr key={rule.id} className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors">
                  <td className="py-2.5 px-3">{rule.countryName}</td>
                  <td className="py-2.5 px-3 font-mono text-xs font-bold">{rule.countryCode}</td>
                  <td className="py-2.5 px-3">
                    <StatusBadge status={rule.action} />
                  </td>
                  <td className="py-2.5 px-3 text-xs text-[var(--text-secondary)]">{rule.label}</td>
                  <td className="py-2.5 px-3 font-mono text-xs text-[var(--text-muted)]">{rule.tableName}</td>
                  <td className="py-2.5 px-3 text-xs text-right text-[var(--text-secondary)]">{rule.cidrs.toLocaleString()}</td>
                  <td className="py-2.5 px-2">
                    <button
                      onClick={() => handleDeleteRule(rule.id)}
                      className="text-[var(--text-muted)] hover:text-red-400 transition-colors"
                      title="Delete rule"
                    >
                      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Row: Lookup + Add Rule */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* IP Lookup */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">IP Address Lookup</h3>
          <p className="text-xs text-[var(--text-muted)] mb-4">Check which geo-ip rule applies to an IP address</p>
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={lookupIp}
              onChange={(e) => setLookupIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              placeholder="e.g. 203.0.113.42"
              className="flex-1 bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors"
            />
            <button
              onClick={handleLookup}
              className="px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white text-sm font-medium rounded-md transition-colors"
            >
              Lookup
            </button>
          </div>

          {lookupError && (
            <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-md px-3 py-2">
              {lookupError}
            </div>
          )}

          {lookupResult && (
            <div className="bg-[var(--bg-primary)] border border-[var(--border)] rounded-md p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm">{lookupResult.ip}</span>
                <StatusBadge status={lookupResult.action} size="md" />
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-[var(--text-muted)]">Country:</span>
                  <span className="ml-2 text-[var(--text-primary)]">{lookupResult.country} ({lookupResult.countryCode})</span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)]">CIDR:</span>
                  <span className="ml-2 font-mono text-[var(--text-primary)]">{lookupResult.cidr}</span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)]">Table:</span>
                  <span className="ml-2 font-mono text-[var(--text-primary)]">{lookupResult.table}</span>
                </div>
                <div>
                  <span className="text-[var(--text-muted)]">Action:</span>
                  <span className={`ml-2 font-medium ${lookupResult.action === "block" ? "text-red-400" : "text-green-400"}`}>
                    {lookupResult.action.toUpperCase()}
                  </span>
                </div>
              </div>
            </div>
          )}

          {!lookupResult && !lookupError && (
            <div className="text-xs text-[var(--text-muted)]">
              Try: 203.0.113.42, 198.51.100.17, 8.8.8.8, 1.1.1.1
            </div>
          )}
        </div>

        {/* Add Rule */}
        <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-4">
          <h3 className="text-sm font-medium mb-3">Add Geo-IP Rule</h3>
          <p className="text-xs text-[var(--text-muted)] mb-4">Add a new country-level block or allow rule</p>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Country Code (ISO 3166-1 alpha-2)</label>
              <input
                type="text"
                value={newCountryCode}
                onChange={(e) => setNewCountryCode(e.target.value.toUpperCase().slice(0, 2))}
                placeholder="e.g. FR"
                maxLength={2}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-[var(--text-muted)] focus:outline-none focus:border-[var(--accent)] transition-colors font-mono uppercase"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Action</label>
              <select
                value={newAction}
                onChange={(e) => setNewAction(e.target.value as "block" | "allow")}
                className="w-full bg-[var(--bg-primary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)] transition-colors"
              >
                <option value="block">Block</option>
                <option value="allow">Allow</option>
              </select>
            </div>
            <button
              onClick={handleAddRule}
              disabled={!newCountryCode.trim() || newCountryCode.trim().length !== 2}
              className="w-full px-4 py-2 bg-[var(--accent)] hover:bg-[var(--accent-hover)] disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-medium rounded-md transition-colors"
            >
              Add Rule
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
