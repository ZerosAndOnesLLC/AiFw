"use client";

import { useState } from "react";
import { isValidIPv4 } from "@/lib/validate";
import {
  type DhcpOptionOverride,
  type DhcpSubnet,
  type GlobalDefaults,
  type SubnetForm,
  OPTION_VALUE_TYPES,
  defaultForm,
  isLoopbackV4,
  subnetToForm,
  validateOption,
} from "@/lib/api/dhcp-subnets";

export interface SubnetFormModalProps {
  /** Subnet being edited, or null when creating a new one. */
  editing: DhcpSubnet | null;
  /** Global DHCP config used by the Auto-fill button. */
  globalDefaults: GlobalDefaults;
  submitting: boolean;
  showFeedback: (type: "success" | "error", msg: string) => void;
  onSubmit: (form: SubnetForm) => void;
  onClose: () => void;
}

export function SubnetFormModal({
  editing,
  globalDefaults,
  submitting,
  showFeedback,
  onSubmit,
  onClose,
}: SubnetFormModalProps) {
  const [form, setForm] = useState<SubnetForm>(() => (editing ? subnetToForm(editing) : defaultForm));
  const [relayDraft, setRelayDraft] = useState("");
  const [relayError, setRelayError] = useState<string | null>(null);

  const addRelay = () => {
    const ip = relayDraft.trim();
    if (!ip) return;
    if (!isValidIPv4(ip)) { setRelayError("Must be a valid IPv4 address"); return; }
    if (isLoopbackV4(ip)) { setRelayError("Loopback (127.x.x.x) is not allowed"); return; }
    if (form.trusted_relays.includes(ip)) { setRelayError("Already in list"); return; }
    setForm((p) => ({ ...p, trusted_relays: [...p.trusted_relays, ip] }));
    setRelayDraft("");
    setRelayError(null);
  };

  const removeRelay = (ip: string) => {
    setForm((p) => ({ ...p, trusted_relays: p.trusted_relays.filter((r) => r !== ip) }));
  };

  /** Auto-fill pool + gateway + DNS + NTP from the CIDR's network base +
   *  global defaults. Convention: gateway = .1, pool = .20 — .220. Works
   *  for /16 through /24. */
  const autoFillFromCidr = () => {
    const cidr = form.network.trim();
    const m = cidr.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.\d{1,3}\/(\d{1,2})$/);
    if (!m) {
      showFeedback("error", "Enter a valid IPv4 CIDR first (e.g. 172.29.44.0/24)");
      return;
    }
    const [, a, b, c, prefixStr] = m;
    const prefix = Number(prefixStr);
    if (prefix < 16 || prefix > 24) {
      showFeedback("error", "Auto-fill supports /16 through /24; fill pool manually for other sizes");
      return;
    }
    const base = `${a}.${b}.${c}`;
    setForm((p) => ({
      ...p,
      gateway: `${base}.1`,
      pool_start: `${base}.20`,
      pool_end: `${base}.220`,
      dns_servers: globalDefaults.dns_servers.length > 0
        ? globalDefaults.dns_servers.join(", ")
        : p.dns_servers,
      ntp_servers: globalDefaults.ntp_servers.length > 0
        ? globalDefaults.ntp_servers.join(", ")
        : p.ntp_servers,
      domain_name: p.domain_name || globalDefaults.domain_name,
    }));
    showFeedback("success", "Pool, gateway, DNS, and NTP filled from defaults");
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-lg w-full mx-4 space-y-4">
        <h3 className="text-lg font-semibold text-white">
          {editing ? "Edit Subnet" : "Add Subnet"}
        </h3>

        <div className="space-y-4">
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              Network
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={form.network.includes("/") ? form.network.split("/")[0] : form.network}
                onChange={(e) => {
                  const ip = e.target.value.replace(/[^0-9.]/g, "");
                  const prefix = form.network.includes("/") ? form.network.split("/")[1] : "24";
                  setForm((p) => ({ ...p, network: ip ? `${ip}/${prefix}` : "" }));
                }}
                placeholder="e.g. 192.168.1.0"
                className="flex-1 px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <select
                value={form.network.includes("/") ? form.network.split("/")[1] : "24"}
                onChange={(e) => {
                  const ip = form.network.includes("/") ? form.network.split("/")[0] : form.network;
                  setForm((p) => ({ ...p, network: `${ip}/${e.target.value}` }));
                }}
                className="w-24 px-2 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
              >
                <option value="8">/8</option>
                <option value="12">/12</option>
                <option value="16">/16</option>
                <option value="20">/20</option>
                <option value="21">/21</option>
                <option value="22">/22</option>
                <option value="23">/23</option>
                <option value="24">/24</option>
                <option value="25">/25</option>
                <option value="26">/26</option>
                <option value="27">/27</option>
                <option value="28">/28</option>
                <option value="29">/29</option>
                <option value="30">/30</option>
              </select>
              <button
                type="button"
                onClick={autoFillFromCidr}
                title="Fill pool (.20–.220), gateway (.1), and DNS from global defaults"
                className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded-md whitespace-nowrap"
              >
                Auto
              </button>
            </div>
            <p className="text-[10px] text-gray-500 mt-0.5 font-mono">{form.network || "—"}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Pool Start</label>
              <input
                type="text"
                value={form.pool_start}
                onChange={(e) => setForm((p) => ({ ...p, pool_start: e.target.value.replace(/[^0-9.]/g, "") }))}
                placeholder="e.g. 192.168.1.100"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Pool End</label>
              <input
                type="text"
                value={form.pool_end}
                onChange={(e) => setForm((p) => ({ ...p, pool_end: e.target.value.replace(/[^0-9.]/g, "") }))}
                placeholder="e.g. 192.168.1.200"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Gateway</label>
            <input
              type="text"
              value={form.gateway}
              onChange={(e) => setForm((p) => ({ ...p, gateway: e.target.value.replace(/[^0-9.]/g, "") }))}
              placeholder="e.g. 192.168.1.1"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">
                DNS Servers (comma-separated)
              </label>
              <input
                type="text"
                value={form.dns_servers}
                onChange={(e) => setForm((p) => ({ ...p, dns_servers: e.target.value }))}
                placeholder="e.g. 1.1.1.1, 8.8.8.8"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <p className="text-[10px] text-gray-500 mt-0.5">Leave empty to use global DNS settings</p>
            </div>
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">
                Domain Name (override)
              </label>
              <input
                type="text"
                value={form.domain_name}
                onChange={(e) => setForm((p) => ({ ...p, domain_name: e.target.value }))}
                placeholder="Optional override"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">
              NTP Servers (comma-separated, DHCP option 42)
            </label>
            <input
              type="text"
              value={form.ntp_servers}
              onChange={(e) => setForm((p) => ({ ...p, ntp_servers: e.target.value }))}
              placeholder="e.g. 172.29.69.1"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            <p className="text-[10px] text-gray-500 mt-0.5">Leave empty to inherit from global NTP servers</p>
          </div>

          {/* Subnet type */}
          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Subnet Type</label>
            <select
              value={form.subnet_type}
              onChange={(e) => setForm((p) => ({ ...p, subnet_type: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
            >
              <option value="address">Address Allocation</option>
              <option value="prefix-delegation">Prefix Delegation (DHCPv6)</option>
            </select>
          </div>

          {form.subnet_type === "prefix-delegation" && (
            <div>
              <label className="block text-xs text-[var(--text-muted)] mb-1">Delegated Prefix Length</label>
              <input
                type="number"
                value={form.delegated_length}
                onChange={(e) => setForm((p) => ({ ...p, delegated_length: e.target.value }))}
                placeholder="e.g. 56"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
            </div>
          )}

          {/* Lease Timing */}
          <div className="space-y-3">
            <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">Lease Timing</p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">
                  Lease Time (seconds)
                </label>
                <input type="number" value={form.lease_time}
                  onChange={(e) => setForm((p) => ({ ...p, lease_time: e.target.value }))}
                  placeholder="Blank = use global default"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                <p className="text-[10px] text-gray-500 mt-0.5">e.g. 3600 = 1h, 86400 = 1d</p>
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">
                  Max Lease Time (seconds)
                </label>
                <input type="number" value={form.max_lease_time}
                  onChange={(e) => setForm((p) => ({ ...p, max_lease_time: e.target.value }))}
                  placeholder="No cap"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                <p className="text-[10px] text-gray-500 mt-0.5">Maximum lease a client can request</p>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">
                  Renewal Time / T1 (seconds)
                </label>
                <input type="number" value={form.renewal_time}
                  onChange={(e) => setForm((p) => ({ ...p, renewal_time: e.target.value }))}
                  placeholder="Default: 50% of lease"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                <p className="text-[10px] text-gray-500 mt-0.5">When client starts unicast renewal</p>
              </div>
              <div>
                <label className="block text-xs text-[var(--text-muted)] mb-1">
                  Rebinding Time / T2 (seconds)
                </label>
                <input type="number" value={form.rebinding_time}
                  onChange={(e) => setForm((p) => ({ ...p, rebinding_time: e.target.value }))}
                  placeholder="Default: 87.5% of lease"
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                <p className="text-[10px] text-gray-500 mt-0.5">When client broadcasts for any server</p>
              </div>
            </div>
            {form.subnet_type !== "address" && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">
                    Preferred Time (DHCPv6, seconds)
                  </label>
                  <input type="number" value={form.preferred_time}
                    onChange={(e) => setForm((p) => ({ ...p, preferred_time: e.target.value }))}
                    placeholder="Optional"
                    className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                </div>
              </div>
            )}
          </div>

          <div>
            <label className="block text-xs text-[var(--text-muted)] mb-1">Description</label>
            <input
              type="text"
              value={form.description}
              onChange={(e) => setForm((p) => ({ ...p, description: e.target.value }))}
              placeholder="Optional description"
              className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded-md text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Enable toggle */}
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setForm((p) => ({ ...p, enabled: !p.enabled }))}
              className={`relative w-11 h-6 rounded-full transition-colors ${
                form.enabled ? "bg-blue-600" : "bg-gray-600"
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                  form.enabled ? "translate-x-5" : ""
                }`}
              />
            </button>
            <span className="text-sm text-[var(--text-primary)]">Enabled</span>
          </div>

          {/* -- Advanced DHCP option overrides ------------------ */}
          <div className="space-y-2 pt-2 border-t border-gray-700">
            <div className="flex items-center justify-between">
              <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">
                Advanced DHCP options
              </label>
              <button
                type="button"
                onClick={() => setForm((p) => ({
                  ...p,
                  options: [...p.options, { code: 0, value_type: "string", value: "" }],
                }))}
                className="text-xs px-2 py-1 bg-gray-700 hover:bg-gray-600 text-white rounded-md"
              >
                + Add option
              </button>
            </div>
            {form.options.length === 0 ? (
              <p className="text-[10px] text-gray-500">
                No overrides. Common codes: 66 (TFTP server), 67 (Bootfile), 252 (WPAD URL).
                Reserved (0, 1, 28, 51, 53, 54, 58, 59, 255) and typed-field codes (3, 6, 15, 42) are blocked.
              </p>
            ) : (
              <div className="space-y-2">
                {form.options.map((opt, idx) => {
                  const err = validateOption(opt);
                  return (
                    <div key={idx} className="space-y-1">
                      <div className="flex items-center gap-2">
                        <input
                          type="number"
                          min={0}
                          max={255}
                          value={opt.code}
                          onChange={(e) => {
                            const n = Number(e.target.value);
                            setForm((p) => ({
                              ...p,
                              options: p.options.map((o, i) => i === idx ? { ...o, code: Number.isFinite(n) ? n : 0 } : o),
                            }));
                          }}
                          placeholder="code"
                          className="w-20 px-2 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono focus:outline-none focus:border-blue-500"
                          aria-label={`Option ${idx + 1} code`}
                        />
                        <select
                          value={opt.value_type}
                          onChange={(e) => {
                            const t = e.target.value as DhcpOptionOverride["value_type"];
                            setForm((p) => ({
                              ...p,
                              options: p.options.map((o, i) => i === idx ? { ...o, value_type: t } : o),
                            }));
                          }}
                          className="w-24 px-2 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-white focus:outline-none focus:border-blue-500"
                          aria-label={`Option ${idx + 1} type`}
                        >
                          {OPTION_VALUE_TYPES.map((t) => (
                            <option key={t} value={t}>{t}</option>
                          ))}
                        </select>
                        <input
                          type="text"
                          value={opt.value}
                          onChange={(e) => {
                            const v = e.target.value;
                            setForm((p) => ({
                              ...p,
                              options: p.options.map((o, i) => i === idx ? { ...o, value: v } : o),
                            }));
                          }}
                          placeholder={
                            opt.value_type === "ip" ? "e.g. 10.0.0.1" :
                            opt.value_type === "ips" ? "e.g. 10.0.0.1, 10.0.0.2" :
                            opt.value_type === "hex" ? "e.g. deadbeef" :
                            opt.value_type === "string" ? "text value" :
                            opt.value_type
                          }
                          className="flex-1 px-2 py-1.5 bg-gray-900 border border-gray-700 rounded-md text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-blue-500"
                          aria-label={`Option ${idx + 1} value`}
                        />
                        <button
                          type="button"
                          onClick={() => setForm((p) => ({
                            ...p,
                            options: p.options.filter((_, i) => i !== idx),
                          }))}
                          className="p-1.5 text-gray-500 hover:text-red-400"
                          aria-label={`Remove option ${idx + 1}`}
                        >
                          ×
                        </button>
                      </div>
                      {err && (
                        <p className="text-[10px] text-red-400 ml-1">{err}</p>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* -- Trusted relay agents ---------------------------- */}
          <div className="space-y-2 pt-2 border-t border-gray-700">
            <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider">
              Trusted relay agents
            </label>
            <div className="flex flex-wrap items-center gap-2 min-h-[2.5rem] px-2 py-1.5 bg-gray-900 border border-gray-700 rounded-md focus-within:border-blue-500">
              {form.trusted_relays.map((ip) => (
                <span
                  key={ip}
                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-blue-500/20 border border-blue-500/30 text-blue-300 text-xs font-mono rounded"
                >
                  {ip}
                  <button
                    type="button"
                    onClick={() => removeRelay(ip)}
                    className="text-blue-400 hover:text-red-400"
                    aria-label={`Remove ${ip}`}
                  >
                    ×
                  </button>
                </span>
              ))}
              <input
                type="text"
                value={relayDraft}
                onChange={(e) => {
                  setRelayDraft(e.target.value.replace(/[^0-9.]/g, ""));
                  if (relayError) setRelayError(null);
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === ",") {
                    e.preventDefault();
                    addRelay();
                  } else if (e.key === "Backspace" && !relayDraft && form.trusted_relays.length > 0) {
                    removeRelay(form.trusted_relays[form.trusted_relays.length - 1]);
                  }
                }}
                onBlur={() => { if (relayDraft.trim()) addRelay(); }}
                placeholder={form.trusted_relays.length === 0 ? "e.g. 172.29.69.5 (press Enter)" : ""}
                className="flex-1 min-w-[8rem] bg-transparent text-sm text-white font-mono placeholder-gray-500 focus:outline-none"
              />
            </div>
            {relayError ? (
              <p className="text-[10px] text-red-400 mt-0.5">{relayError}</p>
            ) : (
              <p className="text-[10px] text-gray-500 mt-0.5">
                Relay agents outside this list will be silently dropped. Leave empty to trust any relay.
                The global &quot;Accept DHCP relay&quot; switch lives in DHCP settings.
              </p>
            )}
          </div>
        </div>

        <div className="flex justify-end gap-3 pt-2">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
          >
            Cancel
          </button>
          <button
            onClick={() => onSubmit(form)}
            disabled={submitting}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
          >
            {submitting ? "Saving..." : editing ? "Update Subnet" : "Create Subnet"}
          </button>
        </div>
      </div>
    </div>
  );
}
