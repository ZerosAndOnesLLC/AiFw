"use client";

import { useState, useEffect, useCallback } from "react";
import { validateCIDR, validateIP, isValidIPv4 } from "@/lib/validate";

/* -- Types ---------------------------------------------------------- */

interface DhcpSubnet {
  id: string;
  network: string;
  pool_start: string;
  pool_end: string;
  gateway: string;
  dns_servers?: string[];
  domain_name?: string;
  lease_time?: number;
  max_lease_time?: number;
  renewal_time?: number;
  rebinding_time?: number;
  preferred_time?: number;
  subnet_type: string;
  delegated_length?: number;
  enabled: boolean;
  description?: string;
  accept_relayed?: boolean;
  trusted_relays?: string[];
  created_at: string;
}

interface SubnetForm {
  network: string;
  pool_start: string;
  pool_end: string;
  gateway: string;
  dns_servers: string;
  domain_name: string;
  lease_time: string;
  max_lease_time: string;
  renewal_time: string;
  rebinding_time: string;
  preferred_time: string;
  subnet_type: string;
  delegated_length: string;
  description: string;
  enabled: boolean;
  accept_relayed: boolean;
  trusted_relays: string[];
}

const defaultForm: SubnetForm = {
  network: "",
  pool_start: "",
  pool_end: "",
  gateway: "",
  dns_servers: "",
  domain_name: "",
  lease_time: "",
  max_lease_time: "",
  renewal_time: "",
  rebinding_time: "",
  preferred_time: "",
  subnet_type: "address",
  delegated_length: "",
  description: "",
  enabled: true,
  accept_relayed: true,
  trusted_relays: [],
};

// Loopback: any IPv4 starting with 127.
function isLoopbackV4(ip: string): boolean {
  return ip.trim().startsWith("127.");
}

function fmtSeconds(s: number): string {
  if (s >= 86400 && s % 86400 === 0) return `${s / 86400}d`;
  if (s >= 3600 && s % 3600 === 0) return `${s / 3600}h`;
  if (s >= 60 && s % 60 === 0) return `${s / 60}m`;
  return `${s}s`;
}

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/* -- Page ------------------------------------------------------------ */

export default function DhcpSubnetsPage() {
  const [subnets, setSubnets] = useState<DhcpSubnet[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<{ type: "success" | "error"; msg: string } | null>(null);

  // Modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [form, setForm] = useState<SubnetForm>(defaultForm);
  const [submitting, setSubmitting] = useState(false);
  const [relayDraft, setRelayDraft] = useState("");
  const [relayError, setRelayError] = useState<string | null>(null);

  // Delete confirm
  const [deleteId, setDeleteId] = useState<string | null>(null);

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchSubnets = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/dhcp/v4/subnets", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setSubnets(body.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load subnets");
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchSubnets();
      setLoading(false);
    })();
  }, [fetchSubnets]);

  /* -- Modal -------------------------------------------------------- */

  const openCreate = () => {
    setEditingId(null);
    setForm(defaultForm);
    setRelayDraft("");
    setRelayError(null);
    setModalOpen(true);
  };

  const openEdit = (subnet: DhcpSubnet) => {
    setEditingId(subnet.id);
    setForm({
      network: subnet.network,
      pool_start: subnet.pool_start,
      pool_end: subnet.pool_end,
      gateway: subnet.gateway,
      dns_servers: Array.isArray(subnet.dns_servers) ? subnet.dns_servers.join(", ") : (subnet.dns_servers || ""),
      domain_name: subnet.domain_name || "",
      lease_time: subnet.lease_time ? String(subnet.lease_time) : "",
      max_lease_time: subnet.max_lease_time ? String(subnet.max_lease_time) : "",
      renewal_time: subnet.renewal_time ? String(subnet.renewal_time) : "",
      rebinding_time: subnet.rebinding_time ? String(subnet.rebinding_time) : "",
      preferred_time: subnet.preferred_time ? String(subnet.preferred_time) : "",
      subnet_type: subnet.subnet_type || "address",
      delegated_length: subnet.delegated_length ? String(subnet.delegated_length) : "",
      description: subnet.description || "",
      enabled: subnet.enabled,
      accept_relayed: subnet.accept_relayed ?? true,
      trusted_relays: Array.isArray(subnet.trusted_relays) ? [...subnet.trusted_relays] : [],
    });
    setRelayDraft("");
    setRelayError(null);
    setModalOpen(true);
  };

  const closeModal = () => {
    setModalOpen(false);
    setEditingId(null);
    setForm(defaultForm);
    setRelayDraft("");
    setRelayError(null);
  };

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

  const handleSubmit = async () => {
    if (!form.network.trim() || !form.pool_start.trim() || !form.pool_end.trim() || !form.gateway.trim()) {
      showFeedback("error", "Network, pool start, pool end, and gateway are required");
      return;
    }

    // Client-side validation
    const errors: string[] = [];
    { const e = validateCIDR(form.network, "Network"); if (e) errors.push(e); }
    { const e = validateIP(form.pool_start, "Pool start"); if (e) errors.push(e); }
    { const e = validateIP(form.pool_end, "Pool end"); if (e) errors.push(e); }
    { const e = validateIP(form.gateway, "Gateway"); if (e) errors.push(e); }
    // DNS servers — each entry must be a valid IP
    if (form.dns_servers.trim()) {
      const bad = form.dns_servers.split(",").map((s) => s.trim()).filter(Boolean)
        .filter((ip) => !isValidIPv4(ip) && !/^[0-9a-fA-F:]+$/.test(ip));
      if (bad.length > 0) errors.push(`DNS servers: invalid ${bad.join(", ")}`);
    }
    // Trusted relays — revalidate saved chips (in case they bypassed per-chip check)
    if (form.accept_relayed) {
      const bad = form.trusted_relays.filter((ip) => !isValidIPv4(ip) || isLoopbackV4(ip));
      if (bad.length > 0) errors.push(`Trusted relays: invalid ${bad.join(", ")}`);
    }
    if (errors.length > 0) { showFeedback("error", errors.join(". ")); return; }

    setSubmitting(true);
    try {
      const payload: Record<string, unknown> = {
        network: form.network.trim(),
        pool_start: form.pool_start.trim(),
        pool_end: form.pool_end.trim(),
        gateway: form.gateway.trim(),
        subnet_type: form.subnet_type,
        enabled: form.enabled,
        accept_relayed: form.accept_relayed,
        trusted_relays: form.accept_relayed ? form.trusted_relays : [],
      };
      if (form.dns_servers.trim()) {
        payload.dns_servers = form.dns_servers
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean);
      }
      if (form.domain_name.trim()) payload.domain_name = form.domain_name.trim();
      if (form.lease_time.trim()) payload.lease_time = Number(form.lease_time);
      if (form.max_lease_time.trim()) payload.max_lease_time = Number(form.max_lease_time);
      if (form.renewal_time.trim()) payload.renewal_time = Number(form.renewal_time);
      if (form.rebinding_time.trim()) payload.rebinding_time = Number(form.rebinding_time);
      if (form.preferred_time.trim()) payload.preferred_time = Number(form.preferred_time);
      if (form.delegated_length.trim()) payload.delegated_length = Number(form.delegated_length);
      if (form.description.trim()) payload.description = form.description.trim();

      const url = editingId
        ? `/api/v1/dhcp/v4/subnets/${editingId}`
        : "/api/v1/dhcp/v4/subnets";
      const method = editingId ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      showFeedback("success", editingId ? "Subnet updated" : "Subnet created");
      closeModal();
      await fetchSubnets();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save subnet");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      const res = await fetch(`/api/v1/dhcp/v4/subnets/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Subnet deleted");
      setDeleteId(null);
      await fetchSubnets();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete subnet");
    }
  };

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading subnets...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">DHCP Subnets</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Manage DHCPv4/v6 subnets and address pools
          </p>
        </div>
        <button
          onClick={openCreate}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md flex items-center gap-2"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Subnet
        </button>
      </div>

      {/* Feedback */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* -- Table --------------------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {subnets.length === 0 ? (
          <div className="px-6 py-8 text-center text-sm text-[var(--text-muted)]">
            No subnets configured. Click &quot;Add Subnet&quot; to create one.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs text-[var(--text-muted)] uppercase">
                  <th className="px-6 py-3">Network</th>
                  <th className="px-6 py-3">Type</th>
                  <th className="px-6 py-3">Pool Range</th>
                  <th className="px-6 py-3">Gateway</th>
                  <th className="px-6 py-3">Lease Time</th>
                  <th className="px-6 py-3">Status</th>
                  <th className="px-6 py-3">Created</th>
                  <th className="px-6 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {subnets.map((subnet) => (
                  <tr
                    key={subnet.id}
                    className="border-b border-[var(--border)] hover:bg-white/[0.02] cursor-pointer"
                    onClick={() => openEdit(subnet)}
                  >
                    <td className="px-6 py-3 text-[var(--text-primary)] font-mono text-xs font-medium">
                      {subnet.network}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`text-xs px-2 py-0.5 rounded-full border ${
                        subnet.subnet_type === "prefix-delegation"
                          ? "bg-purple-500/20 text-purple-400 border-purple-500/30"
                          : subnet.network.includes(":")
                            ? "bg-cyan-500/20 text-cyan-400 border-cyan-500/30"
                            : "bg-blue-500/20 text-blue-400 border-blue-500/30"
                      }`}>
                        {subnet.subnet_type === "prefix-delegation" ? "PD" : subnet.network.includes(":") ? "v6" : "v4"}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {subnet.subnet_type === "prefix-delegation"
                        ? `/${subnet.delegated_length || "?"}`
                        : `${subnet.pool_start} - ${subnet.pool_end}`}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)] font-mono text-xs">
                      {subnet.gateway}
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {subnet.lease_time ? fmtSeconds(subnet.lease_time) : "Default"}
                      {subnet.renewal_time && <span className="text-[10px] text-gray-500 ml-1">(T1:{fmtSeconds(subnet.renewal_time)})</span>}
                    </td>
                    <td className="px-6 py-3">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full border ${
                          subnet.enabled
                            ? "bg-green-500/20 text-green-400 border-green-500/30"
                            : "bg-gray-500/20 text-gray-400 border-gray-500/30"
                        }`}
                      >
                        {subnet.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-[var(--text-secondary)]">
                      {fmtDate(subnet.created_at)}
                    </td>
                    <td className="px-6 py-3" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setDeleteId(subnet.id)}
                          title="Delete Subnet"
                          className="p-1.5 text-[var(--text-muted)] hover:text-red-400 rounded hover:bg-red-500/10"
                        >
                          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* -- Create/Edit Modal --------------------------------------- */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-lg w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">
              {editingId ? "Edit Subnet" : "Add Subnet"}
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

              {/* -- DHCP Relay --------------------------------------- */}
              <div className="space-y-3 pt-2 border-t border-gray-700">
                <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">DHCP Relay</p>

                <div className="flex items-center gap-3">
                  <button
                    type="button"
                    onClick={() => setForm((p) => ({ ...p, accept_relayed: !p.accept_relayed }))}
                    className={`relative w-11 h-6 rounded-full transition-colors ${
                      form.accept_relayed ? "bg-blue-600" : "bg-gray-600"
                    }`}
                  >
                    <span
                      className={`absolute top-0.5 left-0.5 w-5 h-5 bg-white rounded-full transition-transform ${
                        form.accept_relayed ? "translate-x-5" : ""
                      }`}
                    />
                  </button>
                  <span className="text-sm text-[var(--text-primary)]">Accept DHCP relay</span>
                </div>
                <p className="text-[10px] text-gray-500 -mt-1">
                  When off, all relayed packets for this scope are dropped.
                </p>

                <div className={form.accept_relayed ? "" : "opacity-50 pointer-events-none"}>
                  <label className="block text-xs text-[var(--text-muted)] mb-1">
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
                      disabled={!form.accept_relayed}
                      className="flex-1 min-w-[8rem] bg-transparent text-sm text-white font-mono placeholder-gray-500 focus:outline-none"
                    />
                  </div>
                  {relayError ? (
                    <p className="text-[10px] text-red-400 mt-0.5">{relayError}</p>
                  ) : (
                    <p className="text-[10px] text-gray-500 mt-0.5">
                      Relay agents outside this list will be silently dropped. Leave empty to trust any relay.
                    </p>
                  )}
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={closeModal}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50"
              >
                {submitting ? "Saving..." : editingId ? "Update Subnet" : "Create Subnet"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* -- Delete Confirm Modal ------------------------------------ */}
      {deleteId && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-sm w-full mx-4 space-y-4">
            <h3 className="text-lg font-semibold text-white">Delete Subnet</h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Are you sure you want to delete this subnet? All associated reservations and leases
              will be affected.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setDeleteId(null)}
                className="px-4 py-2 text-sm text-[var(--text-muted)] hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDelete(deleteId)}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white text-sm rounded-md"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
