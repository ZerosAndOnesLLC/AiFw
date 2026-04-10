"use client";

import { useState, useEffect, useCallback } from "react";

/* ────────────────────────── Types ────────────────────────── */

interface WgTunnel {
  id: string;
  name: string;
  interface_name: string;
  listen_port: number;
  address: string;
  private_key: string;
  public_key: string;
  dns: string | null;
  mtu: number | null;
  listen_interface: string | null;
  status: string;
  created_at: string;
}

interface WgPeer {
  id: string;
  tunnel_id: string;
  name: string;
  public_key: string;
  preshared_key: string | null;
  client_private_key: string | null;
  endpoint: string | null;
  allowed_ips: string;
  persistent_keepalive: number | null;
  created_at: string;
}

interface IpsecSa {
  id: string;
  name: string;
  local_addr: string;
  remote_addr: string;
  protocol: string;
  mode: string;
  spi_in: string;
  spi_out: string;
  status: string;
  created_at: string;
}

/* ────────────────────────── Helpers ────────────────────────── */

function authHeaders(): Record<string, string> {
  const token = typeof window !== "undefined" ? localStorage.getItem("aifw_token") : null;
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function apiFetch<T>(url: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(url, { ...opts, headers: { ...authHeaders(), ...opts?.headers } });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(body || `Request failed (${res.status})`);
  }
  return res.json();
}

/* ────────────────────────── Default form values ────────────────────────── */

const defaultWgForm = {
  name: "",
  listen_port: "",
  address: "",
  private_key: "",
  dns: "",
  mtu: "",
  listen_interface: "any",
};

const defaultPeerForm = {
  name: "",
  public_key: "",
  preshared_key: "",
  auto_generate_key: true,
  endpoint: "",
  allowed_ips: "",
  keepalive: "",
};

const defaultIpsecForm = {
  name: "",
  local_addr: "",
  remote_addr: "",
  protocol: "esp",
  mode: "tunnel",
};

/* ────────────────────────── Shared styles ────────────────────────── */

const inputCls =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
const selectCls =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
const labelCls = "block text-xs text-gray-400 mb-1";
const btnPrimary =
  "px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors";
const btnCancel =
  "px-4 py-1.5 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors";

/* ────────────────────────── Status badge ────────────────────────── */

function StatusBadge({ status }: { status: string }) {
  const isUp = status === "up" || status === "active" || status === "established";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border text-[10px] px-2 py-0.5 font-medium uppercase tracking-wider ${
        isUp
          ? "bg-green-500/15 text-green-400 border-green-500/30"
          : "bg-red-500/15 text-red-400 border-red-500/30"
      }`}
    >
      <span className={`inline-block w-1.5 h-1.5 rounded-full ${isUp ? "bg-green-400" : "bg-red-400"}`} />
      {status}
    </span>
  );
}

/* ────────────────────────── Delete icon ────────────────────────── */

function DeleteButton({ onClick, title }: { onClick: () => void; title?: string }) {
  return (
    <button
      onClick={onClick}
      className="p-1.5 text-gray-500 hover:text-red-400 transition-colors rounded hover:bg-gray-700"
      title={title || "Delete"}
    >
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
        />
      </svg>
    </button>
  );
}

/* ────────────────────────── Edit icon ────────────────────────── */

function EditButton({ onClick, title }: { onClick: () => void; title?: string }) {
  return (
    <button
      onClick={onClick}
      className="p-1.5 text-gray-500 hover:text-blue-400 transition-colors rounded hover:bg-gray-700"
      title={title || "Edit"}
    >
      <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"
        />
      </svg>
    </button>
  );
}

/* ────────────────────────── Chevron icon ────────────────────────── */

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      className={`w-5 h-5 text-gray-400 transition-transform duration-200 ${open ? "rotate-180" : ""}`}
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  );
}

/* ════════════════════════════════════════════════════════════
   Main Page Component
   ════════════════════════════════════════════════════════════ */

export default function VpnPage() {
  /* ── WireGuard state ── */
  const [tunnels, setTunnels] = useState<WgTunnel[]>([]);
  const [peersByTunnel, setPeersByTunnel] = useState<Record<string, WgPeer[]>>({});
  const [wgLoading, setWgLoading] = useState(true);
  const [wgOpen, setWgOpen] = useState(true);
  const [expandedTunnel, setExpandedTunnel] = useState<string | null>(null);
  const [showWgForm, setShowWgForm] = useState(false);
  const [wgForm, setWgForm] = useState(defaultWgForm);
  const [editingWgId, setEditingWgId] = useState<string | null>(null);
  const [wgSubmitting, setWgSubmitting] = useState(false);

  /* ── Peer form state ── */
  const [showPeerForm, setShowPeerForm] = useState<string | null>(null); // tunnel_id or null
  const [peerForm, setPeerForm] = useState(defaultPeerForm);
  const [peerSubmitting, setPeerSubmitting] = useState(false);

  /* ── IPsec state ── */
  const [ipsecSas, setIpsecSas] = useState<IpsecSa[]>([]);
  const [ipsecLoading, setIpsecLoading] = useState(true);
  const [ipsecOpen, setIpsecOpen] = useState(true);
  const [showIpsecForm, setShowIpsecForm] = useState(false);
  const [ipsecForm, setIpsecForm] = useState(defaultIpsecForm);
  const [ipsecSubmitting, setIpsecSubmitting] = useState(false);

  /* ── Config modal ── */
  const [configModal, setConfigModal] = useState<{ peerName: string; fullTunnel: string; splitTunnel: string } | null>(null);
  const [configTab, setConfigTab] = useState<"full" | "split">("full");
  const [configCopied, setConfigCopied] = useState(false);

  /* ── Interfaces (for listen binding dropdown) ── */
  const [interfaces, setInterfaces] = useState<{ name: string; role?: string }[]>([]);

  /* ── Shared ── */
  const [error, setError] = useState<string | null>(null);

  /* ────────────────────────── Fetch helpers ────────────────────────── */

  const fetchTunnels = useCallback(async () => {
    try {
      const res = await apiFetch<{ data: WgTunnel[] }>("/api/v1/vpn/wg");
      setTunnels(res.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load WireGuard tunnels");
    } finally {
      setWgLoading(false);
    }
  }, []);

  const fetchPeers = useCallback(async (tunnelId: string) => {
    try {
      const res = await apiFetch<{ data: WgPeer[] }>(`/api/v1/vpn/wg/${tunnelId}/peers`);
      setPeersByTunnel((prev) => ({ ...prev, [tunnelId]: res.data }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load peers");
    }
  }, []);

  const fetchIpsec = useCallback(async () => {
    try {
      const res = await apiFetch<{ data: IpsecSa[] }>("/api/v1/vpn/ipsec");
      setIpsecSas(res.data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load IPsec SAs");
    } finally {
      setIpsecLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTunnels();
    fetchIpsec();
    apiFetch<{ data: { name: string; role?: string }[] }>("/api/v1/interfaces")
      .then(res => setInterfaces(res.data || []))
      .catch(() => {});
  }, [fetchTunnels, fetchIpsec]);

  /* ────────────────────────── WireGuard CRUD ────────────────────────── */

  const handleExpandTunnel = (tunnelId: string) => {
    if (expandedTunnel === tunnelId) {
      setExpandedTunnel(null);
    } else {
      setExpandedTunnel(tunnelId);
      if (!peersByTunnel[tunnelId]) {
        fetchPeers(tunnelId);
      }
    }
  };

  const handleWgSubmit = async () => {
    if (wgSubmitting) return;
    if (!wgForm.name.trim() || !wgForm.address.trim() || !wgForm.listen_port) return;
    setWgSubmitting(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        name: wgForm.name.trim(),
        listen_port: parseInt(wgForm.listen_port, 10),
        address: wgForm.address.trim(),
      };
      if (wgForm.private_key.trim()) {
        body.private_key = wgForm.private_key.trim();
      }
      if (wgForm.dns.trim()) body.dns = wgForm.dns.trim();
      if (wgForm.mtu.trim()) body.mtu = parseInt(wgForm.mtu, 10);
      if (wgForm.listen_interface && wgForm.listen_interface !== "any") {
        body.listen_interface = wgForm.listen_interface;
      }

      if (editingWgId) {
        await apiFetch(`/api/v1/vpn/wg/${editingWgId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
      } else {
        await apiFetch("/api/v1/vpn/wg", {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      setWgForm(defaultWgForm);
      setEditingWgId(null);
      setShowWgForm(false);
      await fetchTunnels();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save tunnel");
    } finally {
      setWgSubmitting(false);
    }
  };

  const handleEditWg = (tunnel: WgTunnel) => {
    setWgForm({
      name: tunnel.name,
      listen_port: String(tunnel.listen_port),
      address: tunnel.address,
      private_key: "",
      dns: tunnel.dns || "",
      mtu: tunnel.mtu ? String(tunnel.mtu) : "",
      listen_interface: tunnel.listen_interface || "any",
    });
    setEditingWgId(tunnel.id);
    setShowWgForm(true);
  };

  const handleDeleteWg = async (id: string) => {
    setError(null);
    try {
      await apiFetch(`/api/v1/vpn/wg/${id}`, { method: "DELETE" });
      setTunnels((prev) => prev.filter((t) => t.id !== id));
      setPeersByTunnel((prev) => {
        const next = { ...prev };
        delete next[id];
        return next;
      });
      if (expandedTunnel === id) setExpandedTunnel(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete tunnel");
    }
  };

  const handleCancelWg = () => {
    setWgForm(defaultWgForm);
    setEditingWgId(null);
    setShowWgForm(false);
  };

  const handleStartTunnel = async (id: string) => {
    setError(null);
    try {
      await apiFetch(`/api/v1/vpn/wg/${id}/start`, { method: "POST" });
      await fetchTunnels();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start tunnel");
    }
  };

  const handleStopTunnel = async (id: string) => {
    setError(null);
    try {
      await apiFetch(`/api/v1/vpn/wg/${id}/stop`, { method: "POST" });
      await fetchTunnels();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop tunnel");
    }
  };

  const handleAutoAssignIp = async (tunnelId: string) => {
    try {
      const res = await apiFetch<{ next_ip: string }>(`/api/v1/vpn/wg/${tunnelId}/peers/next-ip`);
      setPeerForm((f) => ({ ...f, allowed_ips: res.next_ip }));
    } catch {
      setError("No free IPs in tunnel subnet");
    }
  };

  /* ────────────────────────── Peer CRUD ────────────────────────── */

  const handlePeerSubmit = async (tunnelId: string) => {
    if (peerSubmitting) return;
    if (!peerForm.auto_generate_key && !peerForm.public_key.trim()) return;
    if (!peerForm.allowed_ips.trim()) return;
    setPeerSubmitting(true);
    setError(null);
    try {
      const body: Record<string, unknown> = {
        name: peerForm.name.trim() || null,
        auto_generate_key: peerForm.auto_generate_key,
        allowed_ips: peerForm.allowed_ips.trim(),
        endpoint: peerForm.endpoint.trim() || null,
        keepalive: peerForm.keepalive ? parseInt(peerForm.keepalive, 10) : null,
      };
      if (!peerForm.auto_generate_key) {
        body.public_key = peerForm.public_key.trim();
      }
      if (peerForm.preshared_key.trim()) {
        body.preshared_key = peerForm.preshared_key.trim();
      }
      await apiFetch(`/api/v1/vpn/wg/${tunnelId}/peers`, {
        method: "POST",
        body: JSON.stringify(body),
      });
      setPeerForm(defaultPeerForm);
      setShowPeerForm(null);
      await fetchPeers(tunnelId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add peer");
    } finally {
      setPeerSubmitting(false);
    }
  };

  const handleShowConfig = async (tunnelId: string, peer: WgPeer) => {
    try {
      const res = await apiFetch<{ full_tunnel: string; split_tunnel: string }>(`/api/v1/vpn/wg/${tunnelId}/peers/${peer.id}/config`);
      setConfigModal({ peerName: peer.name || peer.public_key.slice(0, 12), fullTunnel: res.full_tunnel, splitTunnel: res.split_tunnel });
      setConfigTab("full");
      setConfigCopied(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get peer config");
    }
  };

  const handleCopyConfig = () => {
    if (configModal) {
      const text = configTab === "full" ? configModal.fullTunnel : configModal.splitTunnel;
      navigator.clipboard.writeText(text);
      setConfigCopied(true);
      setTimeout(() => setConfigCopied(false), 2000);
    }
  };

  const handleDeletePeer = async (tunnelId: string, peerId: string) => {
    setError(null);
    try {
      await apiFetch(`/api/v1/vpn/wg/${tunnelId}/peers/${peerId}`, { method: "DELETE" });
      setPeersByTunnel((prev) => ({
        ...prev,
        [tunnelId]: (prev[tunnelId] || []).filter((p) => p.id !== peerId),
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete peer");
    }
  };

  /* ────────────────────────── IPsec CRUD ────────────────────────── */

  const handleIpsecSubmit = async () => {
    if (ipsecSubmitting) return;
    if (!ipsecForm.name.trim() || !ipsecForm.local_addr.trim() || !ipsecForm.remote_addr.trim()) return;
    setIpsecSubmitting(true);
    setError(null);
    try {
      await apiFetch("/api/v1/vpn/ipsec", {
        method: "POST",
        body: JSON.stringify({
          name: ipsecForm.name.trim(),
          local_addr: ipsecForm.local_addr.trim(),
          remote_addr: ipsecForm.remote_addr.trim(),
          protocol: ipsecForm.protocol,
          mode: ipsecForm.mode,
        }),
      });
      setIpsecForm(defaultIpsecForm);
      setShowIpsecForm(false);
      await fetchIpsec();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create IPsec SA");
    } finally {
      setIpsecSubmitting(false);
    }
  };

  const handleDeleteIpsec = async (id: string) => {
    setError(null);
    try {
      await apiFetch(`/api/v1/vpn/ipsec/${id}`, { method: "DELETE" });
      setIpsecSas((prev) => prev.filter((sa) => sa.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete IPsec SA");
    }
  };

  /* ════════════════════════════════════════════════════════════
     Render
     ════════════════════════════════════════════════════════════ */

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-2xl font-bold text-white">VPN Management</h1>
        <p className="text-sm text-gray-500">
          WireGuard tunnels and IPsec security associations
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard label="WG Tunnels" value={tunnels.length} color="cyan" />
        <SummaryCard
          label="WG Peers"
          value={Object.values(peersByTunnel).reduce((n, p) => n + p.length, 0)}
          color="blue"
        />
        <SummaryCard label="IPsec SAs" value={ipsecSas.length} color="green" />
        <SummaryCard
          label="Active VPNs"
          value={
            tunnels.filter((t) => t.status === "up").length +
            ipsecSas.filter((s) => s.status === "up" || s.status === "established").length
          }
          color="green"
          subtitle={`of ${tunnels.length + ipsecSas.length} total`}
        />
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-sm text-red-400 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-300">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* ═══════════════ WireGuard Section ═══════════════ */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        {/* Section header */}
        <button
          onClick={() => setWgOpen((o) => !o)}
          className="w-full flex items-center justify-between p-4 hover:bg-gray-750 transition-colors"
        >
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-white">WireGuard Tunnels</h2>
            <span className="text-xs text-gray-500">{tunnels.length} tunnel(s)</span>
          </div>
          <ChevronIcon open={wgOpen} />
        </button>

        {wgOpen && (
          <div className="border-t border-gray-700">
            {/* Add Tunnel button */}
            <div className="px-4 py-3 flex justify-end border-b border-gray-700/50">
              <button
                onClick={() => {
                  if (showWgForm && !editingWgId) {
                    handleCancelWg();
                  } else {
                    setWgForm(defaultWgForm);
                    setEditingWgId(null);
                    setShowWgForm(true);
                  }
                }}
                className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                </svg>
                Add Tunnel
              </button>
            </div>

            {/* Tunnel form */}
            {showWgForm && (
              <div className="px-4 py-4 bg-gray-900/50 border-b border-gray-700">
                <h3 className="text-sm font-semibold text-white mb-3">
                  {editingWgId ? "Edit Tunnel" : "New WireGuard Tunnel"}
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  <div>
                    <label className={labelCls}>Name</label>
                    <input
                      type="text"
                      value={wgForm.name}
                      onChange={(e) => setWgForm((f) => ({ ...f, name: e.target.value }))}
                      placeholder="e.g. wg0-office"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Listen Port</label>
                    <input
                      type="number"
                      value={wgForm.listen_port}
                      onChange={(e) => setWgForm((f) => ({ ...f, listen_port: e.target.value }))}
                      placeholder="51820"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Address (CIDR)</label>
                    <input
                      type="text"
                      value={wgForm.address}
                      onChange={(e) => setWgForm((f) => ({ ...f, address: e.target.value }))}
                      placeholder="10.0.0.1/24"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Listen Interface</label>
                    <select
                      value={wgForm.listen_interface}
                      onChange={(e) => setWgForm((f) => ({ ...f, listen_interface: e.target.value }))}
                      className={selectCls}
                    >
                      <option value="any">Any (all interfaces)</option>
                      {interfaces.map((iface) => (
                        <option key={iface.name} value={iface.name}>
                          {iface.name}{iface.role ? ` (${iface.role})` : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
                  <div>
                    <label className={labelCls}>DNS Servers</label>
                    <input
                      type="text"
                      value={wgForm.dns}
                      onChange={(e) => setWgForm((f) => ({ ...f, dns: e.target.value }))}
                      placeholder="1.1.1.1, 8.8.8.8"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>MTU</label>
                    <input
                      type="number"
                      value={wgForm.mtu}
                      onChange={(e) => setWgForm((f) => ({ ...f, mtu: e.target.value }))}
                      placeholder="1420 (default)"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Private Key (optional)</label>
                    <input
                      type="password"
                      value={wgForm.private_key}
                      onChange={(e) => setWgForm((f) => ({ ...f, private_key: e.target.value }))}
                      placeholder="Auto-generated if empty"
                      className={inputCls}
                    />
                  </div>
                </div>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={handleWgSubmit}
                    disabled={wgSubmitting || !wgForm.name.trim() || !wgForm.address.trim() || !wgForm.listen_port}
                    className={btnPrimary}
                  >
                    {wgSubmitting ? "Saving..." : editingWgId ? "Update Tunnel" : "Create Tunnel"}
                  </button>
                  <button onClick={handleCancelWg} className={btnCancel}>
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* Tunnel list */}
            {wgLoading ? (
              <div className="text-center py-12 text-gray-500">Loading tunnels...</div>
            ) : tunnels.length === 0 ? (
              <div className="text-center py-12 text-gray-500">No WireGuard tunnels configured</div>
            ) : (
              <div className="divide-y divide-gray-700/50">
                {tunnels.map((tunnel) => {
                  const isExpanded = expandedTunnel === tunnel.id;
                  const peers = peersByTunnel[tunnel.id] || [];

                  return (
                    <div key={tunnel.id}>
                      {/* Tunnel card */}
                      <div className="p-4 hover:bg-gray-700/20 transition-colors">
                        <div className="flex items-center justify-between mb-2">
                          <button
                            onClick={() => handleExpandTunnel(tunnel.id)}
                            className="flex items-center gap-3 text-left"
                          >
                            <svg
                              className={`w-4 h-4 text-gray-500 transition-transform duration-200 ${
                                isExpanded ? "rotate-90" : ""
                              }`}
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                              strokeWidth={2}
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                            </svg>
                            <span className="font-medium text-white">{tunnel.name}</span>
                            <StatusBadge status={tunnel.status} />
                          </button>
                          <div className="flex items-center gap-1">
                            {tunnel.status === "up" ? (
                              <button onClick={() => handleStopTunnel(tunnel.id)}
                                className="px-2.5 py-1 text-[10px] font-medium rounded bg-red-600 hover:bg-red-700 text-white transition-colors"
                                title="Stop tunnel">Stop</button>
                            ) : (
                              <button onClick={() => handleStartTunnel(tunnel.id)}
                                className="px-2.5 py-1 text-[10px] font-medium rounded bg-green-600 hover:bg-green-700 text-white transition-colors"
                                title="Start tunnel">Start</button>
                            )}
                            <EditButton onClick={() => handleEditWg(tunnel)} title="Edit tunnel" />
                            <DeleteButton onClick={() => handleDeleteWg(tunnel.id)} title="Delete tunnel" />
                          </div>
                        </div>
                        <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-xs ml-7">
                          <div>
                            <span className="text-gray-500">Interface:</span>{" "}
                            <span className="text-gray-300 font-mono">{tunnel.interface_name}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Port:</span>{" "}
                            <span className="text-gray-300">{tunnel.listen_port}</span>
                          </div>
                          <div>
                            <span className="text-gray-500">Address:</span>{" "}
                            <span className="text-gray-300 font-mono">{tunnel.address}</span>
                          </div>
                          <div className="md:col-span-2">
                            <span className="text-gray-500">Public Key:</span>{" "}
                            <span className="text-gray-300 font-mono truncate">{tunnel.public_key}</span>
                          </div>
                        </div>
                      </div>

                      {/* Expanded peers panel */}
                      {isExpanded && (
                        <div className="bg-gray-900/40 border-t border-gray-700/50 px-4 py-3 ml-4 mr-4 mb-3 rounded-lg">
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-sm font-medium text-gray-300">
                              Peers ({peers.length})
                            </h4>
                            <button
                              onClick={() => {
                                if (showPeerForm === tunnel.id) {
                                  setShowPeerForm(null);
                                  setPeerForm(defaultPeerForm);
                                } else {
                                  setPeerForm(defaultPeerForm);
                                  setShowPeerForm(tunnel.id);
                                }
                              }}
                              className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium rounded bg-green-600 hover:bg-green-700 text-white transition-colors"
                            >
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                              </svg>
                              Add Peer
                            </button>
                          </div>

                          {/* Add peer form */}
                          {showPeerForm === tunnel.id && (
                            <div className="bg-gray-800 border border-gray-700 rounded-lg p-3 mb-3">
                              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                                <div>
                                  <label className={labelCls}>Name</label>
                                  <input
                                    type="text"
                                    value={peerForm.name}
                                    onChange={(e) => setPeerForm((f) => ({ ...f, name: e.target.value }))}
                                    placeholder="e.g. laptop, phone"
                                    className={inputCls}
                                  />
                                </div>
                                <div>
                                  <label className={labelCls}>Client IP</label>
                                  <div className="flex gap-1">
                                    <input
                                      type="text"
                                      value={peerForm.allowed_ips}
                                      onChange={(e) => setPeerForm((f) => ({ ...f, allowed_ips: e.target.value }))}
                                      placeholder="10.10.0.2/32"
                                      className={inputCls}
                                    />
                                    <button type="button" onClick={() => handleAutoAssignIp(tunnel.id)}
                                      className="px-2 py-1 text-[10px] font-medium rounded bg-purple-600 hover:bg-purple-700 text-white whitespace-nowrap transition-colors"
                                      title="Auto-assign next free IP">Auto</button>
                                  </div>
                                </div>
                                <div>
                                  <label className={labelCls}>Keepalive (sec)</label>
                                  <input
                                    type="number"
                                    value={peerForm.keepalive}
                                    onChange={(e) => setPeerForm((f) => ({ ...f, keepalive: e.target.value }))}
                                    placeholder="25"
                                    className={inputCls}
                                  />
                                </div>
                              </div>
                              <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-3">
                                <div className="flex items-end pb-0.5">
                                  <label className="flex items-center gap-2 cursor-pointer select-none text-sm text-gray-300">
                                    <input
                                      type="checkbox"
                                      checked={peerForm.auto_generate_key}
                                      onChange={(e) => setPeerForm((f) => ({ ...f, auto_generate_key: e.target.checked }))}
                                      className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                                    />
                                    Auto-generate keypair
                                  </label>
                                </div>
                                {!peerForm.auto_generate_key && (
                                  <div>
                                    <label className={labelCls}>Public Key</label>
                                    <input
                                      type="text"
                                      value={peerForm.public_key}
                                      onChange={(e) => setPeerForm((f) => ({ ...f, public_key: e.target.value }))}
                                      placeholder="Peer public key"
                                      className={inputCls}
                                    />
                                  </div>
                                )}
                                <div>
                                  <label className={labelCls}>Endpoint (optional)</label>
                                  <input
                                    type="text"
                                    value={peerForm.endpoint}
                                    onChange={(e) => setPeerForm((f) => ({ ...f, endpoint: e.target.value }))}
                                    placeholder="1.2.3.4:51820"
                                    className={inputCls}
                                  />
                                </div>
                              </div>
                              {peerForm.auto_generate_key && (
                                <p className="text-[10px] text-green-400 mt-2">
                                  A keypair will be generated automatically. After creating the peer, click the Config button to get a ready-to-use .conf file.
                                </p>
                              )}
                              <div className="flex gap-2 mt-3">
                                <button
                                  onClick={() => handlePeerSubmit(tunnel.id)}
                                  disabled={peerSubmitting || (!peerForm.auto_generate_key && !peerForm.public_key.trim()) || !peerForm.allowed_ips.trim()}
                                  className={btnPrimary}
                                >
                                  {peerSubmitting ? "Adding..." : "Add Peer"}
                                </button>
                                <button
                                  onClick={() => {
                                    setShowPeerForm(null);
                                    setPeerForm(defaultPeerForm);
                                  }}
                                  className={btnCancel}
                                >
                                  Cancel
                                </button>
                              </div>
                            </div>
                          )}

                          {/* Peer list */}
                          {peers.length === 0 ? (
                            <p className="text-xs text-gray-500 py-2">No peers configured for this tunnel.</p>
                          ) : (
                            <div className="overflow-x-auto">
                              <table className="w-full text-xs">
                                <thead>
                                  <tr className="border-b border-gray-700/50">
                                    <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
                                      Name
                                    </th>
                                    <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
                                      Public Key
                                    </th>
                                    <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
                                      Allowed IPs
                                    </th>
                                    <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
                                      Endpoint
                                    </th>
                                    <th className="text-left py-2 px-2 text-[10px] font-medium text-gray-500 uppercase tracking-wider">
                                      Keepalive
                                    </th>
                                    <th className="w-20" />
                                  </tr>
                                </thead>
                                <tbody>
                                  {peers.map((peer) => (
                                    <tr key={peer.id} className="border-b border-gray-700/30 hover:bg-gray-800/50">
                                      <td className="py-2 px-2 text-white font-medium">
                                        {peer.name || "-"}
                                      </td>
                                      <td className="py-2 px-2 font-mono text-gray-300 truncate max-w-[160px]">
                                        {peer.public_key.slice(0, 16)}...
                                      </td>
                                      <td className="py-2 px-2 font-mono text-gray-300">
                                        {peer.allowed_ips}
                                      </td>
                                      <td className="py-2 px-2 font-mono text-gray-400">
                                        {peer.endpoint || "-"}
                                      </td>
                                      <td className="py-2 px-2 text-gray-400">
                                        {peer.persistent_keepalive != null ? `${peer.persistent_keepalive}s` : "off"}
                                      </td>
                                      <td className="py-2 px-1">
                                        <div className="flex items-center gap-0.5">
                                          <button
                                            onClick={() => handleShowConfig(tunnel.id, peer)}
                                            className="p-1.5 text-gray-500 hover:text-green-400 transition-colors rounded hover:bg-gray-700"
                                            title="Show client config"
                                          >
                                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                                              <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
                                            </svg>
                                          </button>
                                          <DeleteButton
                                            onClick={() => handleDeletePeer(tunnel.id, peer.id)}
                                            title="Delete peer"
                                          />
                                        </div>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* ═══════════════ IPsec Section ═══════════════ */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
        {/* Section header */}
        <button
          onClick={() => setIpsecOpen((o) => !o)}
          className="w-full flex items-center justify-between p-4 hover:bg-gray-750 transition-colors"
        >
          <div className="flex items-center gap-3">
            <h2 className="text-lg font-semibold text-white">IPsec Security Associations</h2>
            <span className="text-xs text-gray-500">{ipsecSas.length} SA(s)</span>
          </div>
          <ChevronIcon open={ipsecOpen} />
        </button>

        {ipsecOpen && (
          <div className="border-t border-gray-700">
            {/* Add IPsec SA button */}
            <div className="px-4 py-3 flex justify-end border-b border-gray-700/50">
              <button
                onClick={() => {
                  if (showIpsecForm) {
                    setShowIpsecForm(false);
                    setIpsecForm(defaultIpsecForm);
                  } else {
                    setIpsecForm(defaultIpsecForm);
                    setShowIpsecForm(true);
                  }
                }}
                className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white transition-colors"
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                </svg>
                Add IPsec SA
              </button>
            </div>

            {/* IPsec form */}
            {showIpsecForm && (
              <div className="px-4 py-4 bg-gray-900/50 border-b border-gray-700">
                <h3 className="text-sm font-semibold text-white mb-3">New IPsec SA</h3>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
                  <div>
                    <label className={labelCls}>Name</label>
                    <input
                      type="text"
                      value={ipsecForm.name}
                      onChange={(e) => setIpsecForm((f) => ({ ...f, name: e.target.value }))}
                      placeholder="e.g. office-vpn"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Local Address</label>
                    <input
                      type="text"
                      value={ipsecForm.local_addr}
                      onChange={(e) => setIpsecForm((f) => ({ ...f, local_addr: e.target.value }))}
                      placeholder="203.0.113.1"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Remote Address</label>
                    <input
                      type="text"
                      value={ipsecForm.remote_addr}
                      onChange={(e) => setIpsecForm((f) => ({ ...f, remote_addr: e.target.value }))}
                      placeholder="198.51.100.1"
                      className={inputCls}
                    />
                  </div>
                  <div>
                    <label className={labelCls}>Protocol</label>
                    <select
                      value={ipsecForm.protocol}
                      onChange={(e) => setIpsecForm((f) => ({ ...f, protocol: e.target.value }))}
                      className={selectCls}
                    >
                      <option value="esp">ESP</option>
                      <option value="ah">AH</option>
                    </select>
                  </div>
                  <div>
                    <label className={labelCls}>Mode</label>
                    <select
                      value={ipsecForm.mode}
                      onChange={(e) => setIpsecForm((f) => ({ ...f, mode: e.target.value }))}
                      className={selectCls}
                    >
                      <option value="tunnel">Tunnel</option>
                      <option value="transport">Transport</option>
                    </select>
                  </div>
                </div>
                <div className="flex gap-2 mt-3">
                  <button
                    onClick={handleIpsecSubmit}
                    disabled={
                      ipsecSubmitting ||
                      !ipsecForm.name.trim() ||
                      !ipsecForm.local_addr.trim() ||
                      !ipsecForm.remote_addr.trim()
                    }
                    className={btnPrimary}
                  >
                    {ipsecSubmitting ? "Creating..." : "Create SA"}
                  </button>
                  <button
                    onClick={() => {
                      setShowIpsecForm(false);
                      setIpsecForm(defaultIpsecForm);
                    }}
                    className={btnCancel}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {/* IPsec table */}
            {ipsecLoading ? (
              <div className="text-center py-12 text-gray-500">Loading IPsec SAs...</div>
            ) : ipsecSas.length === 0 ? (
              <div className="text-center py-12 text-gray-500">No IPsec security associations configured</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Name
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Local
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Remote
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-20">
                        Protocol
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                        Mode
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                        SPI In
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider">
                        SPI Out
                      </th>
                      <th className="text-left py-3 px-3 text-xs font-medium text-gray-500 uppercase tracking-wider w-24">
                        Status
                      </th>
                      <th className="w-12" />
                    </tr>
                  </thead>
                  <tbody>
                    {ipsecSas.map((sa) => (
                      <tr
                        key={sa.id}
                        className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                      >
                        <td className="py-2.5 px-3 font-medium text-white">{sa.name}</td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-300">{sa.local_addr}</td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-300">{sa.remote_addr}</td>
                        <td className="py-2.5 px-3 text-gray-400 uppercase text-xs">{sa.protocol}</td>
                        <td className="py-2.5 px-3 text-gray-400 text-xs">{sa.mode}</td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-400">{sa.spi_in}</td>
                        <td className="py-2.5 px-3 font-mono text-xs text-gray-400">{sa.spi_out}</td>
                        <td className="py-2.5 px-3">
                          <StatusBadge status={sa.status} />
                        </td>
                        <td className="py-2.5 px-2">
                          <DeleteButton onClick={() => handleDeleteIpsec(sa.id)} title="Delete SA" />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      {/* ═══════════════ Config Modal ═══════════════ */}
      {configModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={() => setConfigModal(null)} />
          <div className="relative w-full max-w-2xl bg-gray-800 border border-gray-700 rounded-xl shadow-2xl m-4">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="text-lg font-semibold text-white">
                Client Config — {configModal.peerName}
              </h3>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopyConfig}
                  className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                    configCopied
                      ? "bg-green-600 text-white"
                      : "bg-blue-600 hover:bg-blue-700 text-white"
                  }`}
                >
                  <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    {configCopied ? (
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    ) : (
                      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 17.25v3.375c0 .621-.504 1.125-1.125 1.125h-9.75a1.125 1.125 0 01-1.125-1.125V7.875c0-.621.504-1.125 1.125-1.125H6.75a9.06 9.06 0 011.5.124m7.5 10.376h3.375c.621 0 1.125-.504 1.125-1.125V11.25c0-4.46-3.243-8.161-7.5-8.876a9.06 9.06 0 00-1.5-.124H9.375c-.621 0-1.125.504-1.125 1.125v3.5m7.5 10.375H9.375a1.125 1.125 0 01-1.125-1.125v-9.25m12 6.625v-1.875a3.375 3.375 0 00-3.375-3.375h-1.5a1.125 1.125 0 01-1.125-1.125v-1.5a3.375 3.375 0 00-3.375-3.375H9.75" />
                    )}
                  </svg>
                  {configCopied ? "Copied!" : "Copy"}
                </button>
                <button
                  onClick={() => setConfigModal(null)}
                  className="p-1.5 text-gray-400 hover:text-white transition-colors rounded hover:bg-gray-700"
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>
            <div className="p-6">
              {/* Full / Split tabs */}
              <div className="flex gap-2 mb-3">
                <button onClick={() => { setConfigTab("full"); setConfigCopied(false); }}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                    configTab === "full"
                      ? "bg-blue-600/20 border-blue-500/40 text-blue-400"
                      : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"
                  }`}>
                  Full Tunnel
                </button>
                <button onClick={() => { setConfigTab("split"); setConfigCopied(false); }}
                  className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-colors ${
                    configTab === "split"
                      ? "bg-purple-600/20 border-purple-500/40 text-purple-400"
                      : "bg-gray-900 border-gray-700 text-gray-400 hover:border-gray-500"
                  }`}>
                  Split Tunnel
                </button>
              </div>
              <p className="text-xs text-gray-400 mb-3">
                {configTab === "full"
                  ? "Routes ALL traffic through the VPN. Your IP will appear as the firewall\u2019s WAN address."
                  : "Only routes traffic destined for the VPN subnet. Internet traffic uses your normal connection."}
              </p>
              <pre className="bg-gray-900 border border-gray-700 rounded-lg p-4 text-sm font-mono text-green-400 whitespace-pre-wrap select-all overflow-x-auto">
                {configTab === "full" ? configModal.fullTunnel : configModal.splitTunnel}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* ────────────────────────── Summary card ────────────────────────── */

function SummaryCard({
  label,
  value,
  color,
  subtitle,
}: {
  label: string;
  value: number;
  color: "cyan" | "blue" | "green";
  subtitle?: string;
}) {
  const borderColors: Record<string, string> = {
    cyan: "border-cyan-500/30",
    blue: "border-blue-500/30",
    green: "border-green-500/30",
  };
  const textColors: Record<string, string> = {
    cyan: "text-cyan-400",
    blue: "text-blue-400",
    green: "text-green-400",
  };

  return (
    <div className={`bg-gray-800 border ${borderColors[color]} rounded-lg p-4`}>
      <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${textColors[color]}`}>{value}</p>
      {subtitle && <p className="text-[10px] text-gray-500 mt-0.5">{subtitle}</p>}
    </div>
  );
}
