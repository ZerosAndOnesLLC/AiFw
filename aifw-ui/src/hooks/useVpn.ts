"use client";

/// Data hook for the VPN page (#428): owns WireGuard tunnel/peer and
/// IPsec SA state, loading flags, fetch/refresh, and all CRUD actions
/// with their error feedback. The error banner is shared between the
/// WireGuard and IPsec sections and persists until manually dismissed
/// (the page never auto-dismissed it), so this hook keeps a plain
/// error state rather than useFeedback's auto-dismissing banner.

import { useState, useEffect, useCallback } from "react";
import { useWs } from "@/context/WsContext";
import type {
  WgTunnel,
  WgPeer,
  IpsecSa,
  IpsecTunnel,
  IpsecLiveStatus,
  IpsecTunnelRequest,
  AcmeCertOption,
  VpnInterface,
  WgLiveTunnelStatus,
  ConfigModalData,
  WgTunnelRequest,
  WgPeerRequest,
} from "@/lib/api/vpn";
import {
  defaultWgForm,
  defaultPeerForm,
  defaultIpsecForm,
  listWgTunnels,
  createWgTunnel,
  updateWgTunnel,
  deleteWgTunnel,
  startWgTunnel,
  stopWgTunnel,
  listWgPeers,
  createWgPeer,
  deleteWgPeer,
  getNextPeerIp,
  getWgPeerConfig,
  listIpsecSas,
  deleteIpsecSa,
  listIpsecTunnels,
  createIpsecTunnel,
  updateIpsecTunnel,
  deleteIpsecTunnel,
  startIpsecTunnel,
  stopIpsecTunnel,
  getIpsecStatus,
  listAcmeCertOptions,
  listVpnInterfaces,
} from "@/lib/api/vpn";

export function useVpn() {
  /* ── WireGuard state ── */
  const [tunnels, setTunnels] = useState<WgTunnel[]>([]);
  const [peersByTunnel, setPeersByTunnel] = useState<Record<string, WgPeer[]>>({});
  const [wgLoading, setWgLoading] = useState(true);
  const [expandedTunnel, setExpandedTunnel] = useState<string | null>(null);
  const [showWgForm, setShowWgForm] = useState(false);
  const [wgForm, setWgForm] = useState(defaultWgForm);
  const [editingWgId, setEditingWgId] = useState<string | null>(null);
  const [wgSubmitting, setWgSubmitting] = useState(false);

  /* ── Peer form state ── */
  const [showPeerForm, setShowPeerForm] = useState<string | null>(null); // tunnel_id or null
  const [peerForm, setPeerForm] = useState(defaultPeerForm);
  const [peerSubmitting, setPeerSubmitting] = useState(false);

  /* ── IPsec state (#530: real tunnels + read-only legacy SA records) ── */
  const [ipsecTunnels, setIpsecTunnels] = useState<IpsecTunnel[]>([]);
  const [ipsecStatuses, setIpsecStatuses] = useState<Record<string, IpsecLiveStatus>>({});
  const [ipsecSas, setIpsecSas] = useState<IpsecSa[]>([]);
  const [ipsecLoading, setIpsecLoading] = useState(true);
  const [showIpsecForm, setShowIpsecForm] = useState(false);
  const [ipsecForm, setIpsecForm] = useState(defaultIpsecForm);
  const [editingIpsecId, setEditingIpsecId] = useState<string | null>(null);
  const [ipsecSubmitting, setIpsecSubmitting] = useState(false);
  const [acmeCerts, setAcmeCerts] = useState<AcmeCertOption[]>([]);

  /* ── Tunnel live status from WebSocket ── */
  const ws = useWs();
  const vpnStatus = (ws as unknown as { vpn?: WgLiveTunnelStatus[] }).vpn;

  /* ── Config modal ── */
  const [configModal, setConfigModal] = useState<ConfigModalData | null>(null);

  /* ── Interfaces (for listen binding dropdown) ── */
  const [interfaces, setInterfaces] = useState<VpnInterface[]>([]);

  /* ── Shared ── */
  const [error, setError] = useState<string | null>(null);

  /* ────────────────────────── Fetch helpers ────────────────────────── */

  const fetchTunnels = useCallback(async () => {
    try {
      const data = await listWgTunnels();
      setTunnels(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load WireGuard tunnels");
    } finally {
      setWgLoading(false);
    }
  }, []);

  const fetchPeers = useCallback(async (tunnelId: string) => {
    try {
      const data = await listWgPeers(tunnelId);
      setPeersByTunnel((prev) => ({ ...prev, [tunnelId]: data }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load peers");
    }
  }, []);

  const fetchIpsec = useCallback(async () => {
    try {
      const [tunnels, sas] = await Promise.all([listIpsecTunnels(), listIpsecSas()]);
      setIpsecTunnels(tunnels);
      setIpsecSas(sas);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load IPsec tunnels");
    } finally {
      setIpsecLoading(false);
    }
  }, []);

  const fetchIpsecStatus = useCallback(async () => {
    try {
      const statuses = await getIpsecStatus();
      setIpsecStatuses(Object.fromEntries(statuses.map((s) => [s.tunnel_id, s])));
    } catch {
      // status is best-effort; the table just shows no live badge
    }
  }, []);

  useEffect(() => {
    queueMicrotask(() => {
      fetchTunnels();
      fetchIpsec();
      fetchIpsecStatus();
      listVpnInterfaces()
        .then((data) => setInterfaces(data))
        .catch(() => {});
      listAcmeCertOptions().then(setAcmeCerts);
    });
  }, [fetchTunnels, fetchIpsec, fetchIpsecStatus]);

  /* Poll live IPsec status every 10s while any tunnel exists. */
  useEffect(() => {
    if (ipsecTunnels.length === 0) return;
    const timer = setInterval(fetchIpsecStatus, 10_000);
    return () => clearInterval(timer);
  }, [ipsecTunnels.length, fetchIpsecStatus]);

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
      const body: WgTunnelRequest = {
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
      if (wgForm.split_routes.trim()) {
        body.split_routes = wgForm.split_routes.trim();
      }

      if (editingWgId) {
        await updateWgTunnel(editingWgId, body);
      } else {
        await createWgTunnel(body);
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
      split_routes: tunnel.split_routes || "",
    });
    setEditingWgId(tunnel.id);
    setShowWgForm(true);
  };

  const handleDeleteWg = async (id: string) => {
    setError(null);
    try {
      await deleteWgTunnel(id);
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

  /// Add Tunnel button: toggles the create form closed, or opens a
  /// fresh (non-edit) form.
  const handleAddTunnelClick = () => {
    if (showWgForm && !editingWgId) {
      handleCancelWg();
    } else {
      setWgForm(defaultWgForm);
      setEditingWgId(null);
      setShowWgForm(true);
    }
  };

  const handleStartTunnel = async (id: string) => {
    setError(null);
    try {
      await startWgTunnel(id);
      await fetchTunnels();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start tunnel");
    }
  };

  const handleStopTunnel = async (id: string) => {
    setError(null);
    try {
      await stopWgTunnel(id);
      await fetchTunnels();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop tunnel");
    }
  };

  const handleAutoAssignIp = async (tunnelId: string) => {
    try {
      const nextIp = await getNextPeerIp(tunnelId);
      setPeerForm((f) => ({ ...f, allowed_ips: nextIp }));
    } catch {
      setError("No free IPs in tunnel subnet");
    }
  };

  /* ────────────────────────── Peer CRUD ────────────────────────── */

  /// Add Peer button: toggles the peer form for a tunnel, always
  /// resetting to defaults.
  const handleTogglePeerForm = (tunnelId: string) => {
    if (showPeerForm === tunnelId) {
      setShowPeerForm(null);
      setPeerForm(defaultPeerForm);
    } else {
      setPeerForm(defaultPeerForm);
      setShowPeerForm(tunnelId);
    }
  };

  const handleCancelPeerForm = () => {
    setShowPeerForm(null);
    setPeerForm(defaultPeerForm);
  };

  const handlePeerSubmit = async (tunnelId: string) => {
    if (peerSubmitting) return;
    if (!peerForm.auto_generate_key && !peerForm.public_key.trim()) return;
    if (!peerForm.allowed_ips.trim()) return;
    setPeerSubmitting(true);
    setError(null);
    try {
      const body: WgPeerRequest = {
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
      await createWgPeer(tunnelId, body);
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
      const res = await getWgPeerConfig(tunnelId, peer.id);
      setConfigModal({ peerName: peer.name || peer.public_key.slice(0, 12), fullTunnel: res.full_tunnel, splitTunnel: res.split_tunnel });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to get peer config");
    }
  };

  const closeConfigModal = () => setConfigModal(null);

  const handleDeletePeer = async (tunnelId: string, peerId: string) => {
    setError(null);
    try {
      await deleteWgPeer(tunnelId, peerId);
      setPeersByTunnel((prev) => ({
        ...prev,
        [tunnelId]: (prev[tunnelId] || []).filter((p) => p.id !== peerId),
      }));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete peer");
    }
  };

  /* ────────────────────────── IPsec tunnel CRUD ────────────────────────── */

  /// Add Tunnel button: toggles the create form, always resetting to
  /// defaults.
  const handleToggleIpsecForm = () => {
    if (showIpsecForm && !editingIpsecId) {
      setShowIpsecForm(false);
      setIpsecForm(defaultIpsecForm);
    } else {
      setIpsecForm(defaultIpsecForm);
      setEditingIpsecId(null);
      setShowIpsecForm(true);
    }
  };

  const handleCancelIpsecForm = () => {
    setShowIpsecForm(false);
    setEditingIpsecId(null);
    setIpsecForm(defaultIpsecForm);
  };

  const handleEditIpsec = (t: IpsecTunnel) => {
    setIpsecForm({
      name: t.name,
      enabled: t.enabled,
      local_addr: t.local_addr,
      remote_addr: t.remote_addr,
      local_id: t.local_id,
      remote_id: t.remote_id,
      auth_method: t.auth_method,
      psk: "", // blank = keep stored secret
      cert_source: t.cert_source ?? "manual",
      acme_cert_id: t.acme_cert_id != null ? String(t.acme_cert_id) : "",
      local_cert_pem: t.local_cert_pem === "REDACTED" ? "" : t.local_cert_pem,
      local_key_pem: "", // blank = keep stored secret
      ca_cert_pem: t.ca_cert_pem,
      local_ts: t.local_ts.join(", "),
      remote_ts: t.remote_ts.join(", "),
      ike_proposal: t.ike_proposal,
      esp_proposal: t.esp_proposal,
      ike_lifetime_secs: String(t.ike_lifetime_secs),
      esp_lifetime_secs: String(t.esp_lifetime_secs),
      dpd_delay_secs: String(t.dpd_delay_secs),
      start_action: t.start_action,
    });
    setEditingIpsecId(t.id);
    setShowIpsecForm(true);
  };

  const splitTs = (s: string) =>
    s
      .split(",")
      .map((p) => p.trim())
      .filter(Boolean);

  const handleIpsecSubmit = async () => {
    if (ipsecSubmitting) return;
    if (!ipsecForm.name.trim() || !ipsecForm.remote_addr.trim()) return;
    if (!splitTs(ipsecForm.local_ts).length || !splitTs(ipsecForm.remote_ts).length) return;
    setIpsecSubmitting(true);
    setError(null);
    try {
      const body: IpsecTunnelRequest = {
        name: ipsecForm.name.trim(),
        remote_addr: ipsecForm.remote_addr.trim(),
        local_ts: splitTs(ipsecForm.local_ts),
        remote_ts: splitTs(ipsecForm.remote_ts),
        enabled: ipsecForm.enabled,
        local_addr: ipsecForm.local_addr.trim(),
        local_id: ipsecForm.local_id.trim(),
        remote_id: ipsecForm.remote_id.trim(),
        auth_method: ipsecForm.auth_method,
        ike_proposal: ipsecForm.ike_proposal.trim(),
        esp_proposal: ipsecForm.esp_proposal.trim(),
        ike_lifetime_secs: parseInt(ipsecForm.ike_lifetime_secs, 10) || 14400,
        esp_lifetime_secs: parseInt(ipsecForm.esp_lifetime_secs, 10) || 3600,
        dpd_delay_secs: parseInt(ipsecForm.dpd_delay_secs, 10) || 0,
        start_action: ipsecForm.start_action,
      };
      if (ipsecForm.auth_method === "psk") {
        // Blank on edit means "keep the stored PSK" (send the marker).
        body.psk = ipsecForm.psk.trim() || (editingIpsecId ? "REDACTED" : "");
      } else {
        body.cert_source = ipsecForm.cert_source;
        if (ipsecForm.cert_source === "acme") {
          body.acme_cert_id = parseInt(ipsecForm.acme_cert_id, 10);
        } else {
          if (ipsecForm.local_cert_pem.trim()) body.local_cert_pem = ipsecForm.local_cert_pem.trim();
          body.local_key_pem = ipsecForm.local_key_pem.trim() || (editingIpsecId ? "REDACTED" : "");
        }
        if (ipsecForm.ca_cert_pem.trim()) body.ca_cert_pem = ipsecForm.ca_cert_pem.trim();
      }

      if (editingIpsecId) {
        await updateIpsecTunnel(editingIpsecId, body);
      } else {
        await createIpsecTunnel(body);
      }
      handleCancelIpsecForm();
      await fetchIpsec();
      await fetchIpsecStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save IPsec tunnel");
    } finally {
      setIpsecSubmitting(false);
    }
  };

  const handleDeleteIpsecTunnel = async (id: string) => {
    setError(null);
    try {
      await deleteIpsecTunnel(id);
      setIpsecTunnels((prev) => prev.filter((t) => t.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete IPsec tunnel");
    }
  };

  const handleStartIpsec = async (id: string) => {
    setError(null);
    try {
      await startIpsecTunnel(id);
      await fetchIpsecStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to initiate IPsec tunnel");
    }
  };

  const handleStopIpsec = async (id: string) => {
    setError(null);
    try {
      await stopIpsecTunnel(id);
      await fetchIpsecStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to terminate IPsec tunnel");
    }
  };

  const handleDeleteIpsec = async (id: string) => {
    setError(null);
    try {
      await deleteIpsecSa(id);
      setIpsecSas((prev) => prev.filter((sa) => sa.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete legacy IPsec SA record");
    }
  };

  return {
    // WireGuard tunnels
    tunnels,
    peersByTunnel,
    wgLoading,
    expandedTunnel,
    showWgForm,
    wgForm,
    setWgForm,
    editingWgId,
    wgSubmitting,
    handleExpandTunnel,
    handleWgSubmit,
    handleEditWg,
    handleDeleteWg,
    handleCancelWg,
    handleAddTunnelClick,
    handleStartTunnel,
    handleStopTunnel,
    handleAutoAssignIp,
    // WireGuard peers
    showPeerForm,
    peerForm,
    setPeerForm,
    peerSubmitting,
    handleTogglePeerForm,
    handleCancelPeerForm,
    handlePeerSubmit,
    handleShowConfig,
    handleDeletePeer,
    // Config modal
    configModal,
    closeConfigModal,
    // IPsec tunnels + legacy SA records
    ipsecTunnels,
    ipsecStatuses,
    ipsecSas,
    ipsecLoading,
    showIpsecForm,
    ipsecForm,
    setIpsecForm,
    editingIpsecId,
    ipsecSubmitting,
    acmeCerts,
    handleToggleIpsecForm,
    handleCancelIpsecForm,
    handleEditIpsec,
    handleIpsecSubmit,
    handleDeleteIpsecTunnel,
    handleStartIpsec,
    handleStopIpsec,
    handleDeleteIpsec,
    // Live status + interfaces + shared error
    vpnStatus,
    interfaces,
    error,
    setError,
  };
}
