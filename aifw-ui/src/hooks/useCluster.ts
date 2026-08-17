"use client";

import { useCallback, useEffect, useState } from "react";
import {
  type CarpVip,
  type HcFormState,
  type HealthCheck,
  type HealthSummary,
  type InterfaceInfo,
  type Node,
  type NodeFormState,
  type Pfsync,
  type PfsyncFormState,
  type VipFormState,
  createCarpVip,
  createHealthCheck,
  createNode,
  deleteCarpVip,
  deleteHealthCheck,
  deleteNode as apiDeleteNode,
  demoteCluster,
  forceSnapshotSync,
  generateLoopbackKey as apiGenerateLoopbackKey,
  generateNodePeerKey,
  repinNode,
  getHealthSummary,
  getPfsync,
  listCarpVips,
  listHealthChecks,
  listInterfaces,
  listNodes,
  promoteCluster,
  registerPeerKey as apiRegisterPeerKey,
  updateCarpVip,
  updateHealthCheck,
  updateNode,
  updatePfsync,
} from "@/lib/api/cluster";

/// Data + actions for the Cluster & High Availability page (#428).
/// Owns the resource state, the shared busy/error flags, and every
/// create/update/delete action. The `onSaved`/`onDeleted` callbacks are
/// invoked only on success, *before* the reload — matching the original
/// page's "close form, then refresh" ordering.
///
/// Note: this page historically used a manually-dismissed error banner
/// (no auto-dismiss) plus several bespoke success banners, so it keeps
/// its own error state instead of the shared `useFeedback` hook.
export function useCluster() {
  const [vips, setVips] = useState<CarpVip[]>([]);
  const [pfsync, setPfsync] = useState<Pfsync | null>(null);
  const [nodes, setNodes] = useState<Node[]>([]);
  const [healthChecks, setHealthChecks] = useState<HealthCheck[]>([]);
  const [summary, setSummary] = useState<HealthSummary | null>(null);
  const [ifaces, setIfaces] = useState<InterfaceInfo[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Generated peer key banner
  const [generatedKey, setGeneratedKey] = useState<{
    nodeName: string;
    key: string;
  } | null>(null);

  // Loopback key success message
  const [loopbackMsg, setLoopbackMsg] = useState<string | null>(null);

  // Inbound peer key registration (SEC-H12)
  const [peerKeyMsg, setPeerKeyMsg] = useState<string | null>(null);

  const [savingVip, setSavingVip] = useState(false);
  const [savingPfsync, setSavingPfsync] = useState(false);
  const [savingNode, setSavingNode] = useState(false);
  const [savingHc, setSavingHc] = useState(false);

  // ============================================================
  // Data loading
  // ============================================================

  const reload = useCallback(async () => {
    const [v, p, n, hc, sm, ifaceRes] = await Promise.all([
      listCarpVips().catch(() => [] as CarpVip[]),
      getPfsync().catch(() => null),
      listNodes().catch(() => [] as Node[]),
      listHealthChecks().catch(() => [] as HealthCheck[]),
      getHealthSummary().catch(() => null),
      listInterfaces().catch(() => ({ data: [] as InterfaceInfo[] })),
    ]);
    setVips(v);
    setPfsync(p);
    setNodes(n);
    setHealthChecks(hc);
    setSummary(sm);
    setIfaces(ifaceRes.data ?? []);
  }, []);

  useEffect(() => {
    queueMicrotask(() => { reload().catch(() => {}); });
  }, [reload]);

  // ============================================================
  // Role actions
  // ============================================================

  const promote = async () => {
    setBusy(true);
    try {
      await promoteCluster();
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const demote = async () => {
    setBusy(true);
    try {
      await demoteCluster();
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const repinPeer = async (nodeId: string) => {
    setBusy(true);
    try {
      await repinNode(nodeId);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reset peer TLS pin");
    } finally {
      setBusy(false);
    }
  };

  const generatePeerKey = async (nodeId: string, nodeName: string) => {
    const d = await generateNodePeerKey(nodeId).catch(() => null);
    if (d) {
      setGeneratedKey({ nodeName, key: d.key });
      await reload();
    }
  };

  // ============================================================
  // Loopback key generation (D4)
  // ============================================================

  const generateLoopbackKey = async () => {
    setBusy(true);
    try {
      const r = await apiGenerateLoopbackKey();
      if (r.ok) {
        setLoopbackMsg(r.message);
        await reload();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate loopback key");
    } finally {
      setBusy(false);
    }
  };

  // Register the inbound peer key so a master can push snapshots/certs here.
  const registerPeerKey = async (input: string, onRegistered?: () => void) => {
    const key = input.trim();
    if (key.length < 32) {
      setError("Peer key looks too short — paste the full key generated on the master.");
      return;
    }
    setBusy(true);
    try {
      const r = await apiRegisterPeerKey(key);
      setPeerKeyMsg(r.message || "Peer key registered.");
      onRegistered?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to register peer key");
    } finally {
      setBusy(false);
    }
  };

  // ============================================================
  // CARP VIP CRUD
  // ============================================================

  const saveVip = async (
    form: VipFormState,
    editingVipId: string | null,
    onSaved?: () => void
  ) => {
    const vhid = parseInt(form.vhid, 10);
    const prefix = parseInt(form.prefix, 10);
    if (!form.virtual_ip || !form.interface || !form.password) {
      setError("VIP: all fields are required");
      return;
    }
    if (isNaN(vhid) || vhid < 1 || vhid > 255) {
      setError("VHID must be 1–255");
      return;
    }
    if (form.password.length < 8) {
      setError("CARP password must be at least 8 characters");
      return;
    }
    setSavingVip(true);
    setError(null);
    try {
      const body = {
        vhid,
        virtual_ip: form.virtual_ip,
        prefix,
        interface: form.interface,
        password: form.password,
      };
      if (editingVipId) {
        await updateCarpVip(editingVipId, body);
      } else {
        await createCarpVip(body);
      }
      onSaved?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save VIP");
    } finally {
      setSavingVip(false);
    }
  };

  const deleteVip = async (v: CarpVip, onDeleted?: () => void) => {
    try {
      await deleteCarpVip(v.id);
      onDeleted?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete VIP");
    }
  };

  // ============================================================
  // pfsync CRUD (singleton)
  // ============================================================

  const savePfsync = async (form: PfsyncFormState, onSaved?: () => void) => {
    if (!form.sync_interface) {
      setError("Sync interface is required");
      return;
    }
    setSavingPfsync(true);
    setError(null);
    try {
      const body = {
        sync_interface: form.sync_interface,
        sync_peer: form.sync_peer || null,
        defer: form.defer,
        enabled: form.enabled,
        latency_profile: form.latency_profile,
        heartbeat_iface: form.heartbeat_iface || null,
        heartbeat_interval_ms: form.heartbeat_interval_ms
          ? parseInt(form.heartbeat_interval_ms, 10)
          : null,
        dhcp_link: form.dhcp_link,
      };
      await updatePfsync(body);
      onSaved?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save pfsync config");
    } finally {
      setSavingPfsync(false);
    }
  };

  const forceSync = async () => {
    setBusy(true);
    try {
      await forceSnapshotSync().catch(() => {});
      await reload();
    } finally {
      setBusy(false);
    }
  };

  // ============================================================
  // Node CRUD
  // ============================================================

  const saveNode = async (
    form: NodeFormState,
    editingNodeId: string | null,
    onSaved?: () => void
  ) => {
    if (!form.name || !form.address) {
      setError("Node: name and address are required");
      return;
    }
    setSavingNode(true);
    setError(null);
    try {
      const body = {
        name: form.name,
        address: form.address,
        role: form.role,
      };
      if (editingNodeId) {
        await updateNode(editingNodeId, body);
      } else {
        await createNode(body);
      }
      onSaved?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save node");
    } finally {
      setSavingNode(false);
    }
  };

  const deleteNode = async (n: Node, onDeleted?: () => void) => {
    try {
      await apiDeleteNode(n.id);
      onDeleted?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete node");
    }
  };

  // ============================================================
  // Health check CRUD
  // ============================================================

  const saveHc = async (
    form: HcFormState,
    editingHcId: string | null,
    onSaved?: () => void
  ) => {
    if (!form.name) {
      setError("Health check: name is required");
      return;
    }
    setSavingHc(true);
    setError(null);
    try {
      const body = {
        name: form.name,
        check_type: form.check_type,
        target: form.target,
        interval_secs: parseInt(form.interval_secs, 10) || 10,
        timeout_secs: parseInt(form.timeout_secs, 10) || 5,
        failures_before_down: parseInt(form.failures_before_down, 10) || 3,
        enabled: form.enabled,
      };
      if (editingHcId) {
        await updateHealthCheck(editingHcId, body);
      } else {
        await createHealthCheck(body);
      }
      onSaved?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save health check");
    } finally {
      setSavingHc(false);
    }
  };

  const deleteHc = async (h: HealthCheck, onDeleted?: () => void) => {
    try {
      await deleteHealthCheck(h.id);
      onDeleted?.();
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete health check");
    }
  };

  return {
    // data
    vips,
    pfsync,
    nodes,
    healthChecks,
    summary,
    ifaces,
    // shared flags
    busy,
    error,
    dismissError: () => setError(null),
    // banners
    generatedKey,
    dismissGeneratedKey: () => setGeneratedKey(null),
    loopbackMsg,
    dismissLoopbackMsg: () => setLoopbackMsg(null),
    peerKeyMsg,
    dismissPeerKeyMsg: () => setPeerKeyMsg(null),
    // saving flags
    savingVip,
    savingPfsync,
    savingNode,
    savingHc,
    // actions
    promote,
    demote,
    generatePeerKey,
    repinPeer,
    generateLoopbackKey,
    registerPeerKey,
    saveVip,
    deleteVip,
    savePfsync,
    forceSync,
    saveNode,
    deleteNode,
    saveHc,
    deleteHc,
  };
}
