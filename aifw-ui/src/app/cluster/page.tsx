"use client";

import { useEffect, useState, useCallback } from "react";
import { fetchApi } from "@/lib/api";
import StatusBanner from "./components/StatusBanner";

// ============================================================
// Types
// ============================================================

type CarpVip = {
  id: string;
  vhid: number;
  virtual_ip: string;
  prefix: number;
  interface: string;
  password: string;
  status: string;
};

type Pfsync = {
  id: string;
  sync_interface: string;
  sync_peer: string | null;
  defer: boolean;
  enabled: boolean;
  latency_profile: "conservative" | "tight" | "aggressive";
  heartbeat_iface: string | null;
  heartbeat_interval_ms: number | null;
  dhcp_link: boolean;
  created_at: string;
};

type Node = {
  id: string;
  name: string;
  address: string;
  role: string;
  health: string;
  last_seen: string;
};

type HealthCheck = {
  id: string;
  name: string;
  check_type: string;
  target: string;
  interval_secs: number;
  timeout_secs: number;
  failures_before_down: number;
  enabled: boolean;
};

type HealthSummary = {
  missing_peer_keys: string[];
  loopback_key_missing: boolean;
  warnings: string[];
};

type InterfaceInfo = {
  name: string;
  description?: string;
};

// ============================================================
// Style helpers (match aliases/page.tsx pattern)
// ============================================================

const inputCls =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white placeholder:text-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
const selectCls =
  "w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-1.5 text-sm text-white focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500 transition-colors";
const labelCls = "block text-xs font-medium text-gray-400 mb-1";
const btnPrimary =
  "px-4 py-1.5 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors";
const btnSecondary =
  "px-4 py-1.5 text-sm font-medium rounded-md bg-gray-700 border border-gray-600 text-gray-300 hover:text-white hover:bg-gray-600 transition-colors";
const btnDanger =
  "p-1.5 text-gray-400 hover:text-red-400 transition-colors rounded hover:bg-gray-700";
const btnEdit =
  "p-1.5 text-gray-400 hover:text-blue-400 transition-colors rounded hover:bg-gray-700";

// ============================================================
// Icon helpers
// ============================================================

function PencilIcon() {
  return (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"
      />
    </svg>
  );
}

function TrashIcon() {
  return (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={1.5}
    >
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
      />
    </svg>
  );
}

function PlusIcon() {
  return (
    <svg
      className="w-4 h-4"
      fill="none"
      viewBox="0 0 24 24"
      stroke="currentColor"
      strokeWidth={2}
    >
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
    </svg>
  );
}

// ============================================================
// Section header with optional Add button
// ============================================================

function SectionHeader({
  title,
  onAdd,
  addLabel = "Add",
}: {
  title: string;
  onAdd?: () => void;
  addLabel?: string;
}) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h2 className="text-lg font-semibold">{title}</h2>
      {onAdd && (
        <button
          onClick={onAdd}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <PlusIcon />
          {addLabel}
        </button>
      )}
    </div>
  );
}

// ============================================================
// Inline form card (reusable shell)
// ============================================================

function FormCard({
  title,
  onCancel,
  onSave,
  saving,
  children,
}: {
  title: string;
  onCancel: () => void;
  onSave: () => void;
  saving: boolean;
  children: React.ReactNode;
}) {
  return (
    <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4 mb-4">
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      {children}
      <div className="flex gap-2">
        <button onClick={onSave} disabled={saving} className={btnPrimary}>
          {saving ? "Saving..." : "Save"}
        </button>
        <button onClick={onCancel} className={btnSecondary}>
          Cancel
        </button>
      </div>
    </div>
  );
}

// ============================================================
// Confirmation dialog
// ============================================================

function ConfirmDialog({
  message,
  onConfirm,
  onCancel,
}: {
  message: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 max-w-md w-full mx-4 space-y-4">
        <p className="text-sm text-white">{message}</p>
        <div className="flex gap-2 justify-end">
          <button onClick={onCancel} className={btnSecondary}>
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-1.5 text-sm font-medium rounded-md bg-red-600 hover:bg-red-700 text-white transition-colors"
          >
            Confirm
          </button>
        </div>
      </div>
    </div>
  );
}

// ============================================================
// Main page
// ============================================================

export default function ClusterPage() {
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

  // CARP VIP form
  const defaultVipForm = {
    vhid: "",
    virtual_ip: "",
    prefix: "24",
    interface: "",
    password: "",
  };
  const [showVipForm, setShowVipForm] = useState(false);
  const [vipForm, setVipForm] = useState(defaultVipForm);
  const [editingVipId, setEditingVipId] = useState<string | null>(null);
  const [savingVip, setSavingVip] = useState(false);
  const [deleteVipConfirm, setDeleteVipConfirm] = useState<CarpVip | null>(
    null
  );

  // pfsync form
  const defaultPfsyncForm = {
    sync_interface: "",
    sync_peer: "",
    defer: false,
    enabled: true,
    latency_profile: "conservative" as "conservative" | "tight" | "aggressive",
    heartbeat_iface: "",
    heartbeat_interval_ms: "",
    dhcp_link: false,
  };
  const [showPfsyncForm, setShowPfsyncForm] = useState(false);
  const [pfsyncForm, setPfsyncForm] = useState(defaultPfsyncForm);
  const [savingPfsync, setSavingPfsync] = useState(false);
  const [dhcpLinkConfirm, setDhcpLinkConfirm] = useState(false);
  const [pendingPfsyncSave, setPendingPfsyncSave] = useState(false);

  // Node form
  const defaultNodeForm = { name: "", address: "", role: "secondary" };
  const [showNodeForm, setShowNodeForm] = useState(false);
  const [nodeForm, setNodeForm] = useState(defaultNodeForm);
  const [editingNodeId, setEditingNodeId] = useState<string | null>(null);
  const [savingNode, setSavingNode] = useState(false);
  const [deleteNodeConfirm, setDeleteNodeConfirm] = useState<Node | null>(null);

  // Health check form
  const defaultHcForm = {
    name: "",
    check_type: "ping",
    target: "",
    interval_secs: "10",
    timeout_secs: "5",
    failures_before_down: "3",
    enabled: true,
  };
  const [showHcForm, setShowHcForm] = useState(false);
  const [hcForm, setHcForm] = useState(defaultHcForm);
  const [editingHcId, setEditingHcId] = useState<string | null>(null);
  const [savingHc, setSavingHc] = useState(false);
  const [deleteHcConfirm, setDeleteHcConfirm] = useState<HealthCheck | null>(
    null
  );

  // ============================================================
  // Data loading
  // ============================================================

  const reload = useCallback(async () => {
    const [v, p, n, hc, sm, ifaceRes] = await Promise.all([
      fetchApi<CarpVip[]>("/api/v1/cluster/carp").catch(() => [] as CarpVip[]),
      fetchApi<Pfsync | null>("/api/v1/cluster/pfsync").catch(() => null),
      fetchApi<Node[]>("/api/v1/cluster/nodes").catch(() => [] as Node[]),
      fetchApi<HealthCheck[]>("/api/v1/cluster/health").catch(
        () => [] as HealthCheck[]
      ),
      fetchApi<HealthSummary>("/api/v1/cluster/health-summary").catch(
        () => null
      ),
      fetchApi<{ data: InterfaceInfo[] }>("/api/v1/interfaces").catch(
        () => ({ data: [] })
      ),
    ]);
    setVips(v);
    setPfsync(p);
    setNodes(n);
    setHealthChecks(hc);
    setSummary(sm);
    setIfaces(ifaceRes.data ?? []);
  }, []);

  useEffect(() => {
    reload().catch(() => {});
  }, [reload]);

  // ============================================================
  // Role actions
  // ============================================================

  const promote = async () => {
    setBusy(true);
    try {
      await fetchApi("/api/v1/cluster/promote", { method: "POST" });
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const demote = async () => {
    setBusy(true);
    try {
      await fetchApi("/api/v1/cluster/demote", { method: "POST" });
      await reload();
    } finally {
      setBusy(false);
    }
  };

  const generatePeerKey = async (nodeId: string, nodeName: string) => {
    const d = await fetchApi<{ key: string }>(
      `/api/v1/cluster/nodes/${nodeId}/generate-key`,
      { method: "POST" }
    ).catch(() => null);
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
      const r = await fetchApi<{ ok: boolean; message: string }>(
        "/api/v1/cluster/loopback-key/generate",
        { method: "POST" }
      );
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

  // ============================================================
  // CARP VIP CRUD
  // ============================================================

  const openAddVip = () => {
    setVipForm(defaultVipForm);
    setEditingVipId(null);
    setShowVipForm(true);
  };

  const openEditVip = (v: CarpVip) => {
    setVipForm({
      vhid: String(v.vhid),
      virtual_ip: v.virtual_ip,
      prefix: String(v.prefix),
      interface: v.interface,
      password: v.password,
    });
    setEditingVipId(v.id);
    setShowVipForm(true);
  };

  const saveVip = async () => {
    const vhid = parseInt(vipForm.vhid, 10);
    const prefix = parseInt(vipForm.prefix, 10);
    if (!vipForm.virtual_ip || !vipForm.interface || !vipForm.password) {
      setError("VIP: all fields are required");
      return;
    }
    if (isNaN(vhid) || vhid < 1 || vhid > 255) {
      setError("VHID must be 1–255");
      return;
    }
    if (vipForm.password.length < 8) {
      setError("CARP password must be at least 8 characters");
      return;
    }
    setSavingVip(true);
    setError(null);
    try {
      const body = {
        vhid,
        virtual_ip: vipForm.virtual_ip,
        prefix,
        interface: vipForm.interface,
        password: vipForm.password,
      };
      if (editingVipId) {
        await fetchApi(`/api/v1/cluster/carp/${editingVipId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
      } else {
        await fetchApi("/api/v1/cluster/carp", {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      setShowVipForm(false);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save VIP");
    } finally {
      setSavingVip(false);
    }
  };

  const deleteVip = async (v: CarpVip) => {
    try {
      await fetchApi(`/api/v1/cluster/carp/${v.id}`, { method: "DELETE" });
      setDeleteVipConfirm(null);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete VIP");
    }
  };

  // ============================================================
  // pfsync CRUD (singleton)
  // ============================================================

  const openEditPfsync = () => {
    if (pfsync) {
      setPfsyncForm({
        sync_interface: pfsync.sync_interface,
        sync_peer: pfsync.sync_peer ?? "",
        defer: pfsync.defer,
        enabled: pfsync.enabled,
        latency_profile: pfsync.latency_profile,
        heartbeat_iface: pfsync.heartbeat_iface ?? "",
        heartbeat_interval_ms: pfsync.heartbeat_interval_ms
          ? String(pfsync.heartbeat_interval_ms)
          : "",
        dhcp_link: pfsync.dhcp_link,
      });
    } else {
      setPfsyncForm(defaultPfsyncForm);
    }
    setShowPfsyncForm(true);
  };

  const doSavePfsync = async () => {
    if (!pfsyncForm.sync_interface) {
      setError("Sync interface is required");
      return;
    }
    setSavingPfsync(true);
    setError(null);
    try {
      const body = {
        sync_interface: pfsyncForm.sync_interface,
        sync_peer: pfsyncForm.sync_peer || null,
        defer: pfsyncForm.defer,
        enabled: pfsyncForm.enabled,
        latency_profile: pfsyncForm.latency_profile,
        heartbeat_iface: pfsyncForm.heartbeat_iface || null,
        heartbeat_interval_ms: pfsyncForm.heartbeat_interval_ms
          ? parseInt(pfsyncForm.heartbeat_interval_ms, 10)
          : null,
        dhcp_link: pfsyncForm.dhcp_link,
      };
      await fetchApi("/api/v1/cluster/pfsync", {
        method: "PUT",
        body: JSON.stringify(body),
      });
      setShowPfsyncForm(false);
      setPendingPfsyncSave(false);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save pfsync config");
    } finally {
      setSavingPfsync(false);
    }
  };

  const savePfsync = () => {
    // If dhcp_link is being turned on (was off before), show confirmation
    const wasDhcpLink = pfsync?.dhcp_link ?? false;
    if (pfsyncForm.dhcp_link && !wasDhcpLink) {
      setDhcpLinkConfirm(true);
      setPendingPfsyncSave(true);
      return;
    }
    doSavePfsync();
  };

  // ============================================================
  // Node CRUD
  // ============================================================

  const openAddNode = () => {
    setNodeForm(defaultNodeForm);
    setEditingNodeId(null);
    setShowNodeForm(true);
  };

  const openEditNode = (n: Node) => {
    setNodeForm({ name: n.name, address: n.address, role: n.role });
    setEditingNodeId(n.id);
    setShowNodeForm(true);
  };

  const saveNode = async () => {
    if (!nodeForm.name || !nodeForm.address) {
      setError("Node: name and address are required");
      return;
    }
    setSavingNode(true);
    setError(null);
    try {
      const body = {
        name: nodeForm.name,
        address: nodeForm.address,
        role: nodeForm.role,
      };
      if (editingNodeId) {
        await fetchApi(`/api/v1/cluster/nodes/${editingNodeId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
      } else {
        await fetchApi("/api/v1/cluster/nodes", {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      setShowNodeForm(false);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save node");
    } finally {
      setSavingNode(false);
    }
  };

  const deleteNode = async (n: Node) => {
    try {
      await fetchApi(`/api/v1/cluster/nodes/${n.id}`, { method: "DELETE" });
      setDeleteNodeConfirm(null);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete node");
    }
  };

  // ============================================================
  // Health check CRUD
  // ============================================================

  const openAddHc = () => {
    setHcForm(defaultHcForm);
    setEditingHcId(null);
    setShowHcForm(true);
  };

  const openEditHc = (h: HealthCheck) => {
    setHcForm({
      name: h.name,
      check_type: h.check_type,
      target: h.target,
      interval_secs: String(h.interval_secs),
      timeout_secs: String(h.timeout_secs),
      failures_before_down: String(h.failures_before_down),
      enabled: h.enabled,
    });
    setEditingHcId(h.id);
    setShowHcForm(true);
  };

  const saveHc = async () => {
    if (!hcForm.name) {
      setError("Health check: name is required");
      return;
    }
    setSavingHc(true);
    setError(null);
    try {
      const body = {
        name: hcForm.name,
        check_type: hcForm.check_type,
        target: hcForm.target,
        interval_secs: parseInt(hcForm.interval_secs, 10) || 10,
        timeout_secs: parseInt(hcForm.timeout_secs, 10) || 5,
        failures_before_down: parseInt(hcForm.failures_before_down, 10) || 3,
        enabled: hcForm.enabled,
      };
      if (editingHcId) {
        await fetchApi(`/api/v1/cluster/health/${editingHcId}`, {
          method: "PUT",
          body: JSON.stringify(body),
        });
      } else {
        await fetchApi("/api/v1/cluster/health", {
          method: "POST",
          body: JSON.stringify(body),
        });
      }
      setShowHcForm(false);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to save health check");
    } finally {
      setSavingHc(false);
    }
  };

  const deleteHc = async (h: HealthCheck) => {
    try {
      await fetchApi(`/api/v1/cluster/health/${h.id}`, { method: "DELETE" });
      setDeleteHcConfirm(null);
      await reload();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete health check");
    }
  };

  // ============================================================
  // Render
  // ============================================================

  return (
    <div className="space-y-6">
      {/* Confirmation dialogs */}
      {deleteVipConfirm && (
        <ConfirmDialog
          message={`Delete CARP VIP ${deleteVipConfirm.virtual_ip} (VHID ${deleteVipConfirm.vhid})?`}
          onConfirm={() => deleteVip(deleteVipConfirm)}
          onCancel={() => setDeleteVipConfirm(null)}
        />
      )}
      {deleteNodeConfirm && (
        <ConfirmDialog
          message={`Delete node "${deleteNodeConfirm.name}" (${deleteNodeConfirm.address})?`}
          onConfirm={() => deleteNode(deleteNodeConfirm)}
          onCancel={() => setDeleteNodeConfirm(null)}
        />
      )}
      {deleteHcConfirm && (
        <ConfirmDialog
          message={`Delete health check "${deleteHcConfirm.name}"?`}
          onConfirm={() => deleteHc(deleteHcConfirm)}
          onCancel={() => setDeleteHcConfirm(null)}
        />
      )}
      {dhcpLinkConfirm && (
        <ConfirmDialog
          message="This will replace any manually-configured rDHCP HA peer list with the cluster-derived list. The peer list editor on the DHCP HA page will be locked. Continue?"
          onConfirm={() => {
            setDhcpLinkConfirm(false);
            if (pendingPfsyncSave) doSavePfsync();
          }}
          onCancel={() => {
            setDhcpLinkConfirm(false);
            setPendingPfsyncSave(false);
            setPfsyncForm((f) => ({ ...f, dhcp_link: false }));
          }}
        />
      )}

      {/* Header */}
      <div className="flex items-end justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold">Cluster &amp; High Availability</h1>
          <p className="text-sm text-[var(--text-muted)]">
            CARP failover, pfsync state synchronization, peer nodes
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={promote}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-green-600 hover:bg-green-700 disabled:opacity-50 text-sm"
          >
            Promote
          </button>
          <button
            onClick={demote}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 text-sm"
          >
            Demote
          </button>
        </div>
      </div>

      {/* D2: Health-summary warning banners */}
      {summary && summary.warnings.length > 0 && (
        <div className="space-y-2">
          {summary.warnings.map((w, i) => (
            <div
              key={i}
              className="bg-red-500/10 border border-red-500/40 rounded p-3 text-sm text-red-300"
            >
              {w}
            </div>
          ))}
        </div>
      )}

      {/* D4: Loopback key missing banner */}
      {summary?.loopback_key_missing && (
        <div className="bg-yellow-500/10 border border-yellow-500/40 rounded p-3 text-sm flex justify-between items-start gap-3">
          <div>
            <div className="font-semibold">Loopback API key missing</div>
            <div className="text-xs opacity-80 mt-1">
              Cluster background tasks (replicator, role watcher, health prober)
              are disabled until a loopback API key is registered. This is
              normal if you configured HA via the UI rather than the setup
              wizard.
            </div>
          </div>
          <button
            onClick={generateLoopbackKey}
            disabled={busy}
            className="px-3 py-1.5 rounded bg-yellow-600 hover:bg-yellow-700 disabled:opacity-50 whitespace-nowrap text-sm"
          >
            Generate now
          </button>
        </div>
      )}

      {/* Loopback key success message */}
      {loopbackMsg && (
        <div className="bg-green-500/10 border border-green-500/40 rounded p-3 text-sm flex justify-between items-start gap-3">
          <div>{loopbackMsg}</div>
          <button
            onClick={() => setLoopbackMsg(null)}
            className="text-xs underline whitespace-nowrap"
          >
            dismiss
          </button>
        </div>
      )}

      {/* Status banner (existing) */}
      <StatusBanner />

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

      {/* Generated peer key banner */}
      {generatedKey && (
        <div className="bg-yellow-500/10 border border-yellow-500/40 rounded p-3 text-sm">
          <div className="font-semibold mb-1">
            Peer API key for {generatedKey.nodeName}
          </div>
          <div className="text-xs opacity-80 mb-2">
            This key is shown ONCE. Copy it and register it on the peer node as
            an API key (in the peer&apos;s Users &#x2192; API Keys page) before
            dismissing. This local node will use it to authenticate to{" "}
            {generatedKey.nodeName}.
          </div>
          <code className="block break-all bg-[var(--bg-card)] p-2 rounded mb-2">
            {generatedKey.key}
          </code>
          <button
            onClick={() => navigator.clipboard.writeText(generatedKey.key)}
            className="text-xs underline mr-3"
          >
            copy
          </button>
          <button onClick={() => setGeneratedKey(null)} className="text-xs underline">
            dismiss
          </button>
        </div>
      )}

      {/* ============================================================ */}
      {/* CARP Virtual IPs */}
      {/* ============================================================ */}
      <section>
        <SectionHeader
          title="CARP Virtual IPs"
          onAdd={openAddVip}
          addLabel="Add VIP"
        />

        {showVipForm && (
          <FormCard
            title={editingVipId ? "Edit CARP VIP" : "New CARP VIP"}
            onCancel={() => setShowVipForm(false)}
            onSave={saveVip}
            saving={savingVip}
          >
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <label className={labelCls}>VHID (1–255)</label>
                <input
                  type="number"
                  min={1}
                  max={255}
                  value={vipForm.vhid}
                  onChange={(e) =>
                    setVipForm((f) => ({ ...f, vhid: e.target.value }))
                  }
                  placeholder="1"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Interface</label>
                <select
                  value={vipForm.interface}
                  onChange={(e) =>
                    setVipForm((f) => ({ ...f, interface: e.target.value }))
                  }
                  className={selectCls}
                >
                  <option value="">-- select --</option>
                  {ifaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                      {i.description ? ` (${i.description})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelCls}>Virtual IP</label>
                <input
                  type="text"
                  value={vipForm.virtual_ip}
                  onChange={(e) =>
                    setVipForm((f) => ({ ...f, virtual_ip: e.target.value }))
                  }
                  placeholder="192.168.1.10"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Prefix length</label>
                <input
                  type="number"
                  min={1}
                  max={128}
                  value={vipForm.prefix}
                  onChange={(e) =>
                    setVipForm((f) => ({ ...f, prefix: e.target.value }))
                  }
                  placeholder="24"
                  className={inputCls}
                />
              </div>
              <div className="md:col-span-2">
                <label className={labelCls}>
                  Password (min 8 chars; avoid shell metacharacters)
                </label>
                <input
                  type="password"
                  value={vipForm.password}
                  onChange={(e) =>
                    setVipForm((f) => ({ ...f, password: e.target.value }))
                  }
                  placeholder="••••••••"
                  className={inputCls}
                />
                {/[|&;`$'"\\!]/.test(vipForm.password) && (
                  <p className="text-xs text-yellow-400 mt-0.5">
                    Warning: password contains shell metacharacters. This may
                    cause issues in rc.conf.
                  </p>
                )}
              </div>
            </div>
          </FormCard>
        )}

        {vips.length === 0 && !showVipForm ? (
          <div className="text-sm text-[var(--text-muted)]">
            No VIPs configured.
          </div>
        ) : vips.length > 0 ? (
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    VHID
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Interface
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    VIP
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="w-20"></th>
                </tr>
              </thead>
              <tbody>
                {vips.map((v) => (
                  <tr
                    key={v.id}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                  >
                    <td className="py-2.5 px-4">{v.vhid}</td>
                    <td className="py-2.5 px-4 font-mono">{v.interface}</td>
                    <td className="py-2.5 px-4 font-mono">
                      {v.virtual_ip}/{v.prefix}
                    </td>
                    <td className="py-2.5 px-4">{v.status}</td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => openEditVip(v)}
                          className={btnEdit}
                          title="Edit"
                        >
                          <PencilIcon />
                        </button>
                        <button
                          onClick={() => setDeleteVipConfirm(v)}
                          className={btnDanger}
                          title="Delete"
                        >
                          <TrashIcon />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {/* ============================================================ */}
      {/* pfsync configuration */}
      {/* ============================================================ */}
      <section>
        <SectionHeader
          title="pfsync Configuration"
          onAdd={openEditPfsync}
          addLabel={pfsync ? "Edit" : "Configure"}
        />

        {showPfsyncForm && (
          <FormCard
            title="pfsync Settings"
            onCancel={() => setShowPfsyncForm(false)}
            onSave={savePfsync}
            saving={savingPfsync}
          >
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <label className={labelCls}>Sync Interface</label>
                <select
                  value={pfsyncForm.sync_interface}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({
                      ...f,
                      sync_interface: e.target.value,
                    }))
                  }
                  className={selectCls}
                >
                  <option value="">-- select --</option>
                  {ifaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                      {i.description ? ` (${i.description})` : ""}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelCls}>
                  Sync Peer IP (blank = multicast)
                </label>
                <input
                  type="text"
                  value={pfsyncForm.sync_peer}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({ ...f, sync_peer: e.target.value }))
                  }
                  placeholder="e.g. 10.0.0.2"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>
                  Heartbeat Interface (future use)
                </label>
                <select
                  value={pfsyncForm.heartbeat_iface}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({
                      ...f,
                      heartbeat_iface: e.target.value,
                    }))
                  }
                  className={selectCls}
                >
                  <option value="">-- none --</option>
                  {ifaces.map((i) => (
                    <option key={i.name} value={i.name}>
                      {i.name}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className={labelCls}>
                  Heartbeat Interval ms (future use)
                </label>
                <input
                  type="number"
                  value={pfsyncForm.heartbeat_interval_ms}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({
                      ...f,
                      heartbeat_interval_ms: e.target.value,
                    }))
                  }
                  placeholder="1000"
                  className={inputCls}
                />
              </div>
            </div>

            {/* Latency profile radio */}
            <div>
              <label className={labelCls}>Latency Profile</label>
              <div className="space-y-2">
                {(
                  [
                    {
                      value: "conservative",
                      label: "Conservative",
                      desc: "Higher advskew — only promotes after several missed heartbeats. Best for unstable links.",
                    },
                    {
                      value: "tight",
                      label: "Tight",
                      desc: "Balanced — promotes after 2–3 missed heartbeats. Recommended for most deployments.",
                    },
                    {
                      value: "aggressive",
                      label: "Aggressive",
                      desc: "Low advskew — promotes quickly. Use only on very reliable dedicated sync links.",
                    },
                  ] as const
                ).map(({ value, label, desc }) => (
                  <label
                    key={value}
                    className="flex items-start gap-2 cursor-pointer"
                  >
                    <input
                      type="radio"
                      name="latency_profile"
                      value={value}
                      checked={pfsyncForm.latency_profile === value}
                      onChange={() =>
                        setPfsyncForm((f) => ({
                          ...f,
                          latency_profile: value,
                        }))
                      }
                      className="mt-0.5"
                    />
                    <span className="text-sm">
                      <span className="font-medium text-white">{label}</span>
                      <span className="text-gray-400"> — {desc}</span>
                    </span>
                  </label>
                ))}
              </div>
            </div>

            {/* Bool toggles */}
            <div className="flex flex-wrap gap-6">
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={pfsyncForm.defer}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({ ...f, defer: e.target.checked }))
                  }
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Defer</span>
              </label>
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={pfsyncForm.enabled}
                  onChange={(e) =>
                    setPfsyncForm((f) => ({
                      ...f,
                      enabled: e.target.checked,
                    }))
                  }
                  className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                />
                <span className="text-sm text-gray-300">Enabled</span>
              </label>
              <div>
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={pfsyncForm.dhcp_link}
                    onChange={(e) =>
                      setPfsyncForm((f) => ({
                        ...f,
                        dhcp_link: e.target.checked,
                      }))
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <span className="text-sm text-gray-300">DHCP Link</span>
                </label>
                <p className="text-xs text-gray-500 mt-0.5 ml-6">
                  Auto-derives the rDHCP HA peer list from the cluster nodes —
                  when enabled, you don&apos;t have to enter peer addresses again
                  on the DHCP HA page.
                </p>
              </div>
            </div>
          </FormCard>
        )}

        {pfsync && !showPfsyncForm ? (
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 text-sm space-y-1">
            <div>
              Sync interface:{" "}
              <span className="font-mono">{pfsync.sync_interface}</span>
            </div>
            <div>
              Peer:{" "}
              <span className="font-mono">
                {pfsync.sync_peer ?? "multicast"}
              </span>
            </div>
            <div>Latency profile: {pfsync.latency_profile}</div>
            <div>DHCP link: {pfsync.dhcp_link ? "yes" : "no"}</div>
            <div>Enabled: {pfsync.enabled ? "yes" : "no"}</div>
            <div className="pt-1">
              <button
                onClick={async () => {
                  setBusy(true);
                  try {
                    await fetchApi("/api/v1/cluster/snapshot/force", {
                      method: "POST",
                    }).catch(() => {});
                    await reload();
                  } finally {
                    setBusy(false);
                  }
                }}
                disabled={busy}
                className="px-3 py-1.5 rounded bg-purple-600 hover:bg-purple-700 disabled:opacity-50 text-sm"
              >
                Force sync from peer
              </button>
            </div>
          </div>
        ) : !pfsync && !showPfsyncForm ? (
          <div className="text-sm text-[var(--text-muted)]">Not configured.</div>
        ) : null}
      </section>

      {/* ============================================================ */}
      {/* Health checks */}
      {/* ============================================================ */}
      <section>
        <SectionHeader
          title="Health Checks"
          onAdd={openAddHc}
          addLabel="Add Check"
        />

        {showHcForm && (
          <FormCard
            title={editingHcId ? "Edit Health Check" : "New Health Check"}
            onCancel={() => setShowHcForm(false)}
            onSave={saveHc}
            saving={savingHc}
          >
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <label className={labelCls}>Name</label>
                <input
                  type="text"
                  value={hcForm.name}
                  onChange={(e) =>
                    setHcForm((f) => ({ ...f, name: e.target.value }))
                  }
                  placeholder="e.g. wan-ping"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Check Type</label>
                <select
                  value={hcForm.check_type}
                  onChange={(e) =>
                    setHcForm((f) => ({ ...f, check_type: e.target.value }))
                  }
                  className={selectCls}
                >
                  <option value="ping">Ping (ICMP)</option>
                  <option value="tcp_port">TCP Port</option>
                  <option value="http_get">HTTP GET (2xx)</option>
                  <option value="pf_status">pf Status</option>
                  <option value="process_running">Process Running</option>
                </select>
              </div>
              <div>
                <label className={labelCls}>
                  Target{" "}
                  <span className="text-gray-500">
                    (IP, host:port, URL, or process name)
                  </span>
                </label>
                <input
                  type="text"
                  value={hcForm.target}
                  onChange={(e) =>
                    setHcForm((f) => ({ ...f, target: e.target.value }))
                  }
                  placeholder={
                    hcForm.check_type === "ping"
                      ? "8.8.8.8"
                      : hcForm.check_type === "tcp_port"
                        ? "10.0.0.1:22"
                        : hcForm.check_type === "http_get"
                          ? "http://10.0.0.1/health"
                          : hcForm.check_type === "process_running"
                            ? "rdhcpd"
                            : ""
                  }
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Interval (secs)</label>
                <input
                  type="number"
                  value={hcForm.interval_secs}
                  onChange={(e) =>
                    setHcForm((f) => ({ ...f, interval_secs: e.target.value }))
                  }
                  placeholder="10"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Timeout (secs)</label>
                <input
                  type="number"
                  value={hcForm.timeout_secs}
                  onChange={(e) =>
                    setHcForm((f) => ({ ...f, timeout_secs: e.target.value }))
                  }
                  placeholder="5"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Failures before down</label>
                <input
                  type="number"
                  value={hcForm.failures_before_down}
                  onChange={(e) =>
                    setHcForm((f) => ({
                      ...f,
                      failures_before_down: e.target.value,
                    }))
                  }
                  placeholder="3"
                  className={inputCls}
                />
              </div>
              <div className="flex items-end pb-0.5">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={hcForm.enabled}
                    onChange={(e) =>
                      setHcForm((f) => ({ ...f, enabled: e.target.checked }))
                    }
                    className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-0"
                  />
                  <span className="text-sm text-gray-300">Enabled</span>
                </label>
              </div>
            </div>
          </FormCard>
        )}

        {healthChecks.length === 0 && !showHcForm ? (
          <div className="text-sm text-[var(--text-muted)]">
            No health checks configured.
          </div>
        ) : healthChecks.length > 0 ? (
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Target
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Interval
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="w-20"></th>
                </tr>
              </thead>
              <tbody>
                {healthChecks.map((h) => (
                  <tr
                    key={h.id}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                  >
                    <td className="py-2.5 px-4 font-mono">{h.name}</td>
                    <td className="py-2.5 px-4">{h.check_type}</td>
                    <td className="py-2.5 px-4 font-mono text-xs">
                      {h.target || "—"}
                    </td>
                    <td className="py-2.5 px-4">{h.interval_secs}s</td>
                    <td className="py-2.5 px-4">
                      <span
                        className={
                          h.enabled
                            ? "text-green-400 text-xs"
                            : "text-gray-500 text-xs"
                        }
                      >
                        {h.enabled ? "enabled" : "disabled"}
                      </span>
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => openEditHc(h)}
                          className={btnEdit}
                          title="Edit"
                        >
                          <PencilIcon />
                        </button>
                        <button
                          onClick={() => setDeleteHcConfirm(h)}
                          className={btnDanger}
                          title="Delete"
                        >
                          <TrashIcon />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      {/* ============================================================ */}
      {/* Cluster Nodes */}
      {/* ============================================================ */}
      <section>
        <SectionHeader
          title="Cluster Nodes"
          onAdd={openAddNode}
          addLabel="Add Node"
        />

        {showNodeForm && (
          <FormCard
            title={editingNodeId ? "Edit Cluster Node" : "New Cluster Node"}
            onCancel={() => setShowNodeForm(false)}
            onSave={saveNode}
            saving={savingNode}
          >
            <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <div>
                <label className={labelCls}>Name</label>
                <input
                  type="text"
                  value={nodeForm.name}
                  onChange={(e) =>
                    setNodeForm((f) => ({ ...f, name: e.target.value }))
                  }
                  placeholder="firewall-b"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Address (IP)</label>
                <input
                  type="text"
                  value={nodeForm.address}
                  onChange={(e) =>
                    setNodeForm((f) => ({ ...f, address: e.target.value }))
                  }
                  placeholder="10.0.0.2"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Role</label>
                <select
                  value={nodeForm.role}
                  onChange={(e) =>
                    setNodeForm((f) => ({ ...f, role: e.target.value }))
                  }
                  className={selectCls}
                >
                  <option value="primary">Primary</option>
                  <option value="secondary">Secondary</option>
                  <option value="standalone">Standalone</option>
                </select>
              </div>
            </div>
          </FormCard>
        )}

        {nodes.length === 0 && !showNodeForm ? (
          <div className="text-sm text-[var(--text-muted)]">
            No peer nodes registered.
          </div>
        ) : nodes.length > 0 ? (
          <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Address
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Role
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Health
                  </th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-400 uppercase tracking-wider">
                    Last seen
                  </th>
                  <th className="w-40"></th>
                </tr>
              </thead>
              <tbody>
                {nodes.map((n) => (
                  <tr
                    key={n.id}
                    className="border-b border-gray-700/50 hover:bg-gray-700/30 transition-colors"
                  >
                    <td className="py-2.5 px-4">{n.name}</td>
                    <td className="py-2.5 px-4 font-mono">{n.address}</td>
                    <td className="py-2.5 px-4">{n.role}</td>
                    <td className="py-2.5 px-4">{n.health}</td>
                    <td className="py-2.5 px-4">
                      {new Date(n.last_seen).toLocaleString()}
                    </td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => generatePeerKey(n.id, n.name)}
                          className="px-2 py-1 rounded bg-indigo-600 hover:bg-indigo-700 text-xs text-white whitespace-nowrap"
                        >
                          Peer Key
                        </button>
                        <button
                          onClick={() => openEditNode(n)}
                          className={btnEdit}
                          title="Edit"
                        >
                          <PencilIcon />
                        </button>
                        <button
                          onClick={() => setDeleteNodeConfirm(n)}
                          className={btnDanger}
                          title="Delete"
                        >
                          <TrashIcon />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>
    </div>
  );
}
