import { api } from "@/lib/api";

// ============================================================
// Types
// ============================================================

export type CarpVip = {
  id: string;
  vhid: number;
  virtual_ip: string;
  prefix: number;
  interface: string;
  password: string;
  status: string;
};

export type LatencyProfile = "conservative" | "tight" | "aggressive";

export type Pfsync = {
  id: string;
  sync_interface: string;
  sync_peer: string | null;
  defer: boolean;
  enabled: boolean;
  latency_profile: LatencyProfile;
  heartbeat_iface: string | null;
  heartbeat_interval_ms: number | null;
  dhcp_link: boolean;
  /** Tear WireGuard down on CARP BACKUP, back up on MASTER (#486). */
  wg_deconfigure_on_backup?: boolean;
  created_at: string;
};

export type Node = {
  id: string;
  name: string;
  address: string;
  role: string;
  health: string;
  last_seen: string;
  /** SHA-256 of the peer's API certificate that our calls are pinned to (#317); null until first contact. */
  cert_fingerprint?: string | null;
  /** Port the peer's API listens on (#487); 8080 unless configured. */
  api_port?: number;
  software_version?: string | null;
  last_pushed_cert_at?: string | null;
  /** Live CARP role the peer last reported to the peer monitor (#712). */
  peer_state?: string | null;
};

/** One CARP vhid as the kernel reports it (#712). */
export type KernelVhid = {
  interface: string;
  vhid: number;
  state: "master" | "backup" | "init" | string;
  advbase: number;
  advskew: number;
};

export type KernelPfsync = {
  up: boolean;
  syncdev: string | null;
  syncpeer: string | null;
  defer: boolean;
  /** Bulk update finished; null when the kernel doesn't report it. */
  syncok: boolean | null;
};

export type DemoteReason =
  | "boot"
  | "shutdown"
  | "health"
  | "manual"
  | "maintenance";

export type ClusterStatus = {
  /** primary | secondary | split | init | standalone */
  role: string;
  configured_role: string;
  peer_reachable: boolean;
  pfsync_state_count: number;
  last_snapshot_hash: string | null;
  carp: {
    vhids: KernelVhid[];
    addrs: { interface: string; addr: string; vhid: number }[];
    pfsync: KernelPfsync | null;
  };
  demotion: {
    level: number | null;
    reasons: DemoteReason[];
    preempt: boolean | null;
    maintenance: boolean;
  };
  peer: Node | null;
  split_brain: boolean;
  warnings: string[];
};

export type HealthRunResult = {
  name: string;
  check_type: string;
  target: string;
  healthy: boolean;
};

export type FailoverEvent = {
  id: string;
  ts: string;
  from_role: string;
  to_role: string;
  cause: string;
  detail?: string | null;
};

export type HealthCheck = {
  id: string;
  name: string;
  check_type: string;
  target: string;
  interval_secs: number;
  timeout_secs: number;
  failures_before_down: number;
  enabled: boolean;
};

export type HealthSummary = {
  missing_peer_keys: string[];
  loopback_key_missing: boolean;
  inbound_peer_key_missing: boolean;
  warnings: string[];
};

export type InterfaceInfo = {
  name: string;
  description?: string;
};

// ============================================================
// Request payloads
// ============================================================

export type CarpVipRequest = {
  vhid: number;
  virtual_ip: string;
  prefix: number;
  interface: string;
  password: string;
};

export type PfsyncRequest = {
  sync_interface: string;
  sync_peer: string | null;
  defer: boolean;
  enabled: boolean;
  latency_profile: LatencyProfile;
  heartbeat_iface: string | null;
  heartbeat_interval_ms: number | null;
  dhcp_link: boolean;
  wg_deconfigure_on_backup?: boolean;
};

export type NodeRequest = {
  name: string;
  address: string;
  role: string;
  api_port?: number;
};

export type HealthCheckRequest = {
  name: string;
  check_type: string;
  target: string;
  interval_secs: number;
  timeout_secs: number;
  failures_before_down: number;
  enabled: boolean;
};

// ============================================================
// Form state (string-typed fields mirror the text inputs)
// ============================================================

export type VipFormState = {
  vhid: string;
  virtual_ip: string;
  prefix: string;
  interface: string;
  password: string;
};

export const defaultVipForm: VipFormState = {
  vhid: "",
  virtual_ip: "",
  prefix: "24",
  interface: "",
  password: "",
};

export type PfsyncFormState = {
  sync_interface: string;
  sync_peer: string;
  defer: boolean;
  enabled: boolean;
  latency_profile: LatencyProfile;
  heartbeat_iface: string;
  heartbeat_interval_ms: string;
  dhcp_link: boolean;
  wg_deconfigure_on_backup: boolean;
};

export const defaultPfsyncForm: PfsyncFormState = {
  sync_interface: "",
  sync_peer: "",
  defer: false,
  enabled: true,
  latency_profile: "conservative",
  heartbeat_iface: "",
  heartbeat_interval_ms: "",
  dhcp_link: false,
  wg_deconfigure_on_backup: false,
};

export type NodeFormState = {
  name: string;
  address: string;
  role: string;
  api_port: string;
};

export const defaultNodeForm: NodeFormState = {
  name: "",
  address: "",
  role: "secondary",
  api_port: "8080",
};

export type HcFormState = {
  name: string;
  check_type: string;
  target: string;
  interval_secs: string;
  timeout_secs: string;
  failures_before_down: string;
  enabled: boolean;
};

export const defaultHcForm: HcFormState = {
  name: "",
  check_type: "ping",
  target: "",
  interval_secs: "10",
  timeout_secs: "5",
  failures_before_down: "3",
  enabled: true,
};

// ============================================================
// HTTP calls
// ============================================================

export const listCarpVips = () => api.get<CarpVip[]>("/api/v1/cluster/carp");

export const getPfsync = () => api.get<Pfsync | null>("/api/v1/cluster/pfsync");

export const listNodes = () => api.get<Node[]>("/api/v1/cluster/nodes");

export const listHealthChecks = () =>
  api.get<HealthCheck[]>("/api/v1/cluster/health");

export const getHealthSummary = () =>
  api.get<HealthSummary>("/api/v1/cluster/health-summary");

export const listInterfaces = () =>
  api.get<{ data: InterfaceInfo[] }>("/api/v1/interfaces");

export const promoteCluster = () =>
  api.post<unknown>("/api/v1/cluster/promote");

export const demoteCluster = () => api.post<unknown>("/api/v1/cluster/demote");

export const getClusterStatus = () =>
  api.get<ClusterStatus>("/api/v1/cluster/status", { noAuthRedirect: true });

/** Persistent CARP maintenance mode — stays BACKUP across reboots (#712). */
export const setMaintenance = (enabled: boolean) =>
  api.put<unknown>("/api/v1/cluster/maintenance", { enabled });

export const runHealthChecks = () =>
  api.post<HealthRunResult[]>("/api/v1/cluster/health/run");

export const getFailoverHistory = (days: number) =>
  api.get<FailoverEvent[]>(`/api/v1/cluster/failover-history?days=${days}`);

export const generateNodePeerKey = (nodeId: string) =>
  api.post<{ key: string }>(`/api/v1/cluster/nodes/${nodeId}/generate-key`);

/** Clear (no fingerprint) or set the pinned TLS certificate of a peer (#317). */
export const repinNode = (nodeId: string, fingerprint?: string) =>
  api.post<Node>(
    `/api/v1/cluster/nodes/${nodeId}/repin`,
    fingerprint ? { fingerprint } : {},
  );

export const generateLoopbackKey = () =>
  api.post<{ ok: boolean; message: string }>(
    "/api/v1/cluster/loopback-key/generate"
  );

// Register the inbound peer key so a master can push snapshots/certs here.
export const registerPeerKey = (key: string) =>
  api.post<{ message: string }>("/api/v1/cluster/peer-key", { key });

export const createCarpVip = (body: CarpVipRequest) =>
  api.post<unknown>("/api/v1/cluster/carp", body);

export const updateCarpVip = (id: string, body: CarpVipRequest) =>
  api.put<unknown>(`/api/v1/cluster/carp/${id}`, body);

export const deleteCarpVip = (id: string) =>
  api.delete<unknown>(`/api/v1/cluster/carp/${id}`);

export const updatePfsync = (body: PfsyncRequest) =>
  api.put<unknown>("/api/v1/cluster/pfsync", body);

export const forceSnapshotSync = () =>
  api.post<unknown>("/api/v1/cluster/snapshot/force");

export const createNode = (body: NodeRequest) =>
  api.post<unknown>("/api/v1/cluster/nodes", body);

export const updateNode = (id: string, body: NodeRequest) =>
  api.put<unknown>(`/api/v1/cluster/nodes/${id}`, body);

export const deleteNode = (id: string) =>
  api.delete<unknown>(`/api/v1/cluster/nodes/${id}`);

export const createHealthCheck = (body: HealthCheckRequest) =>
  api.post<unknown>("/api/v1/cluster/health", body);

export const updateHealthCheck = (id: string, body: HealthCheckRequest) =>
  api.put<unknown>(`/api/v1/cluster/health/${id}`, body);

export const deleteHealthCheck = (id: string) =>
  api.delete<unknown>(`/api/v1/cluster/health/${id}`);
