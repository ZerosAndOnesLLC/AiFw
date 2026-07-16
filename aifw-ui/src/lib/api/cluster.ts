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
  created_at: string;
};

export type Node = {
  id: string;
  name: string;
  address: string;
  role: string;
  health: string;
  last_seen: string;
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
};

export type NodeRequest = {
  name: string;
  address: string;
  role: string;
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
};

export type NodeFormState = {
  name: string;
  address: string;
  role: string;
};

export const defaultNodeForm: NodeFormState = {
  name: "",
  address: "",
  role: "secondary",
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

export const generateNodePeerKey = (nodeId: string) =>
  api.post<{ key: string }>(`/api/v1/cluster/nodes/${nodeId}/generate-key`);

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
