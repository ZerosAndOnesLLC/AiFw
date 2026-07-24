/// VPN page API module (#428): resource types, request bodies, and all
/// HTTP calls for WireGuard tunnels/peers and IPsec SAs. No React here.

import { api } from "@/lib/api";

/* ────────────────────────── Types ────────────────────────── */

export interface WgTunnel {
  id: string;
  name: string;
  interface: string;
  listen_port: number;
  address: string;
  /** IPv6 tunnel address for dual-stack tunnels (#471); null = IPv4-only */
  address6: string | null;
  private_key: string;
  public_key: string;
  dns: string | null;
  mtu: number | null;
  listen_interface: string | null;
  split_routes: string | null;
  status: string;
  created_at: string;
}

export interface WgPeer {
  id: string;
  tunnel_id: string;
  name: string;
  public_key: string;
  preshared_key: string | null;
  client_private_key: string | null;
  endpoint: string | null;
  /** Serialized by the API as an array of CIDR strings (one per family
   *  on dual-stack tunnels, e.g. ["10.10.0.2/32", "fd00:a1f0::2/128"]) */
  allowed_ips: string[];
  persistent_keepalive: number | null;
  created_at: string;
}

/// Legacy pre-#530 IPsec SA record. Configuration-only — never carried
/// traffic; the API now flags every row `legacy: true` and refuses new
/// creations (410).
export interface IpsecSa {
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
  legacy?: boolean;
}

/// A real IPsec IKEv2 site-to-site tunnel (#530). Secrets (`psk`,
/// `local_key_pem`) always arrive as "REDACTED".
export interface IpsecTunnel {
  id: string;
  name: string;
  enabled: boolean;
  local_addr: string;
  remote_addr: string;
  local_id: string;
  remote_id: string;
  auth_method: "psk" | "cert";
  psk: string;
  cert_source: "acme" | "manual" | null;
  acme_cert_id: number | null;
  local_cert_pem: string;
  local_key_pem: string;
  ca_cert_pem: string;
  ike_proposal: string;
  esp_proposal: string;
  local_ts: string[];
  remote_ts: string[];
  ike_lifetime_secs: number;
  esp_lifetime_secs: number;
  dpd_delay_secs: number;
  start_action: "start" | "trap" | "none";
  created_at: string;
  updated_at: string;
}

/// Live negotiated state of one child (ESP) SA.
export interface ChildSaStatus {
  name: string;
  state: string;
  local_ts: string[];
  remote_ts: string[];
  bytes_in: number;
  bytes_out: number;
  rekey_in_secs: number | null;
  enc_alg: string | null;
}

/// Live negotiated tunnel state from charon (`swanctl --list-sas`).
/// `ike_state` is "DOWN" when no SA exists.
export interface IpsecLiveStatus {
  tunnel_id: string;
  conn_name: string;
  ike_state: string;
  established_secs: number | null;
  remote_host: string | null;
  ike_version: number | null;
  child_sas: ChildSaStatus[];
}

/// ACME store certificate summary, for the cert-auth picker.
export interface AcmeCertOption {
  id: number;
  common_name: string;
  status: string;
}

/// Interface entry for the "Listen Interface" dropdown.
export interface VpnInterface {
  name: string;
  role?: string;
}

/// Live per-peer status pushed over the WebSocket (see WsContext).
export interface WgLivePeerStatus {
  public_key: string;
  endpoint: string | null;
  latest_handshake_secs_ago: number;
  transfer_rx: number;
  transfer_tx: number;
}

/// Live per-tunnel status pushed over the WebSocket.
export interface WgLiveTunnelStatus {
  id: string;
  name: string;
  running: boolean;
  peers: WgLivePeerStatus[];
}

/// Generated client config for a peer (full- and split-tunnel variants).
export interface WgPeerConfig {
  full_tunnel: string;
  split_tunnel: string;
}

/// Data shown in the peer client-config modal.
export interface ConfigModalData {
  peerName: string;
  fullTunnel: string;
  splitTunnel: string;
}

/* ────────────────────────── Request bodies ────────────────────────── */

/// Create/update body for a WireGuard tunnel. Optional fields are only
/// set when the corresponding form field is non-empty, so the JSON
/// payload matches what the page has always sent.
export interface WgTunnelRequest {
  name: string;
  listen_port: number;
  address: string;
  address6?: string;
  private_key?: string;
  dns?: string;
  mtu?: number;
  listen_interface?: string;
  split_routes?: string;
}

/// Create body for a WireGuard peer.
export interface WgPeerRequest {
  name: string | null;
  auto_generate_key: boolean;
  allowed_ips: string;
  endpoint: string | null;
  keepalive: number | null;
  public_key?: string;
  preshared_key?: string;
}

/// Create/update body for an IPsec tunnel. Optional fields keep
/// defaults on create / stored values on update; secrets set to
/// "REDACTED" keep the stored secret.
export interface IpsecTunnelRequest {
  name: string;
  remote_addr: string;
  local_ts: string[];
  remote_ts: string[];
  enabled?: boolean;
  local_addr?: string;
  local_id?: string;
  remote_id?: string;
  auth_method?: string;
  psk?: string;
  cert_source?: string;
  acme_cert_id?: number;
  local_cert_pem?: string;
  local_key_pem?: string;
  ca_cert_pem?: string;
  ike_proposal?: string;
  esp_proposal?: string;
  ike_lifetime_secs?: number;
  esp_lifetime_secs?: number;
  dpd_delay_secs?: number;
  start_action?: string;
}

/* ────────────────────────── Helpers ────────────────────────── */

export function fmtBytes(b: number): string {
  if (b >= 1e9) return `${(b/1e9).toFixed(1)} GB`; if (b >= 1e6) return `${(b/1e6).toFixed(1)} MB`;
  if (b >= 1e3) return `${(b/1e3).toFixed(1)} KB`; return `${b} B`;
}

export function fmtDuration(secs: number): string {
  if (secs < 0) return "never";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.floor(secs/60)}m ago`;
  return `${Math.floor(secs/3600)}h ${Math.floor((secs%3600)/60)}m ago`;
}

/* ────────────────────────── Default form values ────────────────────────── */

export interface WgFormState {
  name: string;
  listen_port: string;
  address: string;
  address6: string;
  private_key: string;
  dns: string;
  mtu: string;
  listen_interface: string;
  split_routes: string;
}

export const defaultWgForm: WgFormState = {
  name: "",
  listen_port: "",
  address: "",
  address6: "",
  private_key: "",
  dns: "",
  mtu: "",
  listen_interface: "any",
  split_routes: "",
};

export interface PeerFormState {
  name: string;
  public_key: string;
  preshared_key: string;
  auto_generate_key: boolean;
  endpoint: string;
  allowed_ips: string;
  keepalive: string;
}

export const defaultPeerForm: PeerFormState = {
  name: "",
  public_key: "",
  preshared_key: "",
  auto_generate_key: true,
  endpoint: "",
  allowed_ips: "",
  keepalive: "",
};

export interface IpsecFormState {
  name: string;
  enabled: boolean;
  local_addr: string;
  remote_addr: string;
  local_id: string;
  remote_id: string;
  auth_method: "psk" | "cert";
  psk: string;
  cert_source: "acme" | "manual";
  acme_cert_id: string;
  local_cert_pem: string;
  local_key_pem: string;
  ca_cert_pem: string;
  local_ts: string;
  remote_ts: string;
  ike_proposal: string;
  esp_proposal: string;
  ike_lifetime_secs: string;
  esp_lifetime_secs: string;
  dpd_delay_secs: string;
  start_action: "start" | "trap" | "none";
}

export const defaultIpsecForm: IpsecFormState = {
  name: "",
  enabled: true,
  local_addr: "",
  remote_addr: "",
  local_id: "",
  remote_id: "",
  auth_method: "psk",
  psk: "",
  cert_source: "manual",
  acme_cert_id: "",
  local_cert_pem: "",
  local_key_pem: "",
  ca_cert_pem: "",
  local_ts: "",
  remote_ts: "",
  ike_proposal: "aes256gcm16-prfsha256-ecp256",
  esp_proposal: "aes256gcm16-ecp256",
  ike_lifetime_secs: "14400",
  esp_lifetime_secs: "3600",
  dpd_delay_secs: "30",
  start_action: "start",
};

/* ────────────────────────── WireGuard tunnels ────────────────────────── */

export async function listWgTunnels(): Promise<WgTunnel[]> {
  const res = await api.get<{ data: WgTunnel[] }>("/api/v1/vpn/wg");
  return res.data;
}

export async function createWgTunnel(body: WgTunnelRequest): Promise<void> {
  await api.post("/api/v1/vpn/wg", body);
}

export async function updateWgTunnel(id: string, body: WgTunnelRequest): Promise<void> {
  await api.put(`/api/v1/vpn/wg/${id}`, body);
}

export async function deleteWgTunnel(id: string): Promise<void> {
  await api.delete(`/api/v1/vpn/wg/${id}`);
}

export async function startWgTunnel(id: string): Promise<void> {
  await api.post(`/api/v1/vpn/wg/${id}/start`);
}

export async function stopWgTunnel(id: string): Promise<void> {
  await api.post(`/api/v1/vpn/wg/${id}/stop`);
}

/* ────────────────────────── WireGuard peers ────────────────────────── */

export async function listWgPeers(tunnelId: string): Promise<WgPeer[]> {
  const res = await api.get<{ data: WgPeer[] }>(`/api/v1/vpn/wg/${tunnelId}/peers`);
  return res.data;
}

export async function createWgPeer(tunnelId: string, body: WgPeerRequest): Promise<void> {
  await api.post(`/api/v1/vpn/wg/${tunnelId}/peers`, body);
}

export async function deleteWgPeer(tunnelId: string, peerId: string): Promise<void> {
  await api.delete(`/api/v1/vpn/wg/${tunnelId}/peers/${peerId}`);
}

/// Next free IP in the tunnel subnet, for the peer form's Auto button.
export async function getNextPeerIp(tunnelId: string): Promise<string> {
  const res = await api.get<{ next_ip: string }>(`/api/v1/vpn/wg/${tunnelId}/peers/next-ip`);
  return res.next_ip;
}

export async function getWgPeerConfig(tunnelId: string, peerId: string): Promise<WgPeerConfig> {
  return api.get<WgPeerConfig>(`/api/v1/vpn/wg/${tunnelId}/peers/${peerId}/config`);
}

/* ────────────────────────── IPsec ────────────────────────── */

/// Legacy read-only SA records (creation is 410 Gone on the API).
export async function listIpsecSas(): Promise<IpsecSa[]> {
  const res = await api.get<{ data: IpsecSa[] }>("/api/v1/vpn/ipsec");
  return res.data;
}

export async function deleteIpsecSa(id: string): Promise<void> {
  await api.delete(`/api/v1/vpn/ipsec/${id}`);
}

/* ────────────────────────── IPsec tunnels (#530) ────────────────────────── */

export async function listIpsecTunnels(): Promise<IpsecTunnel[]> {
  const res = await api.get<{ data: IpsecTunnel[] }>("/api/v1/vpn/ipsec/tunnels");
  return res.data;
}

export async function createIpsecTunnel(body: IpsecTunnelRequest): Promise<void> {
  await api.post("/api/v1/vpn/ipsec/tunnels", body);
}

export async function updateIpsecTunnel(id: string, body: IpsecTunnelRequest): Promise<void> {
  await api.put(`/api/v1/vpn/ipsec/tunnels/${id}`, body);
}

export async function deleteIpsecTunnel(id: string): Promise<void> {
  await api.delete(`/api/v1/vpn/ipsec/tunnels/${id}`);
}

export async function startIpsecTunnel(id: string): Promise<void> {
  await api.post(`/api/v1/vpn/ipsec/tunnels/${id}/start`);
}

export async function stopIpsecTunnel(id: string): Promise<void> {
  await api.post(`/api/v1/vpn/ipsec/tunnels/${id}/stop`);
}

/// Live negotiated status for all tunnels (fresh `swanctl --list-sas`).
export async function getIpsecStatus(): Promise<IpsecLiveStatus[]> {
  const res = await api.get<{ data: IpsecLiveStatus[] }>("/api/v1/vpn/ipsec/status");
  return res.data;
}

/// ACME certs for the cert-auth picker (best-effort; empty on error).
export async function listAcmeCertOptions(): Promise<AcmeCertOption[]> {
  try {
    return await api.get<AcmeCertOption[]>("/api/v1/acme/certs");
  } catch {
    return [];
  }
}

/* ────────────────────────── Interfaces ────────────────────────── */

/// Interfaces for the listen-binding dropdown.
export async function listVpnInterfaces(): Promise<VpnInterface[]> {
  const res = await api.get<{ data: VpnInterface[] }>("/api/v1/interfaces");
  return res.data || [];
}
