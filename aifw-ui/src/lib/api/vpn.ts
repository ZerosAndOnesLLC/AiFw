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
  allowed_ips: string;
  persistent_keepalive: number | null;
  created_at: string;
}

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

/// Create body for an IPsec SA.
export interface IpsecSaRequest {
  name: string;
  local_addr: string;
  remote_addr: string;
  protocol: string;
  mode: string;
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
  local_addr: string;
  remote_addr: string;
  protocol: string;
  mode: string;
}

export const defaultIpsecForm: IpsecFormState = {
  name: "",
  local_addr: "",
  remote_addr: "",
  protocol: "esp",
  mode: "tunnel",
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

export async function listIpsecSas(): Promise<IpsecSa[]> {
  const res = await api.get<{ data: IpsecSa[] }>("/api/v1/vpn/ipsec");
  return res.data;
}

export async function createIpsecSa(body: IpsecSaRequest): Promise<void> {
  await api.post("/api/v1/vpn/ipsec", body);
}

export async function deleteIpsecSa(id: string): Promise<void> {
  await api.delete(`/api/v1/vpn/ipsec/${id}`);
}

/* ────────────────────────── Interfaces ────────────────────────── */

/// Interfaces for the listen-binding dropdown.
export async function listVpnInterfaces(): Promise<VpnInterface[]> {
  const res = await api.get<{ data: VpnInterface[] }>("/api/v1/interfaces");
  return res.data || [];
}
