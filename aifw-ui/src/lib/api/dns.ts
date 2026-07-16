import { api } from "@/lib/api";

/* -- Types ---------------------------------------------------------- */

export interface DnsStatus {
  running: boolean;
  version: string;
  total_hosts: number;
  total_domains: number;
  total_acls: number;
  cache_hits: number;
  cache_misses: number;
  queries_total: number;
  backend: string;
  listening_udp: boolean;
  listening_tcp: boolean;
  last_switch_at: string | null;
  last_switch_result: string | null;
  probe_enabled: boolean;
}

export interface ApplyReport {
  backend: string;
  enabled: boolean;
  probe_udp: boolean;
  probe_tcp: boolean;
  rolled_back: boolean;
  previous: string | null;
  message: string;
}

export interface ResolverConfig {
  backend: string;
  enabled: boolean;
  listen_interfaces: string[];
  port: number;
  dnssec: boolean;
  dns64: boolean;
  register_dhcp: boolean;
  dhcp_domain: string;
  local_zone_type: string;
  outgoing_interface: string;
  num_threads: number;
  msg_cache_size: number;
  rrset_cache_size: number;
  cache_max_ttl: number;
  cache_min_ttl: number;
  prefetch: boolean;
  prefetch_key: boolean;
  infra_host_ttl: number;
  unwanted_reply_threshold: number;
  log_queries: boolean;
  log_replies: boolean;
  log_verbosity: number;
  query_timeout_ms: number;
  hide_identity: boolean;
  hide_version: boolean;
  rebind_protection: boolean;
  private_addresses: string[];
  dot_enabled: boolean;
  dot_upstream: string[];
  blocklists_enabled: boolean;
  blocklist_urls: string[];
  whitelist: string[];
  blocklist_action: string;
  blocklist_redirect_ip: string;
  custom_options: string;
  probe_enabled: boolean;
}

interface NetInterface {
  name: string;
}

export type ServiceAction = "start" | "stop" | "restart";

/* -- Helpers --------------------------------------------------------- */

export const defaultResolverConfig: ResolverConfig = {
  backend: "rdns",
  enabled: false,
  listen_interfaces: [],
  port: 53,
  dnssec: true,
  dns64: false,
  register_dhcp: false,
  dhcp_domain: "local",
  local_zone_type: "transparent",
  outgoing_interface: "",
  num_threads: 2,
  msg_cache_size: 4,
  rrset_cache_size: 4,
  cache_max_ttl: 86400,
  cache_min_ttl: 0,
  prefetch: true,
  prefetch_key: false,
  infra_host_ttl: 900,
  unwanted_reply_threshold: 0,
  log_queries: false,
  log_replies: false,
  log_verbosity: 1,
  query_timeout_ms: 0,
  hide_identity: true,
  hide_version: true,
  rebind_protection: true,
  private_addresses: [],
  dot_enabled: false,
  dot_upstream: [],
  blocklists_enabled: false,
  blocklist_urls: [],
  whitelist: [],
  blocklist_action: "nxdomain",
  blocklist_redirect_ip: "",
  custom_options: "",
  probe_enabled: true,
};

/* -- HTTP calls ------------------------------------------------------ */

export function fetchResolverStatus(): Promise<DnsStatus> {
  return api.get<DnsStatus>("/api/v1/dns/resolver/status");
}

export function fetchResolverConfig(): Promise<ResolverConfig> {
  return api.get<ResolverConfig>("/api/v1/dns/resolver/config");
}

export function saveResolverConfigApi(config: ResolverConfig): Promise<unknown> {
  return api.put("/api/v1/dns/resolver/config", config);
}

export function resolverServiceAction(
  action: ServiceAction,
): Promise<ApplyReport | { message?: string }> {
  return api.post<ApplyReport | { message?: string }>(`/api/v1/dns/resolver/${action}`);
}

export function applyResolverConfigApi(): Promise<ApplyReport> {
  return api.post<ApplyReport>("/api/v1/dns/resolver/apply");
}

/// Interface names for the "Listen Interfaces" selector, with loopback
/// and pflog pseudo-interfaces filtered out.
export async function fetchDnsInterfaceNames(): Promise<string[]> {
  const body = await api.get<{ data?: NetInterface[] }>("/api/v1/interfaces");
  return (body.data || [])
    .map((i: NetInterface) => i.name)
    .filter((n: string) => !n.startsWith("lo") && !n.startsWith("pflog"));
}
