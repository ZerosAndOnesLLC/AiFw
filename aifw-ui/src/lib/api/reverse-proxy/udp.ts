import { api } from "@/lib/api";

/* -- Types ---------------------------------------------------------- */

export interface UdpRouter {
  id: string;
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: number;
  enabled: boolean;
  created_at: string;
}

export interface UdpService {
  id: string;
  name: string;
  service_type: string;
  config_json: string;
  enabled: boolean;
  created_at: string;
}

export interface EntryPoint {
  id: string;
  name: string;
  address: string;
  enabled: boolean;
}

/* -- Router form ---------------------------------------------------- */

export interface RouterForm {
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: string;
  enabled: boolean;
}

export const defaultRouterForm: RouterForm = {
  name: "",
  rule: "",
  service: "",
  entry_points: "",
  priority: "0",
  enabled: true,
};

/* -- Service form --------------------------------------------------- */

export interface ServerEntry {
  address: string;
  weight: string;
}

export interface ServiceForm {
  name: string;
  service_type: string;
  enabled: boolean;
  // loadBalancer fields
  servers: ServerEntry[];
  healthCheckInterval: string;
  healthCheckTimeout: string;
  healthCheckPayload: string;
  healthCheckExpectedResponse: string;
  // weighted fields
  weightedRefs: { name: string; weight: string }[];
}

export const defaultServiceForm: ServiceForm = {
  name: "",
  service_type: "loadBalancer",
  enabled: true,
  servers: [{ address: "", weight: "1" }],
  healthCheckInterval: "",
  healthCheckTimeout: "",
  healthCheckPayload: "",
  healthCheckExpectedResponse: "",
  weightedRefs: [{ name: "", weight: "1" }],
};

/* -- Request payloads ------------------------------------------------ */

export interface UdpRouterPayload {
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: number;
  enabled: boolean;
}

export interface UdpServicePayload {
  name: string;
  service_type: string;
  config_json: string;
  enabled: boolean;
}

/* -- Helpers --------------------------------------------------------- */

export function buildServiceConfigJson(form: ServiceForm): string {
  if (form.service_type === "weighted") {
    return JSON.stringify({
      weighted: {
        services: form.weightedRefs
          .filter((r) => r.name.trim())
          .map((r) => ({ name: r.name.trim(), weight: parseInt(r.weight, 10) || 1 })),
      },
    });
  }
  const cfg: Record<string, unknown> = {};
  const servers = form.servers
    .filter((s) => s.address.trim())
    .map((s) => {
      const entry: Record<string, unknown> = { address: s.address.trim() };
      const w = parseInt(s.weight, 10);
      if (w && w !== 1) entry.weight = w;
      return entry;
    });
  if (servers.length > 0) cfg.servers = servers;
  if (
    form.healthCheckInterval.trim() ||
    form.healthCheckTimeout.trim() ||
    form.healthCheckPayload.trim() ||
    form.healthCheckExpectedResponse.trim()
  ) {
    const hc: Record<string, string> = {};
    if (form.healthCheckInterval.trim()) hc.interval = form.healthCheckInterval.trim();
    if (form.healthCheckTimeout.trim()) hc.timeout = form.healthCheckTimeout.trim();
    if (form.healthCheckPayload.trim()) hc.payload = form.healthCheckPayload.trim();
    if (form.healthCheckExpectedResponse.trim()) hc.expectedResponse = form.healthCheckExpectedResponse.trim();
    cfg.healthCheck = hc;
  }
  return JSON.stringify(cfg);
}

export function parseServiceConfigJson(raw: string, serviceType: string): Partial<ServiceForm> {
  try {
    const obj = JSON.parse(raw || "{}");
    if (serviceType === "weighted" && obj.weighted?.services) {
      return {
        weightedRefs: obj.weighted.services.map((s: { name: string; weight: number }) => ({
          name: s.name,
          weight: String(s.weight),
        })),
      };
    }
    const partial: Partial<ServiceForm> = {};
    if (Array.isArray(obj.servers)) {
      partial.servers = obj.servers.map((s: { address: string; weight?: number }) => ({
        address: s.address || "",
        weight: String(s.weight || 1),
      }));
    }
    if (obj.healthCheck) {
      if (obj.healthCheck.interval) partial.healthCheckInterval = obj.healthCheck.interval;
      if (obj.healthCheck.timeout) partial.healthCheckTimeout = obj.healthCheck.timeout;
      if (obj.healthCheck.payload) partial.healthCheckPayload = obj.healthCheck.payload;
      if (obj.healthCheck.expectedResponse) partial.healthCheckExpectedResponse = obj.healthCheck.expectedResponse;
    }
    return partial;
  } catch {
    return {};
  }
}

/* -- HTTP calls ------------------------------------------------------ */

/// The list endpoints may return either a bare array or `{ data: [...] }`.
function unwrapList<T>(body: T[] | { data?: T[] }): T[] {
  return Array.isArray(body) ? body : body.data || [];
}

export async function listUdpRouters(): Promise<UdpRouter[]> {
  return unwrapList(await api.get<UdpRouter[] | { data?: UdpRouter[] }>("/api/v1/reverse-proxy/udp/routers"));
}

export async function createUdpRouter(payload: UdpRouterPayload): Promise<void> {
  await api.post("/api/v1/reverse-proxy/udp/routers", payload);
}

export async function updateUdpRouter(id: string, payload: UdpRouterPayload): Promise<void> {
  await api.put(`/api/v1/reverse-proxy/udp/routers/${id}`, payload);
}

export async function deleteUdpRouter(id: string): Promise<void> {
  await api.delete(`/api/v1/reverse-proxy/udp/routers/${id}`);
}

export async function listUdpServices(): Promise<UdpService[]> {
  return unwrapList(await api.get<UdpService[] | { data?: UdpService[] }>("/api/v1/reverse-proxy/udp/services"));
}

export async function createUdpService(payload: UdpServicePayload): Promise<void> {
  await api.post("/api/v1/reverse-proxy/udp/services", payload);
}

export async function updateUdpService(id: string, payload: UdpServicePayload): Promise<void> {
  await api.put(`/api/v1/reverse-proxy/udp/services/${id}`, payload);
}

export async function deleteUdpService(id: string): Promise<void> {
  await api.delete(`/api/v1/reverse-proxy/udp/services/${id}`);
}

export async function listEntryPoints(): Promise<EntryPoint[]> {
  return unwrapList(await api.get<EntryPoint[] | { data?: EntryPoint[] }>("/api/v1/reverse-proxy/entrypoints"));
}
