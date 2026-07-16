import { api } from "@/lib/api";

/* -- Types ---------------------------------------------------------- */

export interface TcpRouter {
  id: string;
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: number;
  tls_json: string | null;
  enabled: boolean;
  created_at: string;
}

export interface TcpService {
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

/// Request body for create/update (POST/PUT) of a TCP router.
export interface TcpRouterBody {
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: number;
  tls_json: string | null;
  enabled: boolean;
}

/// Request body for create/update (POST/PUT) of a TCP service.
export interface TcpServiceBody {
  name: string;
  service_type: string;
  config_json: string;
  enabled: boolean;
}

/* -- Router form ---------------------------------------------------- */

export interface RouterForm {
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  priority: string;
  tlsPassthrough: boolean;
  tlsCertResolver: string;
  enabled: boolean;
}

export const defaultRouterForm: RouterForm = {
  name: "",
  rule: "",
  service: "",
  entry_points: "",
  priority: "0",
  tlsPassthrough: false,
  tlsCertResolver: "",
  enabled: true,
};

/* -- Service form --------------------------------------------------- */

export interface ServerEntry {
  address: string;
  weight: string;
  tls: boolean;
}

export interface ServiceForm {
  name: string;
  service_type: string;
  enabled: boolean;
  // loadBalancer fields
  servers: ServerEntry[];
  healthCheckInterval: string;
  healthCheckTimeout: string;
  proxyProtocol: string;
  // weighted fields
  weightedRefs: { name: string; weight: string }[];
}

export const defaultServiceForm: ServiceForm = {
  name: "",
  service_type: "loadBalancer",
  enabled: true,
  servers: [{ address: "", weight: "1", tls: false }],
  healthCheckInterval: "",
  healthCheckTimeout: "",
  proxyProtocol: "none",
  weightedRefs: [{ name: "", weight: "1" }],
};

/* -- Helpers --------------------------------------------------------- */

export function buildTlsJson(form: RouterForm): string | null {
  if (!form.tlsPassthrough && !form.tlsCertResolver.trim()) return null;
  const tls: Record<string, unknown> = {};
  if (form.tlsPassthrough) tls.passthrough = true;
  if (form.tlsCertResolver.trim()) tls.certResolver = form.tlsCertResolver.trim();
  return JSON.stringify(tls);
}

export function parseTlsJson(raw: string | null): { passthrough: boolean; certResolver: string } {
  if (!raw) return { passthrough: false, certResolver: "" };
  try {
    const obj = JSON.parse(raw);
    return {
      passthrough: !!obj.passthrough,
      certResolver: obj.certResolver || "",
    };
  } catch {
    return { passthrough: false, certResolver: "" };
  }
}

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
      if (s.tls) entry.tls = true;
      return entry;
    });
  if (servers.length > 0) cfg.servers = servers;
  if (form.healthCheckInterval.trim() || form.healthCheckTimeout.trim()) {
    const hc: Record<string, string> = {};
    if (form.healthCheckInterval.trim()) hc.interval = form.healthCheckInterval.trim();
    if (form.healthCheckTimeout.trim()) hc.timeout = form.healthCheckTimeout.trim();
    cfg.healthCheck = hc;
  }
  if (form.proxyProtocol !== "none") {
    cfg.proxyProtocol = { version: parseInt(form.proxyProtocol, 10) };
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
      partial.servers = obj.servers.map((s: { address: string; weight?: number; tls?: boolean }) => ({
        address: s.address || "",
        weight: String(s.weight || 1),
        tls: !!s.tls,
      }));
    }
    if (obj.healthCheck) {
      if (obj.healthCheck.interval) partial.healthCheckInterval = obj.healthCheck.interval;
      if (obj.healthCheck.timeout) partial.healthCheckTimeout = obj.healthCheck.timeout;
    }
    if (obj.proxyProtocol?.version) {
      partial.proxyProtocol = String(obj.proxyProtocol.version);
    }
    return partial;
  } catch {
    return {};
  }
}

/* -- HTTP calls ------------------------------------------------------ */

export async function listTcpRouters(): Promise<TcpRouter[]> {
  const body = await api.get<TcpRouter[] | { data?: TcpRouter[] }>("/api/v1/reverse-proxy/tcp/routers");
  return Array.isArray(body) ? body : body.data || [];
}

export async function createTcpRouter(body: TcpRouterBody): Promise<void> {
  await api.post<unknown>("/api/v1/reverse-proxy/tcp/routers", body);
}

export async function updateTcpRouter(id: string, body: TcpRouterBody): Promise<void> {
  await api.put<unknown>(`/api/v1/reverse-proxy/tcp/routers/${id}`, body);
}

export async function deleteTcpRouter(id: string): Promise<void> {
  await api.delete<unknown>(`/api/v1/reverse-proxy/tcp/routers/${id}`);
}

export async function listTcpServices(): Promise<TcpService[]> {
  const body = await api.get<TcpService[] | { data?: TcpService[] }>("/api/v1/reverse-proxy/tcp/services");
  return Array.isArray(body) ? body : body.data || [];
}

export async function createTcpService(body: TcpServiceBody): Promise<void> {
  await api.post<unknown>("/api/v1/reverse-proxy/tcp/services", body);
}

export async function updateTcpService(id: string, body: TcpServiceBody): Promise<void> {
  await api.put<unknown>(`/api/v1/reverse-proxy/tcp/services/${id}`, body);
}

export async function deleteTcpService(id: string): Promise<void> {
  await api.delete<unknown>(`/api/v1/reverse-proxy/tcp/services/${id}`);
}

export async function listEntryPoints(): Promise<EntryPoint[]> {
  const body = await api.get<EntryPoint[] | { data?: EntryPoint[] }>("/api/v1/reverse-proxy/entrypoints");
  return Array.isArray(body) ? body : body.data || [];
}
