import { api } from "@/lib/api";

/* ── Types ────────────────────────────────────────────────────── */

export interface HttpMiddleware {
  id: string;
  name: string;
  middleware_type: string;
  config_json: string;
  enabled: boolean;
  created_at: string;
}

/// Request body for create/update (POST/PUT) of an HTTP middleware.
export interface HttpMiddlewareBody {
  name: string;
  middleware_type: string;
  config_json: string;
  enabled: boolean;
}

/* ── Helpers ──────────────────────────────────────────────────── */

export function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/* ── Middleware categories & badge colors ─────────────────────── */

export const MIDDLEWARE_CATEGORIES: Record<string, { label: string; types: string[] }> = {
  rateLimiting: { label: "Rate Limiting", types: ["rateLimit", "inFlightReq"] },
  accessControl: {
    label: "Access Control",
    types: ["ipAllowList", "ipDenyList", "basicAuth", "digestAuth", "forwardAuth", "jwt"],
  },
  headers: { label: "Headers & Content", types: ["headers", "passTLSClientCert", "contentType"] },
  compression: { label: "Compression", types: ["compress"] },
  redirects: { label: "Redirects", types: ["redirectScheme", "redirectRegex"] },
  pathManipulation: {
    label: "Path Manipulation",
    types: ["stripPrefix", "stripPrefixRegex", "addPrefix", "replacePath", "replacePathRegex"],
  },
  reliability: { label: "Reliability", types: ["retry", "circuitBreaker"] },
  buffering: { label: "Buffering", types: ["buffering"] },
  composition: { label: "Composition", types: ["chain"] },
  protocol: { label: "Protocol", types: ["grpcWeb"] },
  errorHandling: { label: "Error Handling", types: ["errors"] },
};

export const CATEGORY_COLORS: Record<string, string> = {
  rateLimiting: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  accessControl: "bg-red-500/20 text-red-400 border-red-500/30",
  headers: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  compression: "bg-green-500/20 text-green-400 border-green-500/30",
  redirects: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  pathManipulation: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  reliability: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  buffering: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  composition: "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
  protocol: "bg-pink-500/20 text-pink-400 border-pink-500/30",
  errorHandling: "bg-amber-500/20 text-amber-400 border-amber-500/30",
};

export function getCategoryForType(mtype: string): string {
  for (const [cat, info] of Object.entries(MIDDLEWARE_CATEGORIES)) {
    if (info.types.includes(mtype)) return cat;
  }
  return "headers";
}

/* ── Default config_json per type ─────────────────────────────── */

export function defaultConfigForType(mtype: string): any {
  switch (mtype) {
    case "rateLimit":
      return { average: 100, burst: 200, period: "1s", sourceCriterion: { ipStrategy: { depth: 0 } } };
    case "inFlightReq":
      return { amount: 10 };
    case "ipAllowList":
      return { sourceRange: ["10.0.0.0/8", "172.16.0.0/12"] };
    case "ipDenyList":
      return { sourceRange: ["1.2.3.4/32"] };
    case "basicAuth":
      return { users: [], realm: "Restricted", removeHeader: true };
    case "digestAuth":
      return { users: [], realm: "Restricted", removeHeader: true };
    case "forwardAuth":
      return { address: "http://auth-svc:9091/verify", trustForwardHeader: true, authResponseHeaders: ["X-User"] };
    case "jwt":
      return { secret: "", algorithm: "HS256", headerName: "Authorization", headerPrefix: "Bearer ", stripAuthorizationHeader: false };
    case "headers":
      return {
        customRequestHeaders: {},
        customResponseHeaders: {},
        frameDeny: false,
        contentTypeNosniff: false,
        browserXssFilter: false,
        stsSeconds: 0,
        stsIncludeSubdomains: false,
        sslRedirect: false,
        contentSecurityPolicy: "",
      };
    case "passTLSClientCert":
      return { pem: false };
    case "contentType":
      return { autoDetect: true };
    case "compress":
      return { minResponseBodyBytes: 1024, encodings: ["zstd", "br", "gzip"] };
    case "redirectScheme":
      return { scheme: "https", permanent: true, port: "" };
    case "redirectRegex":
      return { regex: "", replacement: "", permanent: true };
    case "stripPrefix":
      return { prefixes: ["/api"] };
    case "stripPrefixRegex":
      return { regex: ["/api/v[0-9]+"] };
    case "addPrefix":
      return { prefix: "/api" };
    case "replacePath":
      return { path: "/new-path" };
    case "replacePathRegex":
      return { regex: "", replacement: "" };
    case "retry":
      return { attempts: 3, initialInterval: "100ms" };
    case "circuitBreaker":
      return { expression: "NetworkErrorRatio() > 0.5", checkPeriod: "100ms", fallbackDuration: "10s", recoveryDuration: "10s", responseCode: 503 };
    case "buffering":
      return { maxRequestBodyBytes: 1048576, memRequestBodyBytes: 1048576, maxResponseBodyBytes: 1048576, memResponseBodyBytes: 1048576 };
    case "chain":
      return { middlewares: [] };
    case "grpcWeb":
      return { allowOrigins: ["*"] };
    case "errors":
      return { status: ["500-599"], service: "error-handler", query: "/error?status={status}" };
    default:
      return {};
  }
}

/* ── HTTP calls ───────────────────────────────────────────────── */

export async function listHttpMiddlewares(): Promise<HttpMiddleware[]> {
  const data = await api.get<HttpMiddleware[] | { data?: HttpMiddleware[] }>(
    "/api/v1/reverse-proxy/http/middlewares"
  );
  return Array.isArray(data) ? data : data.data || [];
}

export async function createHttpMiddleware(body: HttpMiddlewareBody): Promise<void> {
  await api.post<unknown>("/api/v1/reverse-proxy/http/middlewares", body);
}

export async function updateHttpMiddleware(id: string, body: HttpMiddlewareBody): Promise<void> {
  await api.put<unknown>(`/api/v1/reverse-proxy/http/middlewares/${id}`, body);
}

export async function deleteHttpMiddleware(id: string): Promise<void> {
  await api.delete<unknown>(`/api/v1/reverse-proxy/http/middlewares/${id}`);
}
