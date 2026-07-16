import { api } from "@/lib/api";

/* -- Types ---------------------------------------------------------- */

export interface HttpRouter {
  id: string;
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  middlewares: string;
  priority: number;
  tls_json: string | null;
  enabled: boolean;
  created_at: string;
}

export interface Entrypoint {
  id: string;
  name: string;
}

export interface HttpService {
  id: string;
  name: string;
}

export interface HttpMiddleware {
  id: string;
  name: string;
}

export interface TlsConfig {
  certResolver: string;
  domains: string;
}

export interface RuleCondition {
  type: "Host" | "PathPrefix" | "Path" | "Method" | "Headers" | "ClientIP";
  value: string;
}

/// Request body for create/update (POST/PUT) of an HTTP router.
export interface HttpRouterPayload {
  name: string;
  rule: string;
  service: string;
  entry_points: string;
  middlewares: string;
  priority: number;
  tls_json: string | null;
  enabled: boolean;
}

/* -- HTTP calls ------------------------------------------------------ */

export async function listHttpRouters(): Promise<HttpRouter[]> {
  const data = await api.get<HttpRouter[] | { data?: HttpRouter[] }>("/api/v1/reverse-proxy/http/routers");
  return Array.isArray(data) ? data : data.data || [];
}

export async function listEntrypoints(): Promise<Entrypoint[]> {
  const data = await api.get<Entrypoint[] | { data?: Entrypoint[] }>("/api/v1/reverse-proxy/entrypoints");
  return Array.isArray(data) ? data : data.data || [];
}

export async function listHttpServices(): Promise<HttpService[]> {
  const data = await api.get<HttpService[] | { data?: HttpService[] }>("/api/v1/reverse-proxy/http/services");
  return Array.isArray(data) ? data : data.data || [];
}

export async function listHttpMiddlewares(): Promise<HttpMiddleware[]> {
  const data = await api.get<HttpMiddleware[] | { data?: HttpMiddleware[] }>("/api/v1/reverse-proxy/http/middlewares");
  return Array.isArray(data) ? data : data.data || [];
}

export async function createHttpRouter(body: HttpRouterPayload): Promise<void> {
  await api.post("/api/v1/reverse-proxy/http/routers", body);
}

/// PUT accepts either a form payload or a full router record (used by the
/// enabled toggle, which round-trips the existing row with `enabled` flipped).
export async function updateHttpRouter(id: string, body: HttpRouterPayload | HttpRouter): Promise<void> {
  await api.put(`/api/v1/reverse-proxy/http/routers/${id}`, body);
}

export async function deleteHttpRouter(id: string): Promise<void> {
  await api.delete(`/api/v1/reverse-proxy/http/routers/${id}`);
}

/* -- Helpers --------------------------------------------------------- */

export function parseJsonArray(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function parseTlsJson(raw: string | null): TlsConfig | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return {
      certResolver: parsed.certResolver || parsed.cert_resolver || "",
      domains: parsed.domains || "",
    };
  } catch {
    return null;
  }
}

export function buildRuleString(conditions: RuleCondition[], operators: string[]): string {
  if (conditions.length === 0) return "";
  let result = formatCondition(conditions[0]);
  for (let i = 1; i < conditions.length; i++) {
    const op = operators[i - 1] === "||" ? " || " : " && ";
    result += op + formatCondition(conditions[i]);
  }
  return result;
}

function formatCondition(c: RuleCondition): string {
  switch (c.type) {
    case "Host":
      return "Host(`" + c.value + "`)";
    case "PathPrefix":
      return "PathPrefix(`" + c.value + "`)";
    case "Path":
      return "Path(`" + c.value + "`)";
    case "Method":
      return "Method(`" + c.value + "`)";
    case "Headers": {
      const parts = c.value.split(":");
      const key = parts[0]?.trim() || "";
      const val = parts.slice(1).join(":").trim();
      return "Headers(`" + key + "`, `" + val + "`)";
    }
    case "ClientIP":
      return "ClientIP(`" + c.value + "`)";
    default:
      return c.value;
  }
}

export function parseRuleToConditions(rule: string): { conditions: RuleCondition[]; operators: string[] } {
  if (!rule.trim()) return { conditions: [], operators: [] };

  const conditions: RuleCondition[] = [];
  const operators: string[] = [];

  // Try to split on && and ||
  // We need to handle backtick-enclosed values that might contain && or ||
  const tokens: string[] = [];
  const ops: string[] = [];
  let depth = 0;
  let current = "";

  for (let i = 0; i < rule.length; i++) {
    const ch = rule[i];
    if (ch === "`") {
      depth = depth === 0 ? 1 : 0;
      current += ch;
    } else if (depth === 0 && i + 3 < rule.length && rule.substring(i, i + 4) === " && ") {
      tokens.push(current.trim());
      ops.push("&&");
      current = "";
      i += 3;
    } else if (depth === 0 && i + 3 < rule.length && rule.substring(i, i + 4) === " || ") {
      tokens.push(current.trim());
      ops.push("||");
      current = "";
      i += 3;
    } else {
      current += ch;
    }
  }
  if (current.trim()) tokens.push(current.trim());

  for (const token of tokens) {
    const condition = parseConditionToken(token);
    if (condition) {
      conditions.push(condition);
    }
  }

  for (const op of ops) {
    operators.push(op);
  }

  return { conditions, operators };
}

function parseConditionToken(token: string): RuleCondition | null {
  const match = token.match(/^(\w+)\((.+)\)$/);
  if (!match) return null;

  const type = match[1] as RuleCondition["type"];
  const inner = match[2];

  // Extract values from backticks
  const backtickValues: string[] = [];
  const re = /`([^`]*)`/g;
  let m;
  while ((m = re.exec(inner)) !== null) {
    backtickValues.push(m[1]);
  }

  const validTypes: RuleCondition["type"][] = ["Host", "PathPrefix", "Path", "Method", "Headers", "ClientIP"];
  if (!validTypes.includes(type)) return null;

  if (type === "Headers" && backtickValues.length >= 2) {
    return { type, value: backtickValues[0] + ": " + backtickValues[1] };
  }

  return { type, value: backtickValues[0] || "" };
}
