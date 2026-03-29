"use client";

import { useState, useEffect, useCallback } from "react";

/* -- Types ---------------------------------------------------------- */

interface HttpRouter {
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

interface Entrypoint {
  id: string;
  name: string;
}

interface HttpService {
  id: string;
  name: string;
}

interface HttpMiddleware {
  id: string;
  name: string;
}

interface TlsConfig {
  certResolver: string;
  domains: string;
}

interface RuleCondition {
  type: "Host" | "PathPrefix" | "Path" | "Method" | "Headers" | "ClientIP";
  value: string;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
}

/* -- Helpers --------------------------------------------------------- */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function parseJsonArray(raw: string): string[] {
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function parseTlsJson(raw: string | null): TlsConfig | null {
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

function buildRuleString(conditions: RuleCondition[], operators: string[]): string {
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

function parseRuleToConditions(rule: string): { conditions: RuleCondition[]; operators: string[] } {
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

const CONDITION_TYPES: { value: RuleCondition["type"]; label: string; placeholder: string }[] = [
  { value: "Host", label: "Host", placeholder: "example.com" },
  { value: "PathPrefix", label: "PathPrefix", placeholder: "/api" },
  { value: "Path", label: "Path", placeholder: "/exact/path" },
  { value: "Method", label: "Method", placeholder: "GET" },
  { value: "Headers", label: "Headers", placeholder: "X-Custom: value" },
  { value: "ClientIP", label: "ClientIP", placeholder: "192.168.1.0/24" },
];

/* -- Page ------------------------------------------------------------ */

export default function HttpRoutersPage() {
  const [routers, setRouters] = useState<HttpRouter[]>([]);
  const [entrypoints, setEntrypoints] = useState<Entrypoint[]>([]);
  const [services, setServices] = useState<HttpService[]>([]);
  const [middlewares, setMiddlewares] = useState<HttpMiddleware[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [showModal, setShowModal] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Form state
  const [formName, setFormName] = useState("");
  const [formEntryPoints, setFormEntryPoints] = useState<string[]>([]);
  const [formService, setFormService] = useState("");
  const [formMiddlewares, setFormMiddlewares] = useState<string[]>([]);
  const [formPriority, setFormPriority] = useState(0);
  const [formEnabled, setFormEnabled] = useState(true);
  const [formTlsCertResolver, setFormTlsCertResolver] = useState("");
  const [formTlsDomains, setFormTlsDomains] = useState("");
  const [showTls, setShowTls] = useState(false);

  // Rule builder
  const [ruleMode, setRuleMode] = useState<"visual" | "raw">("visual");
  const [ruleConditions, setRuleConditions] = useState<RuleCondition[]>([]);
  const [ruleOperators, setRuleOperators] = useState<string[]>([]);
  const [ruleRaw, setRuleRaw] = useState("");

  const showFeedback = (type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 6000);
  };

  /* -- Fetch -------------------------------------------------------- */

  const fetchRouters = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/http/routers", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setRouters(Array.isArray(data) ? data : data.data || []);
    } catch {
      showFeedback("error", "Failed to load HTTP routers");
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchEntrypoints = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/entrypoints", { headers: authHeadersPlain() });
      if (!res.ok) return;
      const data = await res.json();
      setEntrypoints(Array.isArray(data) ? data : data.data || []);
    } catch { /* silent */ }
  }, []);

  const fetchServices = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/http/services", { headers: authHeadersPlain() });
      if (!res.ok) return;
      const data = await res.json();
      setServices(Array.isArray(data) ? data : data.data || []);
    } catch { /* silent */ }
  }, []);

  const fetchMiddlewares = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/http/middlewares", { headers: authHeadersPlain() });
      if (!res.ok) return;
      const data = await res.json();
      setMiddlewares(Array.isArray(data) ? data : data.data || []);
    } catch { /* silent */ }
  }, []);

  useEffect(() => {
    Promise.all([fetchRouters(), fetchEntrypoints(), fetchServices(), fetchMiddlewares()]);
  }, [fetchRouters, fetchEntrypoints, fetchServices, fetchMiddlewares]);

  /* -- Form helpers -------------------------------------------------- */

  const resetForm = () => {
    setFormName("");
    setFormEntryPoints([]);
    setFormService("");
    setFormMiddlewares([]);
    setFormPriority(0);
    setFormEnabled(true);
    setFormTlsCertResolver("");
    setFormTlsDomains("");
    setShowTls(false);
    setRuleMode("visual");
    setRuleConditions([]);
    setRuleOperators([]);
    setRuleRaw("");
    setEditingId(null);
    setShowModal(false);
  };

  const openCreate = () => {
    resetForm();
    setShowModal(true);
  };

  const openEdit = (router: HttpRouter) => {
    setEditingId(router.id);
    setFormName(router.name);
    setFormEntryPoints(parseJsonArray(router.entry_points));
    setFormService(router.service);
    setFormMiddlewares(parseJsonArray(router.middlewares));
    setFormPriority(router.priority);
    setFormEnabled(router.enabled);

    const tls = parseTlsJson(router.tls_json);
    if (tls && (tls.certResolver || tls.domains)) {
      setFormTlsCertResolver(tls.certResolver);
      setFormTlsDomains(tls.domains);
      setShowTls(true);
    } else {
      setFormTlsCertResolver("");
      setFormTlsDomains("");
      setShowTls(false);
    }

    // Parse rule into conditions
    const { conditions, operators } = parseRuleToConditions(router.rule);
    if (conditions.length > 0) {
      setRuleMode("visual");
      setRuleConditions(conditions);
      setRuleOperators(operators);
      setRuleRaw(router.rule);
    } else {
      setRuleMode("raw");
      setRuleRaw(router.rule);
      setRuleConditions([]);
      setRuleOperators([]);
    }

    setShowModal(true);
  };

  const getCurrentRule = (): string => {
    if (ruleMode === "raw") return ruleRaw;
    return buildRuleString(ruleConditions, ruleOperators);
  };

  const buildTlsJson = (): string | null => {
    if (!showTls || (!formTlsCertResolver.trim() && !formTlsDomains.trim())) return null;
    return JSON.stringify({
      certResolver: formTlsCertResolver.trim(),
      domains: formTlsDomains.trim(),
    });
  };

  /* -- CRUD --------------------------------------------------------- */

  const handleSubmit = async () => {
    const rule = getCurrentRule();
    if (!formName.trim() || !rule.trim()) return;
    setSubmitting(true);
    try {
      const body = {
        name: formName.trim(),
        rule,
        service: formService,
        entry_points: JSON.stringify(formEntryPoints),
        middlewares: JSON.stringify(formMiddlewares),
        priority: formPriority,
        tls_json: buildTlsJson(),
        enabled: formEnabled,
      };

      const url = editingId
        ? `/api/v1/reverse-proxy/http/routers/${editingId}`
        : "/api/v1/reverse-proxy/http/routers";
      const method = editingId ? "PUT" : "POST";

      const res = await fetch(url, {
        method,
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({ message: `HTTP ${res.status}` }));
        throw new Error(errData.message || errData.error || `HTTP ${res.status}`);
      }

      showFeedback("success", editingId ? "Router updated" : "Router created");
      resetForm();
      await fetchRouters();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save router");
    } finally {
      setSubmitting(false);
    }
  };

  const handleDelete = async (id: string) => {
    setDeletingId(id);
    try {
      const res = await fetch(`/api/v1/reverse-proxy/http/routers/${id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      showFeedback("success", "Router deleted");
      setRouters((prev) => prev.filter((r) => r.id !== id));
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete router");
    } finally {
      setDeletingId(null);
    }
  };

  const handleToggleEnabled = async (router: HttpRouter) => {
    try {
      const res = await fetch(`/api/v1/reverse-proxy/http/routers/${router.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify({ ...router, enabled: !router.enabled }),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setRouters((prev) =>
        prev.map((r) => (r.id === router.id ? { ...r, enabled: !r.enabled } : r))
      );
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to toggle router");
    }
  };

  /* -- Rule builder actions ----------------------------------------- */

  const addCondition = () => {
    setRuleConditions((prev) => [...prev, { type: "Host", value: "" }]);
    if (ruleConditions.length > 0) {
      setRuleOperators((prev) => [...prev, "&&"]);
    }
  };

  const removeCondition = (idx: number) => {
    setRuleConditions((prev) => prev.filter((_, i) => i !== idx));
    setRuleOperators((prev) => {
      const next = [...prev];
      if (idx === 0 && next.length > 0) {
        next.splice(0, 1);
      } else if (idx > 0) {
        next.splice(idx - 1, 1);
      }
      return next;
    });
  };

  const updateConditionType = (idx: number, type: RuleCondition["type"]) => {
    setRuleConditions((prev) => prev.map((c, i) => (i === idx ? { ...c, type } : c)));
  };

  const updateConditionValue = (idx: number, value: string) => {
    setRuleConditions((prev) => prev.map((c, i) => (i === idx ? { ...c, value } : c)));
  };

  const toggleOperator = (idx: number) => {
    setRuleOperators((prev) =>
      prev.map((op, i) => (i === idx ? (op === "&&" ? "||" : "&&") : op))
    );
  };

  const toggleEntryPoint = (name: string) => {
    setFormEntryPoints((prev) =>
      prev.includes(name) ? prev.filter((e) => e !== name) : [...prev, name]
    );
  };

  const toggleMiddleware = (name: string) => {
    setFormMiddlewares((prev) =>
      prev.includes(name) ? prev.filter((m) => m !== name) : [...prev, name]
    );
  };

  const removeMiddleware = (name: string) => {
    setFormMiddlewares((prev) => prev.filter((m) => m !== name));
  };

  /* -- Render ------------------------------------------------------- */

  const inputCls =
    "w-full bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors";
  const selectCls =
    "w-full bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors";
  const labelCls = "block text-xs text-[var(--text-muted)] mb-1";
  const chipCls =
    "inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-500/15 text-blue-400 border border-blue-500/30";

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading HTTP routers...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-[var(--text-primary)]">HTTP Routers</h1>
          <p className="text-sm text-[var(--text-muted)]">
            Route incoming HTTP requests to backend services based on rules
          </p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Router
        </button>
      </div>

      {/* Feedback */}
      {feedback && (
        <div
          className={`px-4 py-3 rounded-lg text-sm border ${
            feedback.type === "success"
              ? "bg-green-500/10 border-green-500/30 text-green-400"
              : "bg-red-500/10 border-red-500/30 text-red-400"
          }`}
        >
          {feedback.msg}
        </div>
      )}

      {/* Table */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--border)]">
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Name</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Rule</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Entry Points</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Service</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">Middlewares</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-20">Priority</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-16">TLS</th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider w-20">Enabled</th>
                <th className="w-24"></th>
              </tr>
            </thead>
            <tbody>
              {routers.length === 0 ? (
                <tr>
                  <td colSpan={9} className="text-center py-12 text-[var(--text-muted)]">
                    No HTTP routers configured
                  </td>
                </tr>
              ) : (
                routers.map((router) => {
                  const eps = parseJsonArray(router.entry_points);
                  const mws = parseJsonArray(router.middlewares);
                  const hasTls = !!router.tls_json;

                  return (
                    <tr
                      key={router.id}
                      className="border-b border-[var(--border)] hover:bg-[var(--bg-secondary)] transition-colors"
                    >
                      {/* Name */}
                      <td className="py-2.5 px-3">
                        <span className="font-medium text-[var(--text-primary)]">{router.name}</span>
                      </td>
                      {/* Rule (truncated) */}
                      <td className="py-2.5 px-3 max-w-[260px]">
                        <span
                          className="font-mono text-xs text-[var(--text-secondary)] truncate block"
                          title={router.rule}
                        >
                          {router.rule.length > 60 ? router.rule.substring(0, 60) + "..." : router.rule}
                        </span>
                      </td>
                      {/* Entry Points */}
                      <td className="py-2.5 px-3">
                        <div className="flex flex-wrap gap-1">
                          {eps.map((ep) => (
                            <span key={ep} className={chipCls}>{ep}</span>
                          ))}
                          {eps.length === 0 && <span className="text-xs text-[var(--text-muted)]">-</span>}
                        </div>
                      </td>
                      {/* Service */}
                      <td className="py-2.5 px-3">
                        <span className="text-xs text-[var(--text-secondary)]">{router.service || "-"}</span>
                      </td>
                      {/* Middlewares */}
                      <td className="py-2.5 px-3">
                        <div className="flex flex-wrap gap-1">
                          {mws.map((mw) => (
                            <span
                              key={mw}
                              className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30"
                            >
                              {mw}
                            </span>
                          ))}
                          {mws.length === 0 && <span className="text-xs text-[var(--text-muted)]">-</span>}
                        </div>
                      </td>
                      {/* Priority */}
                      <td className="py-2.5 px-3 text-center">
                        <span className="text-xs text-[var(--text-secondary)] font-mono">{router.priority}</span>
                      </td>
                      {/* TLS */}
                      <td className="py-2.5 px-3 text-center">
                        {hasTls ? (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/30">
                            TLS
                          </span>
                        ) : (
                          <span className="text-xs text-[var(--text-muted)]">-</span>
                        )}
                      </td>
                      {/* Enabled toggle */}
                      <td className="py-2.5 px-3">
                        <button
                          onClick={() => handleToggleEnabled(router)}
                          className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none"
                          style={{
                            backgroundColor: router.enabled ? "#2563eb" : "#4b5563",
                          }}
                          title={router.enabled ? "Disable" : "Enable"}
                        >
                          <span
                            className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                              router.enabled ? "translate-x-[18px]" : "translate-x-[3px]"
                            }`}
                          />
                        </button>
                      </td>
                      {/* Actions */}
                      <td className="py-2.5 px-2">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => openEdit(router)}
                            className="text-[var(--text-muted)] hover:text-blue-400 transition-colors p-1"
                            title="Edit"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10" />
                            </svg>
                          </button>
                          <button
                            onClick={() => handleDelete(router.id)}
                            disabled={deletingId === router.id}
                            className="text-[var(--text-muted)] hover:text-red-400 transition-colors p-1 disabled:opacity-50"
                            title="Delete"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal Overlay */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={resetForm}
          />

          {/* Modal */}
          <div className="relative bg-[var(--bg-card)] border border-[var(--border)] rounded-lg shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto mx-4">
            {/* Modal Header */}
            <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
              <h2 className="text-lg font-semibold text-[var(--text-primary)]">
                {editingId ? "Edit Router" : "New HTTP Router"}
              </h2>
              <button
                onClick={resetForm}
                className="text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal Body */}
            <div className="px-6 py-4 space-y-5">
              {/* Name */}
              <div>
                <label className={labelCls}>Name *</label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="my-router"
                  className={inputCls}
                />
              </div>

              {/* Entry Points */}
              <div>
                <label className={labelCls}>Entry Points</label>
                {entrypoints.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)]">No entrypoints available. Create entrypoints first.</p>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {entrypoints.map((ep) => {
                      const selected = formEntryPoints.includes(ep.name);
                      return (
                        <button
                          key={ep.id}
                          type="button"
                          onClick={() => toggleEntryPoint(ep.name)}
                          className={`inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium border transition-colors ${
                            selected
                              ? "bg-blue-500/20 text-blue-400 border-blue-500/40"
                              : "bg-[var(--bg-secondary)] text-[var(--text-muted)] border-[var(--border)] hover:border-blue-500/30 hover:text-blue-400"
                          }`}
                        >
                          {selected && (
                            <svg className="w-3 h-3 mr-1" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                            </svg>
                          )}
                          {ep.name}
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Rule Builder */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className={labelCls + " mb-0"}>Rule *</label>
                  <div className="flex items-center bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md overflow-hidden">
                    <button
                      type="button"
                      onClick={() => {
                        if (ruleMode === "raw") {
                          // Switching from raw to visual: try to parse
                          const { conditions, operators } = parseRuleToConditions(ruleRaw);
                          if (conditions.length > 0 || !ruleRaw.trim()) {
                            setRuleConditions(conditions);
                            setRuleOperators(operators);
                            setRuleMode("visual");
                          } else {
                            // Can't parse, stay in raw
                            showFeedback("error", "Cannot parse rule into visual conditions. Edit manually.");
                          }
                        } else {
                          setRuleMode("visual");
                        }
                      }}
                      className={`px-3 py-1 text-xs font-medium transition-colors ${
                        ruleMode === "visual"
                          ? "bg-blue-600 text-white"
                          : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      Visual
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (ruleMode === "visual") {
                          // Switching from visual to raw: serialize conditions
                          setRuleRaw(buildRuleString(ruleConditions, ruleOperators));
                        }
                        setRuleMode("raw");
                      }}
                      className={`px-3 py-1 text-xs font-medium transition-colors ${
                        ruleMode === "raw"
                          ? "bg-blue-600 text-white"
                          : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
                      }`}
                    >
                      Raw
                    </button>
                  </div>
                </div>

                {ruleMode === "visual" ? (
                  <div className="space-y-2">
                    {ruleConditions.length === 0 && (
                      <p className="text-xs text-[var(--text-muted)] py-2">No conditions yet. Add one below.</p>
                    )}

                    {ruleConditions.map((cond, idx) => (
                      <div key={idx}>
                        {/* Operator between rows */}
                        {idx > 0 && (
                          <div className="flex items-center justify-center py-1">
                            <button
                              type="button"
                              onClick={() => toggleOperator(idx - 1)}
                              className="px-3 py-0.5 text-xs font-mono font-bold rounded border transition-colors bg-[var(--bg-secondary)] border-[var(--border)] text-[var(--text-secondary)] hover:border-blue-500/40 hover:text-blue-400"
                            >
                              {ruleOperators[idx - 1] === "||" ? "OR" : "AND"}
                            </button>
                          </div>
                        )}

                        {/* Condition row */}
                        <div className="flex items-center gap-2">
                          <select
                            value={cond.type}
                            onChange={(e) => updateConditionType(idx, e.target.value as RuleCondition["type"])}
                            className="bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-2 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 w-36 shrink-0"
                          >
                            {CONDITION_TYPES.map((ct) => (
                              <option key={ct.value} value={ct.value}>
                                {ct.label}
                              </option>
                            ))}
                          </select>
                          <input
                            type="text"
                            value={cond.value}
                            onChange={(e) => updateConditionValue(idx, e.target.value)}
                            placeholder={CONDITION_TYPES.find((ct) => ct.value === cond.type)?.placeholder || "value"}
                            className={inputCls}
                          />
                          <button
                            type="button"
                            onClick={() => removeCondition(idx)}
                            className="text-[var(--text-muted)] hover:text-red-400 transition-colors p-1 shrink-0"
                            title="Remove condition"
                          >
                            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                            </svg>
                          </button>
                        </div>
                      </div>
                    ))}

                    <button
                      type="button"
                      onClick={addCondition}
                      className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors mt-1"
                    >
                      <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
                      </svg>
                      Add Condition
                    </button>

                    {/* Rule preview */}
                    {ruleConditions.length > 0 && (
                      <div className="mt-2 p-2 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md">
                        <span className="text-[10px] text-[var(--text-muted)] uppercase tracking-wider block mb-1">Preview</span>
                        <code className="text-xs text-[var(--text-secondary)] font-mono break-all">
                          {buildRuleString(ruleConditions, ruleOperators) || "(empty)"}
                        </code>
                      </div>
                    )}
                  </div>
                ) : (
                  <textarea
                    value={ruleRaw}
                    onChange={(e) => setRuleRaw(e.target.value)}
                    placeholder='Host(`example.com`) && PathPrefix(`/api`)'
                    rows={3}
                    className={inputCls + " font-mono resize-y"}
                  />
                )}
              </div>

              {/* Service */}
              <div>
                <label className={labelCls}>Service</label>
                <select
                  value={formService}
                  onChange={(e) => setFormService(e.target.value)}
                  className={selectCls}
                >
                  <option value="">-- Select a service --</option>
                  {services.map((s) => (
                    <option key={s.id} value={s.name}>
                      {s.name}
                    </option>
                  ))}
                </select>
              </div>

              {/* Middlewares */}
              <div>
                <label className={labelCls}>Middlewares</label>
                {middlewares.length === 0 ? (
                  <p className="text-xs text-[var(--text-muted)]">No middlewares available.</p>
                ) : (
                  <>
                    {/* Selected middlewares in order */}
                    {formMiddlewares.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mb-2">
                        {formMiddlewares.map((mw, idx) => (
                          <span
                            key={mw}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/30"
                          >
                            <span className="text-[10px] text-purple-400/60 font-mono mr-0.5">{idx + 1}.</span>
                            {mw}
                            <button
                              type="button"
                              onClick={() => removeMiddleware(mw)}
                              className="ml-0.5 hover:text-red-400 transition-colors"
                            >
                              <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                              </svg>
                            </button>
                          </span>
                        ))}
                      </div>
                    )}
                    <div className="flex flex-wrap gap-2">
                      {middlewares
                        .filter((mw) => !formMiddlewares.includes(mw.name))
                        .map((mw) => (
                          <button
                            key={mw.id}
                            type="button"
                            onClick={() => toggleMiddleware(mw.name)}
                            className="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-medium border transition-colors bg-[var(--bg-secondary)] text-[var(--text-muted)] border-[var(--border)] hover:border-purple-500/30 hover:text-purple-400"
                          >
                            {mw.name}
                          </button>
                        ))}
                    </div>
                  </>
                )}
              </div>

              {/* Priority */}
              <div>
                <label className={labelCls}>Priority</label>
                <input
                  type="number"
                  value={formPriority}
                  onChange={(e) => setFormPriority(parseInt(e.target.value, 10) || 0)}
                  className={inputCls + " w-32"}
                />
                <p className="text-[10px] text-[var(--text-muted)] mt-1">Higher priority routes are evaluated first. Default is 0.</p>
              </div>

              {/* TLS Section */}
              <div>
                <button
                  type="button"
                  onClick={() => setShowTls(!showTls)}
                  className="flex items-center gap-2 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
                >
                  <svg
                    className={`w-4 h-4 transition-transform ${showTls ? "rotate-90" : ""}`}
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                  TLS Configuration
                  {showTls && (formTlsCertResolver || formTlsDomains) && (
                    <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-green-500/15 text-green-400 border border-green-500/30">
                      Configured
                    </span>
                  )}
                </button>

                {showTls && (
                  <div className="mt-3 p-4 bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md space-y-3">
                    <div>
                      <label className={labelCls}>Cert Resolver</label>
                      <input
                        type="text"
                        value={formTlsCertResolver}
                        onChange={(e) => setFormTlsCertResolver(e.target.value)}
                        placeholder="letsencrypt"
                        className={inputCls}
                      />
                    </div>
                    <div>
                      <label className={labelCls}>Domains (SANs, comma-separated)</label>
                      <input
                        type="text"
                        value={formTlsDomains}
                        onChange={(e) => setFormTlsDomains(e.target.value)}
                        placeholder="example.com, *.example.com"
                        className={inputCls}
                      />
                      <p className="text-[10px] text-[var(--text-muted)] mt-1">Comma-separated list of Subject Alternative Names</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Enabled */}
              <div className="flex items-center justify-between">
                <label className="text-sm text-[var(--text-secondary)]">Enabled</label>
                <button
                  type="button"
                  onClick={() => setFormEnabled(!formEnabled)}
                  className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                    formEnabled ? "bg-blue-600" : "bg-gray-600"
                  }`}
                >
                  <span
                    className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                      formEnabled ? "translate-x-6" : "translate-x-1"
                    }`}
                  />
                </button>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[var(--border)]">
              <button
                onClick={resetForm}
                className="px-4 py-2 text-sm font-medium rounded-md bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting || !formName.trim() || !getCurrentRule().trim()}
                className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {submitting ? "Saving..." : editingId ? "Update Router" : "Create Router"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
