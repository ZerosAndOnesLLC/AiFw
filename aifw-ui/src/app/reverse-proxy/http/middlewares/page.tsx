"use client";

import { useState, useEffect, useCallback } from "react";

/* ── Types ────────────────────────────────────────────────────── */

interface HttpMiddleware {
  id: string;
  name: string;
  middleware_type: string;
  config_json: string;
  enabled: boolean;
  created_at: string;
}

interface Feedback {
  type: "success" | "error";
  msg: string;
}

/* ── Helpers ──────────────────────────────────────────────────── */

function authHeaders(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { "Content-Type": "application/json", Authorization: `Bearer ${token}` };
}

function authHeadersPlain(): HeadersInit {
  const token = localStorage.getItem("aifw_token") || "";
  return { Authorization: `Bearer ${token}` };
}

function fmtDate(iso: string): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

/* ── Middleware categories & badge colors ─────────────────────── */

const MIDDLEWARE_CATEGORIES: Record<string, { label: string; types: string[] }> = {
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

const CATEGORY_COLORS: Record<string, string> = {
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

function getCategoryForType(mtype: string): string {
  for (const [cat, info] of Object.entries(MIDDLEWARE_CATEGORIES)) {
    if (info.types.includes(mtype)) return cat;
  }
  return "headers";
}

function TypeBadge({ mtype }: { mtype: string }) {
  const cat = getCategoryForType(mtype);
  const cls = CATEGORY_COLORS[cat] || "bg-gray-500/20 text-gray-400 border-gray-500/30";
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls} font-medium`}>
      {mtype}
    </span>
  );
}

/* ── Default config_json per type ─────────────────────────────── */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function defaultConfigForType(mtype: string): any {
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

/* ── Page ─────────────────────────────────────────────────────── */

export default function HttpMiddlewaresPage() {
  const [middlewares, setMiddlewares] = useState<HttpMiddleware[]>([]);
  const [loading, setLoading] = useState(true);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  // Form state
  const [formName, setFormName] = useState("");
  const [formType, setFormType] = useState("rateLimit");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [formConfig, setFormConfig] = useState<any>(defaultConfigForType("rateLimit"));
  const [formEnabled, setFormEnabled] = useState(true);

  const showFeedback = useCallback((type: "success" | "error", msg: string) => {
    setFeedback({ type, msg });
    setTimeout(() => setFeedback(null), 5000);
  }, []);

  /* ── Fetch ─────────────────────────────────────────────────── */

  const fetchMiddlewares = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/reverse-proxy/http/middlewares", { headers: authHeadersPlain() });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setMiddlewares(Array.isArray(data) ? data : data.data || []);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to load middlewares");
    } finally {
      setLoading(false);
    }
  }, [showFeedback]);

  useEffect(() => {
    fetchMiddlewares();
  }, [fetchMiddlewares]);

  /* ── Modal helpers ──────────────────────────────────────────── */

  function openCreate() {
    setEditingId(null);
    setFormName("");
    setFormType("rateLimit");
    setFormConfig(defaultConfigForType("rateLimit"));
    setFormEnabled(true);
    setModalOpen(true);
  }

  function openEdit(mw: HttpMiddleware) {
    setEditingId(mw.id);
    setFormName(mw.name);
    setFormType(mw.middleware_type);
    try {
      setFormConfig(JSON.parse(mw.config_json));
    } catch {
      setFormConfig(defaultConfigForType(mw.middleware_type));
    }
    setFormEnabled(mw.enabled);
    setModalOpen(true);
  }

  function closeModal() {
    setModalOpen(false);
    setEditingId(null);
  }

  function handleTypeChange(newType: string) {
    setFormType(newType);
    setFormConfig(defaultConfigForType(newType));
  }

  /* ── CRUD ───────────────────────────────────────────────────── */

  async function handleSubmit() {
    if (!formName.trim()) return;
    setSubmitting(true);
    try {
      const body = {
        name: formName.trim(),
        middleware_type: formType,
        config_json: JSON.stringify(formConfig),
        enabled: formEnabled,
      };
      const url = editingId
        ? `/api/v1/reverse-proxy/http/middlewares/${editingId}`
        : "/api/v1/reverse-proxy/http/middlewares";
      const method = editingId ? "PUT" : "POST";
      const res = await fetch(url, { method, headers: authHeaders(), body: JSON.stringify(body) });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.error || errBody.message || `HTTP ${res.status}`);
      }
      showFeedback("success", editingId ? "Middleware updated" : "Middleware created");
      closeModal();
      await fetchMiddlewares();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save middleware");
    } finally {
      setSubmitting(false);
    }
  }

  async function handleDelete(mw: HttpMiddleware) {
    if (!confirm(`Delete middleware "${mw.name}"?`)) return;
    setDeletingId(mw.id);
    try {
      const res = await fetch(`/api/v1/reverse-proxy/http/middlewares/${mw.id}`, {
        method: "DELETE",
        headers: authHeaders(),
      });
      if (!res.ok) {
        const errBody = await res.json().catch(() => ({}));
        throw new Error(errBody.error || errBody.message || `HTTP ${res.status}`);
      }
      showFeedback("success", `Middleware "${mw.name}" deleted`);
      await fetchMiddlewares();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to delete middleware");
    } finally {
      setDeletingId(null);
    }
  }

  async function handleToggleEnabled(mw: HttpMiddleware) {
    try {
      const body = {
        name: mw.name,
        middleware_type: mw.middleware_type,
        config_json: mw.config_json,
        enabled: !mw.enabled,
      };
      const res = await fetch(`/api/v1/reverse-proxy/http/middlewares/${mw.id}`, {
        method: "PUT",
        headers: authHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setMiddlewares((prev) =>
        prev.map((m) => (m.id === mw.id ? { ...m, enabled: !mw.enabled } : m))
      );
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to toggle middleware");
    }
  }

  /* ── Config update helper ──────────────────────────────────── */

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function updateConfig(key: string, value: any) {
    setFormConfig((prev: Record<string, unknown>) => ({ ...prev, [key]: value }));
  }

  /* ── Key-value editor (for headers) ────────────────────────── */

  function KeyValueEditor({
    label,
    value,
    onChange,
  }: {
    label: string;
    value: Record<string, string>;
    onChange: (v: Record<string, string>) => void;
  }) {
    const entries = Object.entries(value || {});

    function addRow() {
      onChange({ ...value, "": "" });
    }

    function removeRow(key: string) {
      const next = { ...value };
      delete next[key];
      onChange(next);
    }

    function updateRow(oldKey: string, newKey: string, newValue: string) {
      const next: Record<string, string> = {};
      for (const [k, v] of Object.entries(value)) {
        if (k === oldKey) {
          next[newKey] = newValue;
        } else {
          next[k] = v;
        }
      }
      onChange(next);
    }

    return (
      <div>
        <div className="flex items-center justify-between mb-1">
          <label className="block text-xs text-gray-400">{label}</label>
          <button
            type="button"
            onClick={addRow}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            + Add
          </button>
        </div>
        {entries.length === 0 && (
          <p className="text-xs text-gray-500 italic">No entries</p>
        )}
        <div className="space-y-1.5">
          {entries.map(([k, v], i) => (
            <div key={i} className="flex items-center gap-2">
              <input
                type="text"
                value={k}
                onChange={(e) => updateRow(k, e.target.value, v)}
                placeholder="Header name"
                className="flex-1 bg-gray-900 border border-gray-600 rounded-md px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <input
                type="text"
                value={v}
                onChange={(e) => updateRow(k, k, e.target.value)}
                placeholder="Value"
                className="flex-1 bg-gray-900 border border-gray-600 rounded-md px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <button
                type="button"
                onClick={() => removeRow(k)}
                className="text-gray-500 hover:text-red-400 transition-colors"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}
        </div>
      </div>
    );
  }

  /* ── Toggle component ──────────────────────────────────────── */

  function Toggle({
    label,
    checked,
    onChange,
  }: {
    label: string;
    checked: boolean;
    onChange: (v: boolean) => void;
  }) {
    return (
      <div className="flex items-center justify-between">
        <label className="text-sm text-gray-300">{label}</label>
        <button
          type="button"
          onClick={() => onChange(!checked)}
          className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
            checked ? "bg-blue-600" : "bg-gray-600"
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
              checked ? "translate-x-6" : "translate-x-1"
            }`}
          />
        </button>
      </div>
    );
  }

  /* ── Type-specific form fields ─────────────────────────────── */

  function renderTypeForm() {
    const inputCls =
      "w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500";
    const selectCls =
      "w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500";
    const labelCls = "block text-xs text-gray-400 mb-1";
    const textareaCls =
      "w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 font-mono";

    switch (formType) {
      /* ── Rate Limiting ─────────────────────────────────────── */
      case "rateLimit":
        return (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Average (req/period)</label>
                <input
                  type="number"
                  value={formConfig.average ?? 100}
                  onChange={(e) => updateConfig("average", parseInt(e.target.value) || 0)}
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Burst</label>
                <input
                  type="number"
                  value={formConfig.burst ?? 200}
                  onChange={(e) => updateConfig("burst", parseInt(e.target.value) || 0)}
                  className={inputCls}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Period</label>
                <input
                  type="text"
                  value={formConfig.period ?? "1s"}
                  onChange={(e) => updateConfig("period", e.target.value)}
                  placeholder="1s"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Source IP Depth</label>
                <input
                  type="number"
                  value={formConfig.sourceCriterion?.ipStrategy?.depth ?? 0}
                  onChange={(e) =>
                    setFormConfig((prev: Record<string, unknown>) => ({
                      ...prev,
                      sourceCriterion: {
                        ipStrategy: { depth: parseInt(e.target.value) || 0 },
                      },
                    }))
                  }
                  className={inputCls}
                />
              </div>
            </div>
          </div>
        );

      case "inFlightReq":
        return (
          <div>
            <label className={labelCls}>Max Concurrent Requests</label>
            <input
              type="number"
              value={formConfig.amount ?? 10}
              onChange={(e) => updateConfig("amount", parseInt(e.target.value) || 0)}
              className={inputCls}
            />
          </div>
        );

      /* ── Access Control ────────────────────────────────────── */
      case "ipAllowList":
      case "ipDenyList":
        return (
          <div>
            <label className={labelCls}>Source Ranges (one CIDR per line)</label>
            <textarea
              rows={5}
              value={(formConfig.sourceRange || []).join("\n")}
              onChange={(e) =>
                updateConfig(
                  "sourceRange",
                  e.target.value.split("\n").filter((l: string) => l.trim())
                )
              }
              placeholder={"10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16"}
              className={textareaCls}
            />
          </div>
        );

      case "basicAuth":
      case "digestAuth":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>
                Users (one {formType === "basicAuth" ? "user:hash" : "user:realm:hash"} per line)
              </label>
              <textarea
                rows={4}
                value={(formConfig.users || []).join("\n")}
                onChange={(e) =>
                  updateConfig(
                    "users",
                    e.target.value.split("\n").filter((l: string) => l.trim())
                  )
                }
                placeholder={formType === "basicAuth" ? "user:$apr1$..." : "user:realm:hash"}
                className={textareaCls}
              />
            </div>
            <div>
              <label className={labelCls}>Realm</label>
              <input
                type="text"
                value={formConfig.realm ?? "Restricted"}
                onChange={(e) => updateConfig("realm", e.target.value)}
                className={inputCls}
              />
            </div>
            <Toggle
              label="Remove Header"
              checked={formConfig.removeHeader ?? true}
              onChange={(v) => updateConfig("removeHeader", v)}
            />
          </div>
        );

      case "forwardAuth":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Address (URL)</label>
              <input
                type="text"
                value={formConfig.address ?? ""}
                onChange={(e) => updateConfig("address", e.target.value)}
                placeholder="http://auth-svc:9091/verify"
                className={inputCls}
              />
            </div>
            <Toggle
              label="Trust Forward Header"
              checked={formConfig.trustForwardHeader ?? true}
              onChange={(v) => updateConfig("trustForwardHeader", v)}
            />
            <div>
              <label className={labelCls}>Auth Response Headers (one per line)</label>
              <textarea
                rows={3}
                value={(formConfig.authResponseHeaders || []).join("\n")}
                onChange={(e) =>
                  updateConfig(
                    "authResponseHeaders",
                    e.target.value.split("\n").filter((l: string) => l.trim())
                  )
                }
                placeholder="X-User\nX-Email"
                className={textareaCls}
              />
            </div>
          </div>
        );

      case "jwt":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Secret</label>
              <input
                type="text"
                value={formConfig.secret ?? ""}
                onChange={(e) => updateConfig("secret", e.target.value)}
                placeholder="mysecret"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Algorithm</label>
              <select
                value={formConfig.algorithm ?? "HS256"}
                onChange={(e) => updateConfig("algorithm", e.target.value)}
                className={selectCls}
              >
                <option value="HS256">HS256</option>
                <option value="HS384">HS384</option>
                <option value="HS512">HS512</option>
                <option value="RS256">RS256</option>
                <option value="ES256">ES256</option>
              </select>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Header Name</label>
                <input
                  type="text"
                  value={formConfig.headerName ?? "Authorization"}
                  onChange={(e) => updateConfig("headerName", e.target.value)}
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Header Prefix</label>
                <input
                  type="text"
                  value={formConfig.headerPrefix ?? "Bearer "}
                  onChange={(e) => updateConfig("headerPrefix", e.target.value)}
                  className={inputCls}
                />
              </div>
            </div>
            <Toggle
              label="Strip Authorization Header"
              checked={formConfig.stripAuthorizationHeader ?? false}
              onChange={(v) => updateConfig("stripAuthorizationHeader", v)}
            />
          </div>
        );

      /* ── Headers & Content ─────────────────────────────────── */
      case "headers":
        return (
          <div className="space-y-4">
            <KeyValueEditor
              label="Custom Request Headers"
              value={formConfig.customRequestHeaders || {}}
              onChange={(v) => updateConfig("customRequestHeaders", v)}
            />
            <KeyValueEditor
              label="Custom Response Headers"
              value={formConfig.customResponseHeaders || {}}
              onChange={(v) => updateConfig("customResponseHeaders", v)}
            />
            <div className="border-t border-gray-700 pt-3 space-y-2">
              <h4 className="text-xs font-medium text-gray-300 uppercase tracking-wider">Security</h4>
              <Toggle
                label="Frame Deny"
                checked={formConfig.frameDeny ?? false}
                onChange={(v) => updateConfig("frameDeny", v)}
              />
              <Toggle
                label="Content-Type Nosniff"
                checked={formConfig.contentTypeNosniff ?? false}
                onChange={(v) => updateConfig("contentTypeNosniff", v)}
              />
              <Toggle
                label="XSS Filter"
                checked={formConfig.browserXssFilter ?? false}
                onChange={(v) => updateConfig("browserXssFilter", v)}
              />
              <Toggle
                label="SSL Redirect"
                checked={formConfig.sslRedirect ?? false}
                onChange={(v) => updateConfig("sslRedirect", v)}
              />
              <Toggle
                label="STS Include Subdomains"
                checked={formConfig.stsIncludeSubdomains ?? false}
                onChange={(v) => updateConfig("stsIncludeSubdomains", v)}
              />
            </div>
            <div>
              <label className={labelCls}>STS Seconds</label>
              <input
                type="number"
                value={formConfig.stsSeconds ?? 0}
                onChange={(e) => updateConfig("stsSeconds", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Content Security Policy</label>
              <input
                type="text"
                value={formConfig.contentSecurityPolicy ?? ""}
                onChange={(e) => updateConfig("contentSecurityPolicy", e.target.value)}
                placeholder="default-src 'self'; script-src 'self'"
                className={inputCls}
              />
            </div>
          </div>
        );

      case "passTLSClientCert":
        return (
          <Toggle
            label="Include PEM"
            checked={formConfig.pem ?? false}
            onChange={(v) => updateConfig("pem", v)}
          />
        );

      case "contentType":
        return (
          <Toggle
            label="Auto Detect"
            checked={formConfig.autoDetect ?? true}
            onChange={(v) => updateConfig("autoDetect", v)}
          />
        );

      /* ── Compression ───────────────────────────────────────── */
      case "compress":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Min Response Body Bytes</label>
              <input
                type="number"
                value={formConfig.minResponseBodyBytes ?? 1024}
                onChange={(e) => updateConfig("minResponseBodyBytes", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Encodings</label>
              <div className="flex items-center gap-4 mt-1">
                {["zstd", "br", "gzip"].map((enc) => {
                  const encodings: string[] = formConfig.encodings || [];
                  const checked = encodings.includes(enc);
                  return (
                    <label key={enc} className="flex items-center gap-2 text-sm text-gray-300 cursor-pointer">
                      <input
                        type="checkbox"
                        checked={checked}
                        onChange={() => {
                          const next = checked
                            ? encodings.filter((e: string) => e !== enc)
                            : [...encodings, enc];
                          updateConfig("encodings", next);
                        }}
                        className="w-4 h-4 rounded border-gray-600 bg-gray-900 text-blue-600 focus:ring-blue-500 focus:ring-offset-0"
                      />
                      {enc}
                    </label>
                  );
                })}
              </div>
            </div>
          </div>
        );

      /* ── Redirects ─────────────────────────────────────────── */
      case "redirectScheme":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Scheme</label>
              <select
                value={formConfig.scheme ?? "https"}
                onChange={(e) => updateConfig("scheme", e.target.value)}
                className={selectCls}
              >
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
            </div>
            <Toggle
              label="Permanent (301)"
              checked={formConfig.permanent ?? true}
              onChange={(v) => updateConfig("permanent", v)}
            />
            <div>
              <label className={labelCls}>Port (optional)</label>
              <input
                type="text"
                value={formConfig.port ?? ""}
                onChange={(e) => updateConfig("port", e.target.value)}
                placeholder="443"
                className={inputCls}
              />
            </div>
          </div>
        );

      case "redirectRegex":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Regex</label>
              <input
                type="text"
                value={formConfig.regex ?? ""}
                onChange={(e) => updateConfig("regex", e.target.value)}
                placeholder="^http://old.example.com/(.*)"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Replacement</label>
              <input
                type="text"
                value={formConfig.replacement ?? ""}
                onChange={(e) => updateConfig("replacement", e.target.value)}
                placeholder="https://new.example.com/${1}"
                className={inputCls}
              />
            </div>
            <Toggle
              label="Permanent (301)"
              checked={formConfig.permanent ?? true}
              onChange={(v) => updateConfig("permanent", v)}
            />
          </div>
        );

      /* ── Path Manipulation ─────────────────────────────────── */
      case "stripPrefix":
        return (
          <div>
            <label className={labelCls}>Prefixes (one per line)</label>
            <textarea
              rows={4}
              value={(formConfig.prefixes || []).join("\n")}
              onChange={(e) =>
                updateConfig(
                  "prefixes",
                  e.target.value.split("\n").filter((l: string) => l.trim())
                )
              }
              placeholder="/api\n/v1"
              className={textareaCls}
            />
          </div>
        );

      case "stripPrefixRegex":
        return (
          <div>
            <label className={labelCls}>Regex Patterns (one per line)</label>
            <textarea
              rows={4}
              value={(formConfig.regex || []).join("\n")}
              onChange={(e) =>
                updateConfig(
                  "regex",
                  e.target.value.split("\n").filter((l: string) => l.trim())
                )
              }
              placeholder="/api/v[0-9]+"
              className={textareaCls}
            />
          </div>
        );

      case "addPrefix":
        return (
          <div>
            <label className={labelCls}>Prefix</label>
            <input
              type="text"
              value={formConfig.prefix ?? ""}
              onChange={(e) => updateConfig("prefix", e.target.value)}
              placeholder="/api"
              className={inputCls}
            />
          </div>
        );

      case "replacePath":
        return (
          <div>
            <label className={labelCls}>Path</label>
            <input
              type="text"
              value={formConfig.path ?? ""}
              onChange={(e) => updateConfig("path", e.target.value)}
              placeholder="/new-path"
              className={inputCls}
            />
          </div>
        );

      case "replacePathRegex":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Regex</label>
              <input
                type="text"
                value={formConfig.regex ?? ""}
                onChange={(e) => updateConfig("regex", e.target.value)}
                placeholder="^/old/(.*)"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Replacement</label>
              <input
                type="text"
                value={formConfig.replacement ?? ""}
                onChange={(e) => updateConfig("replacement", e.target.value)}
                placeholder="/new/${1}"
                className={inputCls}
              />
            </div>
          </div>
        );

      /* ── Reliability ───────────────────────────────────────── */
      case "retry":
        return (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>Attempts</label>
              <input
                type="number"
                value={formConfig.attempts ?? 3}
                onChange={(e) => updateConfig("attempts", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Initial Interval</label>
              <input
                type="text"
                value={formConfig.initialInterval ?? "100ms"}
                onChange={(e) => updateConfig("initialInterval", e.target.value)}
                placeholder="100ms"
                className={inputCls}
              />
            </div>
          </div>
        );

      case "circuitBreaker":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Expression</label>
              <input
                type="text"
                value={formConfig.expression ?? ""}
                onChange={(e) => updateConfig("expression", e.target.value)}
                placeholder="NetworkErrorRatio() > 0.5"
                className={inputCls}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Check Period</label>
                <input
                  type="text"
                  value={formConfig.checkPeriod ?? "100ms"}
                  onChange={(e) => updateConfig("checkPeriod", e.target.value)}
                  placeholder="100ms"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Fallback Duration</label>
                <input
                  type="text"
                  value={formConfig.fallbackDuration ?? "10s"}
                  onChange={(e) => updateConfig("fallbackDuration", e.target.value)}
                  placeholder="10s"
                  className={inputCls}
                />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelCls}>Recovery Duration</label>
                <input
                  type="text"
                  value={formConfig.recoveryDuration ?? "10s"}
                  onChange={(e) => updateConfig("recoveryDuration", e.target.value)}
                  placeholder="10s"
                  className={inputCls}
                />
              </div>
              <div>
                <label className={labelCls}>Response Code</label>
                <input
                  type="number"
                  value={formConfig.responseCode ?? 503}
                  onChange={(e) => updateConfig("responseCode", parseInt(e.target.value) || 503)}
                  className={inputCls}
                />
              </div>
            </div>
          </div>
        );

      /* ── Buffering ─────────────────────────────────────────── */
      case "buffering":
        return (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={labelCls}>Max Request Body (bytes)</label>
              <input
                type="number"
                value={formConfig.maxRequestBodyBytes ?? 1048576}
                onChange={(e) => updateConfig("maxRequestBodyBytes", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Mem Request Body (bytes)</label>
              <input
                type="number"
                value={formConfig.memRequestBodyBytes ?? 1048576}
                onChange={(e) => updateConfig("memRequestBodyBytes", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Max Response Body (bytes)</label>
              <input
                type="number"
                value={formConfig.maxResponseBodyBytes ?? 1048576}
                onChange={(e) => updateConfig("maxResponseBodyBytes", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Mem Response Body (bytes)</label>
              <input
                type="number"
                value={formConfig.memResponseBodyBytes ?? 1048576}
                onChange={(e) => updateConfig("memResponseBodyBytes", parseInt(e.target.value) || 0)}
                className={inputCls}
              />
            </div>
          </div>
        );

      /* ── Composition ───────────────────────────────────────── */
      case "chain":
        return (
          <div>
            <label className={labelCls}>Middlewares (one name per line)</label>
            <textarea
              rows={4}
              value={(formConfig.middlewares || []).join("\n")}
              onChange={(e) =>
                updateConfig(
                  "middlewares",
                  e.target.value.split("\n").filter((l: string) => l.trim())
                )
              }
              placeholder="auth\ncompress\nrate-limit"
              className={textareaCls}
            />
          </div>
        );

      /* ── Protocol ──────────────────────────────────────────── */
      case "grpcWeb":
        return (
          <div>
            <label className={labelCls}>Allow Origins (one per line)</label>
            <textarea
              rows={3}
              value={(formConfig.allowOrigins || []).join("\n")}
              onChange={(e) =>
                updateConfig(
                  "allowOrigins",
                  e.target.value.split("\n").filter((l: string) => l.trim())
                )
              }
              placeholder="*"
              className={textareaCls}
            />
          </div>
        );

      /* ── Error Handling ────────────────────────────────────── */
      case "errors":
        return (
          <div className="space-y-3">
            <div>
              <label className={labelCls}>Status Codes (one range per line)</label>
              <textarea
                rows={3}
                value={(formConfig.status || []).join("\n")}
                onChange={(e) =>
                  updateConfig(
                    "status",
                    e.target.value.split("\n").filter((l: string) => l.trim())
                  )
                }
                placeholder="500-599"
                className={textareaCls}
              />
            </div>
            <div>
              <label className={labelCls}>Service</label>
              <input
                type="text"
                value={formConfig.service ?? ""}
                onChange={(e) => updateConfig("service", e.target.value)}
                placeholder="error-handler"
                className={inputCls}
              />
            </div>
            <div>
              <label className={labelCls}>Query</label>
              <input
                type="text"
                value={formConfig.query ?? ""}
                onChange={(e) => updateConfig("query", e.target.value)}
                placeholder="/error?status={status}"
                className={inputCls}
              />
            </div>
          </div>
        );

      default:
        return (
          <p className="text-xs text-gray-500 italic">Unknown middleware type: {formType}</p>
        );
    }
  }

  /* ── Render ─────────────────────────────────────────────────── */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading HTTP middlewares...
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">HTTP Middlewares</h1>
          <p className="text-sm text-[var(--text-muted)]">
            {middlewares.length} middleware{middlewares.length !== 1 ? "s" : ""} configured
          </p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-blue-600 hover:bg-blue-700 text-white transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          Add Middleware
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
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                  Name
                </th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                  Type
                </th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                  Enabled
                </th>
                <th className="text-left py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                  Created
                </th>
                <th className="text-right py-3 px-3 text-xs font-medium text-[var(--text-muted)] uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody>
              {middlewares.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-12 text-[var(--text-muted)]">
                    No HTTP middlewares configured
                  </td>
                </tr>
              ) : (
                middlewares.map((mw) => (
                  <tr
                    key={mw.id}
                    className="border-b border-[var(--border)] hover:bg-[var(--bg-card-hover)] transition-colors cursor-pointer"
                    onClick={() => openEdit(mw)}
                  >
                    <td className="py-2.5 px-3 font-medium text-[var(--text-primary)]">
                      {mw.name}
                    </td>
                    <td className="py-2.5 px-3">
                      <TypeBadge mtype={mw.middleware_type} />
                    </td>
                    <td className="py-2.5 px-3" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => handleToggleEnabled(mw)}
                        className="relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none"
                        style={{
                          backgroundColor: mw.enabled ? "#22c55e" : "#4b5563",
                        }}
                        title={mw.enabled ? "Disable" : "Enable"}
                      >
                        <span
                          className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform ${
                            mw.enabled ? "translate-x-[18px]" : "translate-x-[3px]"
                          }`}
                        />
                      </button>
                    </td>
                    <td className="py-2.5 px-3 text-xs text-[var(--text-muted)]">
                      {fmtDate(mw.created_at)}
                    </td>
                    <td className="py-2.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => openEdit(mw)}
                          className="text-[var(--text-muted)] hover:text-blue-400 transition-colors p-1"
                          title="Edit"
                        >
                          <svg
                            className="w-4 h-4"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                            strokeWidth={1.5}
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125M18 14v4.75A2.25 2.25 0 0115.75 21H5.25A2.25 2.25 0 013 18.75V8.25A2.25 2.25 0 015.25 6H10"
                            />
                          </svg>
                        </button>
                        <button
                          onClick={() => handleDelete(mw)}
                          disabled={deletingId === mw.id}
                          className="text-[var(--text-muted)] hover:text-red-400 disabled:opacity-40 transition-colors p-1"
                          title="Delete"
                        >
                          {deletingId === mw.id ? (
                            <span className="text-xs">...</span>
                          ) : (
                            <svg
                              className="w-4 h-4"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                              strokeWidth={1.5}
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                              />
                            </svg>
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create / Edit Modal */}
      {modalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-gray-800 border border-gray-700 rounded-xl w-full max-w-lg mx-4 shadow-2xl max-h-[90vh] flex flex-col">
            {/* Modal header */}
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between flex-shrink-0">
              <h2 className="text-lg font-semibold text-white">
                {editingId ? "Edit Middleware" : "Add Middleware"}
              </h2>
              <button
                onClick={closeModal}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>

            {/* Modal body (scrollable) */}
            <div className="p-6 space-y-4 overflow-y-auto flex-1">
              {/* Name */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">Name *</label>
                <input
                  type="text"
                  value={formName}
                  onChange={(e) => setFormName(e.target.value)}
                  placeholder="my-middleware"
                  className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              {/* Middleware Type */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">Middleware Type</label>
                <select
                  value={formType}
                  onChange={(e) => handleTypeChange(e.target.value)}
                  disabled={!!editingId}
                  className="w-full bg-gray-900 border border-gray-600 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500 disabled:opacity-60"
                >
                  {Object.entries(MIDDLEWARE_CATEGORIES).map(([cat, info]) => (
                    <optgroup key={cat} label={info.label}>
                      {info.types.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </div>

              {/* Type-specific config */}
              <div className="border-t border-gray-700 pt-4">
                <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider mb-3">
                  Configuration
                </h3>
                {renderTypeForm()}
              </div>

              {/* Enabled toggle */}
              <div className="border-t border-gray-700 pt-4">
                <Toggle
                  label="Enabled"
                  checked={formEnabled}
                  onChange={setFormEnabled}
                />
              </div>
            </div>

            {/* Modal footer */}
            <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-end gap-2 flex-shrink-0">
              <button
                onClick={closeModal}
                className="px-4 py-2 text-sm font-medium rounded-md bg-gray-700 hover:bg-gray-600 text-gray-300 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={submitting || !formName.trim()}
                className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white transition-colors"
              >
                {submitting ? "Saving..." : editingId ? "Update" : "Create"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
