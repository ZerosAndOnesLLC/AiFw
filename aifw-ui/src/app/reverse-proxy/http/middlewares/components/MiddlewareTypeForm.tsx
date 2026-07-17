"use client";

import { Dispatch, SetStateAction } from "react";
import { Toggle } from "./Toggle";
import { KeyValueEditor } from "./KeyValueEditor";

/* ── Type-specific form fields ─────────────────────────────── */

export function MiddlewareTypeForm({
  formType,
  formConfig,
  updateConfig,
  setFormConfig,
}: {
  formType: string;
  formConfig: any;
  updateConfig: (key: string, value: any) => void;
  setFormConfig: Dispatch<SetStateAction<any>>;
}) {
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
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
