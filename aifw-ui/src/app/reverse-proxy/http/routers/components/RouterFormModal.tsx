"use client";

import { useState } from "react";
import {
  type Entrypoint,
  type HttpMiddleware,
  type HttpRouter,
  type HttpRouterPayload,
  type HttpService,
  type RuleCondition,
  buildRuleString,
  parseJsonArray,
  parseRuleToConditions,
  parseTlsJson,
} from "@/lib/api/reverse-proxy/routers";
import { RuleBuilder } from "./RuleBuilder";

const inputCls =
  "w-full bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors";
const selectCls =
  "w-full bg-[var(--bg-secondary)] border border-[var(--border)] rounded-md px-3 py-2 text-sm text-[var(--text-primary)] focus:outline-none focus:ring-1 focus:ring-blue-500 transition-colors";
const labelCls = "block text-xs text-[var(--text-muted)] mb-1";

/// Seed form state from the router being edited (or blank defaults for
/// create). The modal is mounted fresh each time it opens, so this runs
/// once per open — mirroring the original openCreate/openEdit setters.
interface FormInit {
  name: string;
  entryPoints: string[];
  service: string;
  middlewares: string[];
  priority: number;
  enabled: boolean;
  tlsCertResolver: string;
  tlsDomains: string;
  showTls: boolean;
  ruleMode: "visual" | "raw";
  ruleConditions: RuleCondition[];
  ruleOperators: string[];
  ruleRaw: string;
}

function initialFormState(editing: HttpRouter | null): FormInit {
  if (!editing) {
    return {
      name: "",
      entryPoints: [],
      service: "",
      middlewares: [],
      priority: 0,
      enabled: true,
      tlsCertResolver: "",
      tlsDomains: "",
      showTls: false,
      ruleMode: "visual",
      ruleConditions: [],
      ruleOperators: [],
      ruleRaw: "",
    };
  }

  const tls = parseTlsJson(editing.tls_json);
  const hasTls = !!(tls && (tls.certResolver || tls.domains));

  // Parse rule into conditions
  const { conditions, operators } = parseRuleToConditions(editing.rule);
  const canVisual = conditions.length > 0;

  return {
    name: editing.name,
    entryPoints: parseJsonArray(editing.entry_points),
    service: editing.service,
    middlewares: parseJsonArray(editing.middlewares),
    priority: editing.priority,
    enabled: editing.enabled,
    tlsCertResolver: hasTls && tls ? tls.certResolver : "",
    tlsDomains: hasTls && tls ? tls.domains : "",
    showTls: hasTls,
    ruleMode: canVisual ? "visual" : "raw",
    ruleConditions: canVisual ? conditions : [],
    ruleOperators: canVisual ? operators : [],
    ruleRaw: editing.rule,
  };
}

interface RouterFormModalProps {
  /// Router being edited, or null for create.
  editing: HttpRouter | null;
  entrypoints: Entrypoint[];
  services: HttpService[];
  middlewares: HttpMiddleware[];
  submitting: boolean;
  onSubmit: (body: HttpRouterPayload) => void;
  onClose: () => void;
  /// Surfaces errors (e.g. unparseable rule) on the page-level banner.
  showError: (msg: string) => void;
}

export function RouterFormModal({
  editing,
  entrypoints,
  services,
  middlewares,
  submitting,
  onSubmit,
  onClose,
  showError,
}: RouterFormModalProps) {
  const [init] = useState<FormInit>(() => initialFormState(editing));

  // Form state
  const [formName, setFormName] = useState(init.name);
  const [formEntryPoints, setFormEntryPoints] = useState<string[]>(init.entryPoints);
  const [formService, setFormService] = useState(init.service);
  const [formMiddlewares, setFormMiddlewares] = useState<string[]>(init.middlewares);
  const [formPriority, setFormPriority] = useState(init.priority);
  const [formEnabled, setFormEnabled] = useState(init.enabled);
  const [formTlsCertResolver, setFormTlsCertResolver] = useState(init.tlsCertResolver);
  const [formTlsDomains, setFormTlsDomains] = useState(init.tlsDomains);
  const [showTls, setShowTls] = useState(init.showTls);

  // Rule builder
  const [ruleMode, setRuleMode] = useState<"visual" | "raw">(init.ruleMode);
  const [ruleConditions, setRuleConditions] = useState<RuleCondition[]>(init.ruleConditions);
  const [ruleOperators, setRuleOperators] = useState<string[]>(init.ruleOperators);
  const [ruleRaw, setRuleRaw] = useState(init.ruleRaw);

  /* -- Form helpers -------------------------------------------------- */

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

  const handleSubmit = () => {
    const rule = getCurrentRule();
    if (!formName.trim() || !rule.trim()) return;
    onSubmit({
      name: formName.trim(),
      rule,
      service: formService,
      entry_points: JSON.stringify(formEntryPoints),
      middlewares: JSON.stringify(formMiddlewares),
      priority: formPriority,
      tls_json: buildTlsJson(),
      enabled: formEnabled,
    });
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

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal */}
      <div className="relative bg-[var(--bg-card)] border border-[var(--border)] rounded-lg shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto mx-4">
        {/* Modal Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)]">
          <h2 className="text-lg font-semibold text-[var(--text-primary)]">
            {editing ? "Edit Router" : "New HTTP Router"}
          </h2>
          <button
            onClick={onClose}
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
          <RuleBuilder
            ruleMode={ruleMode}
            ruleConditions={ruleConditions}
            ruleOperators={ruleOperators}
            ruleRaw={ruleRaw}
            setRuleMode={setRuleMode}
            setRuleConditions={setRuleConditions}
            setRuleOperators={setRuleOperators}
            setRuleRaw={setRuleRaw}
            showError={showError}
          />

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
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium rounded-md bg-[var(--bg-secondary)] border border-[var(--border)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || !formName.trim() || !getCurrentRule().trim()}
            className="px-4 py-2 text-sm font-medium rounded-md bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {submitting ? "Saving..." : editing ? "Update Router" : "Create Router"}
          </button>
        </div>
      </div>
    </div>
  );
}
