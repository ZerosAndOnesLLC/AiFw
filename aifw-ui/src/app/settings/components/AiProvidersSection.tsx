"use client";

import { Dispatch, SetStateAction } from "react";
import { Feedback } from "@/hooks/useFeedback";
import { AiProviderConfig, AiTestResult } from "@/lib/api/settings";
import { FeedbackBanner } from "./FeedbackBanner";
import { inputCls, labelCls, saveBtnCls, sectionCls } from "./sectionStyles";

const PROVIDERS = [
  { key: "openai", name: "OpenAI", desc: "GPT-4o, GPT-4 Turbo, GPT-3.5", icon: "O", color: "bg-green-600", defaultEndpoint: "https://api.openai.com/v1", defaultModel: "gpt-4o", needsKey: true },
  { key: "claude", name: "Anthropic Claude", desc: "Claude Sonnet 4, Opus 4, Haiku", icon: "C", color: "bg-orange-600", defaultEndpoint: "https://api.anthropic.com", defaultModel: "claude-sonnet-4-20250514", needsKey: true },
  { key: "lm_studio", name: "LM Studio", desc: "Local models via OpenAI-compatible API", icon: "L", color: "bg-purple-600", defaultEndpoint: "http://localhost:1234/v1", defaultModel: "", needsKey: false },
  { key: "ollama", name: "Ollama", desc: "Local models — llama3, mistral, codellama", icon: "O", color: "bg-blue-600", defaultEndpoint: "http://localhost:11434", defaultModel: "llama3", needsKey: false },
];

export interface AiProvidersSectionProps {
  visible: boolean;
  enabled: boolean;
  activeProvider: string;
  providers: AiProviderConfig[];
  saving: boolean;
  loading: boolean;
  feedback: Feedback | null;
  editingProvider: string | null;
  setEditingProvider: Dispatch<SetStateAction<string | null>>;
  editKey: string;
  setEditKey: Dispatch<SetStateAction<string>>;
  editEndpoint: string;
  setEditEndpoint: Dispatch<SetStateAction<string>>;
  editModel: string;
  setEditModel: Dispatch<SetStateAction<string>>;
  editTlsInsecure: boolean;
  setEditTlsInsecure: Dispatch<SetStateAction<boolean>>;
  models: string[];
  setModels: Dispatch<SetStateAction<string[]>>;
  modelsLoading: boolean;
  testing: boolean;
  testResult: AiTestResult | null;
  setTestResult: Dispatch<SetStateAction<AiTestResult | null>>;
  saveProvider: (provider: string, enabled?: boolean) => void;
  saveGlobal: (enabled: boolean, active?: string) => void;
  fetchModels: (provider: string) => void;
  testConnection: (provider: string) => void;
}

export function AiProvidersSection({
  visible,
  enabled,
  activeProvider,
  providers,
  saving,
  loading,
  feedback,
  editingProvider,
  setEditingProvider,
  editKey,
  setEditKey,
  editEndpoint,
  setEditEndpoint,
  editModel,
  setEditModel,
  editTlsInsecure,
  setEditTlsInsecure,
  models,
  setModels,
  modelsLoading,
  testing,
  testResult,
  setTestResult,
  saveProvider,
  saveGlobal,
  fetchModels,
  testConnection,
}: AiProvidersSectionProps) {
  return (
    <section className={`${sectionCls} ${visible ? "" : "hidden"}`}>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="font-medium">AI / LLM Providers</h2>
          <p className="text-xs text-[var(--text-muted)] mt-0.5">
            Configure AI backends for threat analysis and assisted investigation
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-xs font-medium ${enabled ? "text-green-400" : "text-[var(--text-muted)]"}`}>
            {enabled ? "Enabled" : "Disabled"}
          </span>
          <button
            onClick={() => saveGlobal(!enabled)}
            disabled={saving}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${enabled ? "bg-green-600" : "bg-gray-600"}`}
          >
            <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform ${enabled ? "translate-x-4" : "translate-x-0.5"}`} />
          </button>
        </div>
      </div>
      <FeedbackBanner feedback={feedback} />
      <div className="space-y-3 mt-3">
        {loading ? (
          <p className="text-sm text-[var(--text-muted)]">Loading...</p>
        ) : (
          <>
            {/* WIP notice */}
            <div className="bg-yellow-500/5 border border-yellow-500/30 rounded-md px-3 py-2">
              <p className="text-xs text-[var(--text-muted)]">
                <span className="text-yellow-400 font-medium">Preview.</span> AI-assisted threat analysis is in development.
                Configure your providers now — they&apos;ll be used for automated alert triage, threat classification,
                and investigation assistance in upcoming releases.
              </p>
            </div>

            {/* Provider cards */}
            {PROVIDERS.map(prov => {
              const cfg = providers.find(p => p.provider === prov.key);
              const isEditing = editingProvider === prov.key;
              const isActive = activeProvider === prov.key;

              return (
                <div key={prov.key} className={`bg-[var(--bg-primary)] border rounded-lg overflow-hidden ${
                  isActive && cfg?.enabled ? "border-green-500/30" : "border-[var(--border)]"
                }`}>
                  <div className="px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-8 h-8 rounded-lg ${prov.color} flex items-center justify-center text-white text-xs font-bold`}>
                        {prov.icon}
                      </div>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">{prov.name}</span>
                          {isActive && cfg?.enabled && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-green-500/20 text-green-400 border border-green-500/30">active</span>
                          )}
                          {cfg?.enabled && !isActive && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-blue-500/20 text-blue-400 border border-blue-500/30">configured</span>
                          )}
                        </div>
                        <p className="text-[11px] text-[var(--text-muted)]">{prov.desc}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      {cfg?.enabled && (
                        <button
                          onClick={() => { saveGlobal(true, prov.key); }}
                          disabled={saving || isActive}
                          className={`text-[11px] px-2 py-1 rounded border transition-colors ${
                            isActive
                              ? "border-green-500/30 text-green-400 bg-green-500/10 cursor-default"
                              : "border-[var(--border)] text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--accent)]"
                          }`}
                        >
                          {isActive ? "Active" : "Set Active"}
                        </button>
                      )}
                      <button
                        onClick={() => {
                          if (isEditing) { setEditingProvider(null); }
                          else {
                            setEditingProvider(prov.key);
                            setEditKey("");
                            setEditEndpoint(cfg?.endpoint || prov.defaultEndpoint);
                            setEditModel(cfg?.model || prov.defaultModel);
                            setEditTlsInsecure(cfg?.tls_insecure ?? false);
                            setModels([]);
                            setTestResult(null);
                          }
                        }}
                        className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                      >
                        {isEditing ? "Cancel" : "Configure"}
                      </button>
                      <button
                        onClick={() => saveProvider(prov.key, !cfg?.enabled)}
                        disabled={saving}
                        className={`relative inline-flex h-4 w-7 items-center rounded-full transition-colors ${cfg?.enabled ? "bg-green-600" : "bg-gray-600"}`}
                      >
                        <span className={`inline-block h-2.5 w-2.5 transform rounded-full bg-white transition-transform ${cfg?.enabled ? "translate-x-3.5" : "translate-x-0.5"}`} />
                      </button>
                    </div>
                  </div>

                  {/* Edit form */}
                  {isEditing && (
                    <div className="border-t border-[var(--border)] px-4 py-3 space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {prov.needsKey && (
                          <div>
                            <label className={labelCls}>API Key {cfg?.api_key_set && !editKey && <span className="text-green-400 normal-case">(set)</span>}</label>
                            <input
                              type="password"
                              value={editKey}
                              onChange={e => setEditKey(e.target.value)}
                              placeholder={cfg?.api_key_set ? "(unchanged)" : `Enter ${prov.name} API key`}
                              className={inputCls}
                            />
                          </div>
                        )}
                        <div>
                          <label className={labelCls}>Endpoint URL</label>
                          <input
                            type="text"
                            value={editEndpoint}
                            onChange={e => setEditEndpoint(e.target.value)}
                            placeholder={prov.defaultEndpoint}
                            className={inputCls}
                          />
                        </div>
                        <div>
                          <div className="flex items-center justify-between mb-1">
                            <label className={labelCls}>Model</label>
                            <button
                              onClick={() => fetchModels(prov.key)}
                              disabled={modelsLoading}
                              className="text-[10px] text-[var(--accent)] hover:underline disabled:opacity-50"
                            >
                              {modelsLoading ? "Loading..." : "Fetch Models"}
                            </button>
                          </div>
                          {models.length > 0 ? (
                            <select
                              value={editModel}
                              onChange={e => setEditModel(e.target.value)}
                              className={inputCls}
                            >
                              <option value="">Select a model...</option>
                              {models.map(m => <option key={m} value={m}>{m}</option>)}
                            </select>
                          ) : (
                            <input
                              type="text"
                              value={editModel}
                              onChange={e => setEditModel(e.target.value)}
                              placeholder={prov.defaultModel || "model name"}
                              className={inputCls}
                            />
                          )}
                        </div>
                      </div>
                      <label className="flex items-start gap-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={editTlsInsecure}
                          onChange={e => setEditTlsInsecure(e.target.checked)}
                          className="mt-0.5"
                        />
                        <span className="text-xs text-[var(--text-secondary)]">
                          Skip TLS certificate verification
                          <span className="block text-[10px] text-[var(--text-muted)]">
                            Only for local endpoints with a self-signed cert. Leave off for public providers.
                          </span>
                        </span>
                      </label>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => testConnection(prov.key)}
                            disabled={testing}
                            className="px-3 py-2 text-xs font-medium rounded-md border border-[var(--border)] text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text-primary)] transition-colors disabled:opacity-50"
                          >
                            {testing ? "Testing..." : "Test Connection"}
                          </button>
                          {testResult && (
                            <span className={`text-xs font-medium ${testResult.success ? "text-green-400" : "text-red-400"}`}>
                              {testResult.success ? "Connected" : `Failed (${testResult.status_code})`}
                            </span>
                          )}
                        </div>
                        <button
                          onClick={() => saveProvider(prov.key)}
                          disabled={saving}
                          className={saveBtnCls}
                        >
                          {saving ? "Saving..." : "Save"}
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </>
        )}
      </div>
    </section>
  );
}
