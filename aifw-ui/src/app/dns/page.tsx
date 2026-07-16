"use client";

import { useState } from "react";
import { useDnsResolver } from "@/hooks/useDnsConfig";
import { StatusCard } from "./components/StatusCard";
import { GeneralTab } from "./components/GeneralTab";
import { DotTab } from "./components/DotTab";
import { AdvancedTab } from "./components/AdvancedTab";
import { CustomTab } from "./components/CustomTab";

const TABS = ["General", "DNS over TLS", "Advanced", "Custom"] as const;
type Tab = (typeof TABS)[number];

/* -- Page ------------------------------------------------------------ */

export default function DnsResolverPage() {
  const {
    status,
    config,
    setConfig,
    isDirty,
    interfaces,
    loading,
    saving,
    applying,
    actionLoading,
    feedback,
    serviceAction,
    saveConfig,
    applyConfig,
    isAllInterfaces,
    toggleInterface,
    addToList,
    removeFromList,
  } = useDnsResolver();
  const [activeTab, setActiveTab] = useState<Tab>("General");

  // list inputs
  const [dotUpstreamInput, setDotUpstreamInput] = useState("");
  const [privateAddrInput, setPrivateAddrInput] = useState("");

  /* -- Render ------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64 text-[var(--text-muted)]">
        Loading DNS Resolver status...
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-2xl font-bold">DNS Resolver</h1>
        <p className="text-sm text-[var(--text-muted)]">
          Manage the Unbound DNS resolver, caching, and security settings
        </p>
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

      {/* -- Status Card --------------------------------------------- */}
      <StatusCard status={status} actionLoading={actionLoading} onAction={serviceAction} />

      {/* -- Tabbed Settings ----------------------------------------- */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        {/* Tab bar */}
        <div className="flex border-b border-[var(--border)] overflow-x-auto">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-sm font-medium whitespace-nowrap transition-colors ${
                activeTab === tab
                  ? "text-blue-400 border-b-2 border-blue-400"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* ===================== General Tab ===================== */}
          {activeTab === "General" && (
            <GeneralTab
              config={config}
              setConfig={setConfig}
              interfaces={interfaces}
              isAllInterfaces={isAllInterfaces}
              toggleInterface={toggleInterface}
            />
          )}

          {/* ===================== DNS over TLS Tab ================ */}
          {activeTab === "DNS over TLS" && (
            <DotTab
              config={config}
              setConfig={setConfig}
              upstreamInput={dotUpstreamInput}
              setUpstreamInput={setDotUpstreamInput}
              addToList={addToList}
              removeFromList={removeFromList}
            />
          )}

          {/* ===================== Advanced Tab ==================== */}
          {activeTab === "Advanced" && (
            <AdvancedTab
              config={config}
              setConfig={setConfig}
              privateAddrInput={privateAddrInput}
              setPrivateAddrInput={setPrivateAddrInput}
              addToList={addToList}
              removeFromList={removeFromList}
            />
          )}

          {/* ===================== Custom Tab ====================== */}
          {activeTab === "Custom" && <CustomTab config={config} setConfig={setConfig} />}

          {/* Save (when dirty) + Apply (always — applied state can drift
              from saved state, so Apply must be reachable without a re-edit). */}
          <div className="flex gap-3 pt-4 mt-4 border-t border-[var(--border)]">
            {isDirty && (
              <button
                onClick={saveConfig}
                disabled={saving}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                {saving ? "Saving..." : "Save Settings"}
              </button>
            )}
            <button
              onClick={applyConfig}
              disabled={applying}
              className="px-4 py-2 bg-green-600 hover:bg-green-700 text-white text-sm rounded-md disabled:opacity-50 flex items-center gap-2"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              {applying ? "Applying..." : "Apply & Restart"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
