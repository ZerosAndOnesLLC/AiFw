"use client";

import { useState } from "react";
import { useBackups } from "@/hooks/useBackups";
import { HistoryTab } from "./components/HistoryTab";
import { S3ArchiveTab } from "./components/S3ArchiveTab";
import { ConfigCheckTab } from "./components/ConfigCheckTab";
import { ExportImportTab } from "./components/ExportImportTab";
import { OpnsenseImportTab } from "./components/OpnsenseImportTab";
import { RestoreMappingModal } from "./components/RestoreMappingModal";

const TABS = ["History", "S3 Archive", "Config Check", "Export / Import", "OPNsense Import"] as const;
type Tab = (typeof TABS)[number];

/* -- Page ------------------------------------------------------------ */

export default function BackupPage() {
  const [activeTab, setActiveTab] = useState<Tab>("History");
  const {
    feedback,
    loading,
    // History
    history,
    saving,
    comment,
    setComment,
    saveSnapshot,
    restoring,
    restore,
    // Restore mapping modal
    restorePending,
    restoreMap,
    setRestoreMap,
    applyRestoreMapping,
    cancelRestoreMapping,
    // Diff
    diff,
    diffLoading,
    diffV1,
    diffV2,
    diffSection,
    setDiffSection,
    loadDiff,
    closeDiff,
    // Config check
    check,
    checking,
    runCheck,
    // Export / Import
    exporting,
    handleExport,
    importing,
    preview,
    importPreview,
    importMap,
    setImportMap,
    fileRef,
    handleFileSelect,
    handleImport,
    cancelImport,
    // OPNsense
    opnXml,
    opnImporting,
    opnPreview,
    opnIfaceMap,
    setOpnIfaceMap,
    opnImportSystemSettings,
    setOpnImportSystemSettings,
    opnFileRef,
    handleOpnFileSelect,
    handleOpnPreview,
    handleOpnRefreshPlan,
    handleOpnImport,
    cancelOpnUpload,
    cancelOpnPreview,
    // Commit confirm
    commitConfirm,
    handleCommitConfirm,
  } = useBackups();

  /* -- Render -------------------------------------------------------- */

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="w-6 h-6 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold">Backup & Restore</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1">
          Manage config versions, compare changes, validate, and restore previous configurations
        </p>
      </div>

      {feedback && (
        <div className={`p-3 text-sm rounded-md border ${
          feedback.type === "success"
            ? "text-green-400 bg-green-500/10 border-green-500/20"
            : "text-red-400 bg-red-500/10 border-red-500/20"
        }`}>
          {feedback.msg}
        </div>
      )}

      {/* Tabs */}
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
        <div className="flex border-b border-[var(--border)] overflow-x-auto">
          {TABS.map((tab) => (
            <button key={tab} onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-sm font-medium whitespace-nowrap transition-colors ${
                activeTab === tab
                  ? "text-blue-400 border-b-2 border-blue-400"
                  : "text-[var(--text-muted)] hover:text-[var(--text-secondary)]"
              }`}>
              {tab}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* ===================== History Tab ===================== */}
          {activeTab === "History" && (
            <HistoryTab
              history={history}
              saving={saving}
              comment={comment}
              setComment={setComment}
              saveSnapshot={saveSnapshot}
              restoring={restoring}
              restore={restore}
              loadDiff={loadDiff}
              diff={diff}
              diffLoading={diffLoading}
              diffV1={diffV1}
              diffV2={diffV2}
              diffSection={diffSection}
              setDiffSection={setDiffSection}
              closeDiff={closeDiff}
            />
          )}

          {/* ===================== S3 Archive Tab ===================== */}
          {activeTab === "S3 Archive" && <S3ArchiveTab />}

          {/* ===================== Config Check Tab ================ */}
          {activeTab === "Config Check" && (
            <ConfigCheckTab check={check} checking={checking} runCheck={runCheck} />
          )}

          {/* ===================== Export / Import Tab ================ */}
          {activeTab === "Export / Import" && (
            <ExportImportTab
              exporting={exporting}
              handleExport={handleExport}
              importing={importing}
              preview={preview}
              importPreview={importPreview}
              importMap={importMap}
              setImportMap={setImportMap}
              fileRef={fileRef}
              handleFileSelect={handleFileSelect}
              handleImport={handleImport}
              cancelImport={cancelImport}
            />
          )}

          {/* ===================== OPNsense Import Tab ================ */}
          {activeTab === "OPNsense Import" && (
            <OpnsenseImportTab
              commitConfirm={commitConfirm}
              handleCommitConfirm={handleCommitConfirm}
              opnXml={opnXml}
              opnFileRef={opnFileRef}
              handleOpnFileSelect={handleOpnFileSelect}
              handleOpnPreview={handleOpnPreview}
              cancelOpnUpload={cancelOpnUpload}
              opnPreview={opnPreview}
              opnIfaceMap={opnIfaceMap}
              setOpnIfaceMap={setOpnIfaceMap}
              handleOpnRefreshPlan={handleOpnRefreshPlan}
              opnImportSystemSettings={opnImportSystemSettings}
              setOpnImportSystemSettings={setOpnImportSystemSettings}
              opnImporting={opnImporting}
              handleOpnImport={handleOpnImport}
              cancelOpnPreview={cancelOpnPreview}
            />
          )}
        </div>
      </div>

      {/* ============ History Restore — NIC mapping modal ============ */}
      {restorePending && (
        <RestoreMappingModal
          pending={restorePending}
          map={restoreMap}
          onMapChange={setRestoreMap}
          restoring={restoring}
          onCancel={cancelRestoreMapping}
          onApply={applyRestoreMapping}
        />
      )}
    </div>
  );
}
