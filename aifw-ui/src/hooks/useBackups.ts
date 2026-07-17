"use client";

import { useState, useEffect, useCallback, useRef, type ChangeEvent } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import { usePolling } from "@/lib/usePolling";
import {
  type ConfigVersion,
  type ConfigCheck,
  type ImportPreview,
  type DiffSummary,
  type CommitConfirmStatus,
  type S3Object,
  buildInterfaceMapForApi,
  fetchConfigHistory,
  saveConfigSnapshot,
  restoreConfigVersion,
  fetchRestorePreview,
  fetchConfigDiff,
  fetchConfigCheck,
  exportConfig,
  fetchImportPreview,
  importConfig,
  previewOpnsenseConfig,
  importOpnsenseConfig,
  fetchCommitConfirmStatus,
  confirmCommit,
  listS3Archive,
  importS3Object,
} from "@/lib/api/backup";

/// Data + actions for the Backup & Restore page (#428). Owns history,
/// diff, config-check, export/import, OPNsense import, and commit-confirm
/// state; the page and its components stay purely presentational.
export function useBackups() {
  const { feedback, showFeedback } = useFeedback(8000);
  const [loading, setLoading] = useState(true);

  // History
  const [history, setHistory] = useState<ConfigVersion[]>([]);
  const [saving, setSaving] = useState(false);
  const [comment, setComment] = useState("");
  const [restoring, setRestoring] = useState<number | null>(null);

  // Diff
  const [diff, setDiff] = useState<DiffSummary | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffV1, setDiffV1] = useState<number | null>(null);
  const [diffV2, setDiffV2] = useState<number | null>(null);
  const [diffSection, setDiffSection] = useState<string>("rules");

  // Config check
  const [check, setCheck] = useState<ConfigCheck | null>(null);
  const [checking, setChecking] = useState(false);

  // Export/Import
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const [importPreview, setImportPreview] = useState<ImportPreview | null>(null);
  const [importMap, setImportMap] = useState<Record<string, string>>({});
  const fileRef = useRef<HTMLInputElement>(null);

  // History Restore preview/mapping modal
  const [restorePending, setRestorePending] = useState<{ version: number; preview: ImportPreview } | null>(null);
  const [restoreMap, setRestoreMap] = useState<Record<string, string>>({});

  // OPNsense
  const [opnXml, setOpnXml] = useState("");
  const [opnImporting, setOpnImporting] = useState(false);
  const [opnPreview, setOpnPreview] = useState<Record<string, unknown> | null>(null);
  const [opnIfaceMap, setOpnIfaceMap] = useState<Record<string, string>>({});
  const [opnImportSystemSettings, setOpnImportSystemSettings] = useState(false);
  const opnFileRef = useRef<HTMLInputElement>(null);

  // Commit Confirm
  const [commitConfirm, setCommitConfirm] = useState<CommitConfirmStatus | null>(null);

  /* -- Fetch History ------------------------------------------------- */

  const fetchHistory = useCallback(async () => {
    try {
      setHistory(await fetchConfigHistory());
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await fetchHistory();
      setLoading(false);
    })();
  }, [fetchHistory]);

  /* -- Save snapshot ------------------------------------------------- */

  const saveSnapshot = async () => {
    setSaving(true);
    try {
      const data = await saveConfigSnapshot(comment || null);
      showFeedback("success", data.message || "Config snapshot saved");
      setComment("");
      await fetchHistory();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  /* -- Restore ------------------------------------------------------- */

  const sendRestore = async (version: number, interface_map: Record<string, string | null>) => {
    setRestoring(version);
    try {
      const data = await restoreConfigVersion(version, interface_map);
      showFeedback("success", data.message || "Restored");
      await fetchHistory();
      setRestorePending(null);
      setRestoreMap({});
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Restore failed");
    } finally {
      setRestoring(null);
    }
  };

  const restore = async (version: number) => {
    setRestoring(version);
    let preview: ImportPreview | null = null;
    try {
      preview = await fetchRestorePreview(version);
    } catch { /* fall through */ }
    setRestoring(null);

    if (preview && preview.interfaces_missing.length > 0) {
      const defaults: Record<string, string> = {};
      for (const m of preview.interfaces_missing) {
        defaults[m] = preview.suggestions[m] ?? "__keep__";
      }
      setRestoreMap(defaults);
      setRestorePending({ version, preview });
      return;
    }

    if (!confirm(`Restore to version ${version}? This will REPLACE all current rules, NAT, Geo-IP, VPN tunnels, DNS, auth settings, traffic shaping queues, rate limits, TLS rules, HA config, and pf tuning. Undo by restoring a later version.`)) return;
    await sendRestore(version, {});
  };

  const applyRestoreMapping = () => {
    if (!restorePending) return;
    const mapped = buildInterfaceMapForApi(restorePending.preview, restoreMap);
    sendRestore(restorePending.version, mapped);
  };

  const cancelRestoreMapping = () => {
    setRestorePending(null);
    setRestoreMap({});
  };

  /* -- Diff ---------------------------------------------------------- */

  const loadDiff = async (v1: number, v2: number) => {
    setDiffLoading(true);
    setDiffV1(v1);
    setDiffV2(v2);
    try {
      setDiff(await fetchConfigDiff(v1, v2));
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Diff failed");
    } finally {
      setDiffLoading(false);
    }
  };

  const closeDiff = () => setDiff(null);

  /* -- Config Check -------------------------------------------------- */

  const runCheck = async () => {
    setChecking(true);
    try {
      setCheck(await fetchConfigCheck());
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Check failed");
    } finally {
      setChecking(false);
    }
  };

  /* -- Export -------------------------------------------------------- */

  const handleExport = async () => {
    setExporting(true);
    try {
      const data = await exportConfig();
      const json = JSON.stringify(data, null, 2);
      const blob = new Blob([json], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `aifw-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showFeedback("success", "Config exported");
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  /* -- Import -------------------------------------------------------- */

  const handleFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (ev) => {
      const text = ev.target?.result as string;
      setPreview(text);
      setImportPreview(null);
      setImportMap({});
      try {
        const parsed = JSON.parse(text);
        const data = await fetchImportPreview(parsed);
        setImportPreview(data);
        const defaults: Record<string, string> = {};
        for (const m of data.interfaces_missing) defaults[m] = data.suggestions[m] ?? "__keep__";
        setImportMap(defaults);
      } catch { /* leave preview null; import will still run without mapping */ }
    };
    reader.readAsText(file);
  };

  const handleImport = async () => {
    if (!preview) return;
    const needsMapping = importPreview && importPreview.interfaces_missing.length > 0;
    if (!needsMapping && !window.confirm(
      "Import will REPLACE all firewall rules, NAT, Geo-IP, VPN tunnels, DNS servers, auth settings, traffic shaping, TLS rules, HA config, and pf tuning with the contents of this file. This cannot be undone except by restoring an earlier history version. Continue?"
    )) return;
    setImporting(true);
    try {
      const data = JSON.parse(preview);
      const interface_map = importPreview ? buildInterfaceMapForApi(importPreview, importMap) : {};
      const body = await importConfig({ ...data, interface_map });
      showFeedback("success", body.message || "Config imported");
      setPreview(null);
      setImportPreview(null);
      setImportMap({});
      if (fileRef.current) fileRef.current.value = "";
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setImporting(false);
    }
  };

  const cancelImport = () => {
    setPreview(null);
    setImportPreview(null);
    setImportMap({});
    if (fileRef.current) fileRef.current.value = "";
  };

  /* -- OPNsense Import ----------------------------------------------- */

  const handleOpnFileSelect = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => setOpnXml(ev.target?.result as string);
    reader.readAsText(file);
  };

  const handleOpnPreview = async () => {
    if (!opnXml.trim()) return;
    try {
      const data = await previewOpnsenseConfig(opnXml, {});
      setOpnPreview(data);
      const found = (data.interfaces_found || []) as string[];
      const map: Record<string, string> = {};
      for (const i of found) map[i] = "";
      setOpnIfaceMap(map);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Preview failed");
    }
  };

  /** Re-run preview after the user picks interface mappings, so the dry-run
   *  plan reflects the chosen mapping. */
  const handleOpnRefreshPlan = async () => {
    if (!opnXml.trim()) return;
    try {
      const data = await previewOpnsenseConfig(opnXml, opnIfaceMap);
      setOpnPreview(data);
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Preview refresh failed");
    }
  };

  const handleOpnImport = async () => {
    if (!opnXml.trim() || !opnPreview) return;
    setOpnImporting(true);
    try {
      const body = await importOpnsenseConfig(opnXml, opnIfaceMap, opnImportSystemSettings);
      showFeedback("success", body.message || "OPNsense config imported");
      setOpnXml(""); setOpnPreview(null); setOpnIfaceMap({});
      if (opnFileRef.current) opnFileRef.current.value = "";
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Import failed");
    } finally {
      setOpnImporting(false);
    }
  };

  const cancelOpnUpload = () => {
    setOpnXml("");
    if (opnFileRef.current) opnFileRef.current.value = "";
  };

  const cancelOpnPreview = () => {
    setOpnXml("");
    setOpnPreview(null);
    setOpnIfaceMap({});
    if (opnFileRef.current) opnFileRef.current.value = "";
  };

  /* -- Commit Confirm ------------------------------------------------ */

  const fetchCommitStatus = useCallback(async () => {
    try {
      const data = await fetchCommitConfirmStatus();
      setCommitConfirm(data.active ? data : null);
    } catch { /* silent */ }
  }, []);

  const handleCommitConfirm = async () => {
    try {
      const body = await confirmCommit();
      showFeedback("success", body.message);
      setCommitConfirm(null);
    } catch {
      showFeedback("error", "Failed to confirm");
    }
  };

  // Poll commit confirm status
  usePolling(fetchCommitStatus, 5000);

  return {
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
  };
}

/// S3 archive listing + import. Lives in its own hook (called by the
/// S3 Archive tab component) so the list is fetched when the tab mounts,
/// matching the original per-tab behavior.
export function useS3Archive() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [items, setItems] = useState<S3Object[]>([]);
  const [importing, setImporting] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);

  const reload = useCallback(async () => {
    setLoading(true);
    setError(null);
    setStatus(null);
    try {
      setItems(await listS3Archive());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { queueMicrotask(reload); }, [reload]);

  const importNow = async (key: string) => {
    if (!confirm(`Import ${key}?\n\nThis saves it as a new local version. It does NOT apply — you can diff then restore from the History tab.`)) return;
    setImporting(key);
    setStatus(null);
    try {
      const d = await importS3Object(key);
      setStatus(d.message || `Imported as version ${d.version}`);
    } catch (e) {
      setStatus(e instanceof Error ? e.message : String(e));
    } finally {
      setImporting(null);
    }
  };

  return { loading, error, items, importing, status, reload, importNow };
}
