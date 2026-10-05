"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  LogEntry,
  LogLevel,
  PluginDetail,
  PluginSummary,
  SettingValue,
  getPlugin,
  getPluginLogs,
  getPluginStatus,
  resetPlugin,
  runPluginAction,
  updatePluginSettings,
} from "@/lib/api/plugins";

const STATUS_POLL_MS = 5_000;

export type FieldSave =
  | { state: "saving" }
  | { state: "saved" }
  | { state: "error"; message: string };

function summaryOf(d: PluginDetail): PluginSummary {
  return {
    name: d.name,
    title: d.title,
    version: d.version,
    description: d.description,
    author: d.author,
    hooks: d.hooks,
    state: d.state,
    enabled: d.enabled,
    last_error: d.last_error,
    started_at: d.started_at,
    stats: d.stats,
  };
}

/** Strip the "Label: " prefix the API puts on field validation errors. */
function fieldMessage(label: string, msg: string): string {
  return msg.startsWith(`${label}: `) ? msg.slice(label.length + 2) : msg;
}

/**
 * Everything the plugin drawer needs for one plugin: detail + settings
 * auto-save, live status, activity log and actions. `onSummary` is called
 * whenever the plugin's summary changes (a settings save restarts it), so
 * the list stays in sync.
 */
export function usePlugin(name: string, onSummary: (s: PluginSummary) => void) {
  const [detail, setDetail] = useState<PluginDetail | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [status, setStatus] = useState<unknown>(null);
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [logLevel, setLogLevel] = useState<LogLevel>("info");
  const [fields, setFields] = useState<Record<string, FieldSave>>({});
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ action: string; result: unknown } | null>(null);
  const { feedback, showFeedback, clearFeedback } = useFeedback();
  const savedTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});
  const onSummaryRef = useRef(onSummary);
  useEffect(() => {
    onSummaryRef.current = onSummary;
  }, [onSummary]);

  const applyDetail = useCallback((d: PluginDetail) => {
    setDetail(d);
    onSummaryRef.current(summaryOf(d));
  }, []);

  const loadDetail = useCallback(async () => {
    try {
      applyDetail(await getPlugin(name));
      setLoadError(null);
    } catch (err: unknown) {
      setLoadError(err instanceof Error ? err.message : "Could not load plugin");
    }
  }, [name, applyDetail]);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await getPluginStatus(name));
    } catch {
      // Status is best-effort; the summary still shows state + last error.
    }
  }, [name]);

  const loadLogs = useCallback(async () => {
    try {
      setLogs(await getPluginLogs(name, logLevel));
    } catch {
      // Keep the last good log view.
    }
  }, [name, logLevel]);

  useEffect(() => {
    queueMicrotask(loadDetail);
  }, [loadDetail]);

  useEffect(() => {
    queueMicrotask(loadStatus);
    queueMicrotask(loadLogs);
    const id = setInterval(() => {
      loadStatus();
      loadLogs();
    }, STATUS_POLL_MS);
    return () => clearInterval(id);
  }, [loadStatus, loadLogs]);

  useEffect(() => {
    const timers = savedTimers.current;
    return () => Object.values(timers).forEach(clearTimeout);
  }, []);

  const markField = useCallback((key: string, s: FieldSave) => {
    setFields((f) => ({ ...f, [key]: s }));
    clearTimeout(savedTimers.current[key]);
    if (s.state === "saved") {
      // "Saved" is a transient confirmation; errors stay until fixed.
      savedTimers.current[key] = setTimeout(
        () =>
          setFields((f) => {
            const next = { ...f };
            delete next[key];
            return next;
          }),
        2500,
      );
    }
  }, []);

  /** Persist one setting (value or secret). Returns true on success. */
  const saveField = useCallback(
    async (key: string, label: string, value: SettingValue, secret: boolean) => {
      markField(key, { state: "saving" });
      try {
        const d = await updatePluginSettings(
          name,
          secret
            ? { secrets: { [key]: (value as string | null) ?? null } }
            : { values: { [key]: value } },
        );
        applyDetail(d);
        markField(key, { state: "saved" });
        if (d.state === "error") {
          showFeedback("error", `Saved, but the plugin failed to restart: ${d.last_error}`);
        }
        loadStatus();
        return true;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Save failed";
        markField(key, { state: "error", message: fieldMessage(label, msg) });
        return false;
      }
    },
    [name, applyDetail, markField, showFeedback, loadStatus],
  );

  const reset = useCallback(async () => {
    clearFeedback();
    try {
      const s = await resetPlugin(name);
      onSummaryRef.current(s);
      setFields({});
      await loadDetail();
      showFeedback("success", "Settings reset to defaults and plugin disabled.");
    } catch (err: unknown) {
      showFeedback("error", err instanceof Error ? err.message : "Reset failed");
    }
  }, [name, loadDetail, clearFeedback, showFeedback]);

  const runAction = useCallback(
    async (id: string, label: string, args: Record<string, SettingValue>) => {
      setActionBusy(id);
      clearFeedback();
      setLastResult(null);
      try {
        const result = await runPluginAction(name, id, args);
        setLastResult({ action: label, result });
        showFeedback("success", `${label} finished.`);
        loadStatus();
        loadLogs();
      } catch (err: unknown) {
        showFeedback("error", `${label}: ${err instanceof Error ? err.message : "failed"}`);
      } finally {
        setActionBusy(null);
      }
    },
    [name, clearFeedback, showFeedback, loadStatus, loadLogs],
  );

  return {
    detail,
    loadError,
    status,
    logs,
    logLevel,
    setLogLevel,
    fields,
    actionBusy,
    lastResult,
    feedback,
    showFeedback,
    applyDetail,
    reload: loadDetail,
    clearResult: () => setLastResult(null),
    refreshLogs: loadLogs,
    saveField,
    reset,
    runAction,
  };
}
