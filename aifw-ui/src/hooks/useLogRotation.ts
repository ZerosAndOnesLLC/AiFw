"use client";

import { useCallback, useEffect, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  LogRotationConfig,
  LogRotationLimits,
  ManagedLogStatus,
  defaultLogRotationConfig,
  defaultLogRotationLimits,
  getLogRotation,
  rotateLogs,
  saveLogRotation,
} from "@/lib/api/logRotation";

/** State + actions for Settings → Logging → Log Rotation (#205). */
export function useLogRotation() {
  const [config, setConfig] = useState<LogRotationConfig>(defaultLogRotationConfig);
  const [limits, setLimits] = useState<LogRotationLimits>(defaultLogRotationLimits);
  const [logs, setLogs] = useState<ManagedLogStatus[]>([]);
  const [confPath, setConfPath] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotating, setRotating] = useState<string | "all" | null>(null);
  const { feedback, showFeedback, clearFeedback } = useFeedback(5000);

  const refresh = useCallback(async () => {
    try {
      const v = await getLogRotation();
      setConfig(v.config);
      setLimits(v.limits);
      setLogs(v.logs);
      setConfPath(v.conf_path);
    } catch {
      // endpoint may not exist yet (older API)
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    (async () => {
      await refresh();
    })();
  }, [refresh]);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const v = await saveLogRotation(config);
      setConfig(v.config);
      setLogs(v.logs);
      showFeedback("success", "Log rotation policy saved and applied.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  /** Rotate one log now (path) or run a pass over all managed logs. */
  const rotate = async (path?: string) => {
    setRotating(path ?? "all");
    clearFeedback();
    try {
      const r = await rotateLogs(path);
      setLogs(r.logs);
      showFeedback(r.ok ? "success" : "error", r.message);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Rotate failed: ${msg}`);
    } finally {
      setRotating(null);
    }
  };

  return {
    config,
    setConfig,
    limits,
    logs,
    confPath,
    loading,
    saving,
    rotating,
    feedback,
    refresh,
    save,
    rotate,
  };
}
