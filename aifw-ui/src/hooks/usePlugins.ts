"use client";

import { useCallback, useEffect, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  HookInfo,
  PluginSummary,
  listPlugins,
  setPluginEnabled,
} from "@/lib/api/plugins";

const POLL_MS = 10_000;

/** Plugin list, enable/disable, and the page-level feedback banner. */
export function usePlugins() {
  const [plugins, setPlugins] = useState<PluginSummary[]>([]);
  const [hooks, setHooks] = useState<HookInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const { feedback, showFeedback, clearFeedback } = useFeedback();

  const refresh = useCallback(async () => {
    try {
      const r = await listPlugins();
      setPlugins(r.plugins);
      setHooks(r.hooks);
      setLoadError(null);
    } catch (err: unknown) {
      setLoadError(err instanceof Error ? err.message : "Could not load plugins");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    queueMicrotask(refresh);
    const id = setInterval(refresh, POLL_MS);
    return () => clearInterval(id);
  }, [refresh]);

  /** Replace one plugin's summary (after an action that returned it). */
  const upsert = useCallback((s: PluginSummary) => {
    setPlugins((list) => list.map((p) => (p.name === s.name ? s : p)));
  }, []);

  /** Enable/disable; resolves to the error message, or null on success. */
  const setEnabled = useCallback(
    async (p: PluginSummary, enabled: boolean): Promise<string | null> => {
      setBusy((b) => new Set(b).add(p.name));
      clearFeedback();
      try {
        const s = await setPluginEnabled(p.name, enabled);
        upsert(s);
        if (s.state === "error") {
          const msg = `${p.title} could not start: ${s.last_error ?? "unknown error"}`;
          showFeedback("error", msg);
          return msg;
        }
        showFeedback("success", `${p.title} ${enabled ? "enabled" : "disabled"}.`);
        return null;
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        showFeedback("error", `${p.title}: ${msg}`);
        return msg;
      } finally {
        setBusy((b) => {
          const next = new Set(b);
          next.delete(p.name);
          return next;
        });
      }
    },
    [clearFeedback, showFeedback, upsert],
  );

  return {
    plugins,
    hooks,
    loading,
    loadError,
    busy,
    feedback,
    refresh,
    upsert,
    setEnabled,
  };
}
