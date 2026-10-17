"use client";

import { useCallback, useEffect, useState } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  GeoIpDatabase,
  GeoIpLookup,
  GeoIpRule,
  RuleInput,
  createRule,
  deleteRule,
  getDatabase,
  listRules,
  lookupIp,
  refreshDatabase,
  updateDatabase,
  updateRule,
  uploadDatabase,
} from "@/lib/api/geoip";

const DB_POLL_MS = 30_000;

function errMsg(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

/** Rules, the GeoLite2 database behind them, lookups, and the page banner. */
export function useGeoip() {
  const [rules, setRules] = useState<GeoIpRule[]>([]);
  const [database, setDatabase] = useState<GeoIpDatabase | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const { feedback, showFeedback, clearFeedback } = useFeedback();

  const loadRules = useCallback(async () => {
    try {
      setRules(await listRules());
    } catch (err: unknown) {
      showFeedback("error", errMsg(err, "Could not load geo-IP rules"));
    } finally {
      setLoading(false);
    }
  }, [showFeedback]);

  const loadDatabase = useCallback(async () => {
    try {
      setDatabase(await getDatabase());
    } catch {
      // The rules table still works without the status card.
    }
  }, []);

  const reload = useCallback(async () => {
    await Promise.all([loadRules(), loadDatabase()]);
  }, [loadRules, loadDatabase]);

  useEffect(() => {
    queueMicrotask(reload);
    const id = setInterval(loadDatabase, DB_POLL_MS);
    return () => clearInterval(id);
  }, [reload, loadDatabase]);

  /** Run `fn`, mark `key` busy meanwhile, refresh, and report. */
  const run = useCallback(
    async (key: string, fn: () => Promise<string>): Promise<boolean> => {
      setBusy(key);
      clearFeedback();
      try {
        const msg = await fn();
        await reload();
        if (msg) showFeedback("success", msg);
        return true;
      } catch (err: unknown) {
        showFeedback("error", errMsg(err, "Request failed"));
        return false;
      } finally {
        setBusy(null);
      }
    },
    [reload, clearFeedback, showFeedback],
  );

  const addRule = useCallback(
    (input: RuleInput) =>
      run("add", async () => {
        const r = await createRule(input);
        return `${r.action === "block" ? "Blocking" : "Allowing"} ${r.country}${
          r.cidr_count ? ` (${r.cidr_count.toLocaleString()} networks)` : ""
        }.`;
      }),
    [run],
  );

  const saveRule = useCallback(
    (rule: GeoIpRule, patch: Partial<RuleInput>) =>
      run(rule.id, async () => {
        const next: RuleInput = {
          country: patch.country ?? rule.country,
          action: patch.action ?? rule.action,
          status: patch.status ?? rule.status,
          label: patch.label !== undefined ? patch.label : rule.label,
        };
        await updateRule(rule.id, next);
        return `${next.country} saved.`;
      }),
    [run],
  );

  const removeRule = useCallback(
    (rule: GeoIpRule) =>
      run(rule.id, async () => {
        await deleteRule(rule.id);
        return `Rule for ${rule.country} deleted.`;
      }),
    [run],
  );

  const lookup = useCallback(async (ip: string): Promise<GeoIpLookup> => lookupIp(ip), []);

  const saveDatabaseSettings = useCallback(
    (patch: { license_key?: string | null; update_interval_hours?: number }) =>
      run("db-settings", async () => {
        const st = await updateDatabase(patch);
        setDatabase(st);
        if (patch.license_key === null) return "License key removed.";
        if (patch.license_key) return "License key saved.";
        return "Refresh schedule saved.";
      }),
    [run],
  );

  const refresh = useCallback(
    () =>
      run("db-refresh", async () => {
        const r = await refreshDatabase();
        return `Downloaded ${r.cidrs.toLocaleString()} networks from MaxMind.`;
      }),
    [run],
  );

  const upload = useCallback(
    (files: File[]) =>
      run("db-upload", async () => {
        const r = await uploadDatabase(files);
        return `Imported ${r.cidrs.toLocaleString()} networks.`;
      }),
    [run],
  );

  return {
    rules,
    database,
    loading,
    busy,
    feedback,
    reload,
    addRule,
    saveRule,
    removeRule,
    lookup,
    saveDatabaseSettings,
    refresh,
    upload,
  };
}
