"use client";

import { useState, useEffect, useCallback } from "react";
import { useFeedback } from "@/hooks/useFeedback";
import {
  type ApplyReport,
  type DnsStatus,
  type ResolverConfig,
  type ServiceAction,
  applyResolverConfigApi,
  defaultResolverConfig,
  fetchDnsInterfaceNames,
  fetchResolverConfig,
  fetchResolverStatus,
  resolverServiceAction,
  saveResolverConfigApi,
} from "@/lib/api/dns";

/// Owns all DNS Resolver page data: status, config (with dirty tracking),
/// interface list, loading/saving flags, and the service/save/apply actions
/// with their success/error feedback (#428).
export function useDnsResolver() {
  const [status, setStatus] = useState<DnsStatus | null>(null);
  const [config, setConfigRaw] = useState<ResolverConfig>(defaultResolverConfig);
  const [isDirty, setIsDirty] = useState(false);
  const setConfig: typeof setConfigRaw = (v) => { setConfigRaw(v); setIsDirty(true); };
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [applying, setApplying] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const { feedback, showFeedback } = useFeedback();

  /* -- Fetch -------------------------------------------------------- */

  const fetchStatus = useCallback(async () => {
    try {
      setStatus(await fetchResolverStatus());
    } catch {
      /* silent */
    }
  }, []);

  const fetchConfig = useCallback(async () => {
    try {
      const data = await fetchResolverConfig();
      setConfigRaw(data);
    } catch {
      /* silent */
    }
  }, []);

  const fetchInterfaces = useCallback(async () => {
    try {
      setInterfaces(await fetchDnsInterfaceNames());
    } catch {
      /* silent */
    }
  }, []);

  useEffect(() => {
    (async () => {
      setLoading(true);
      await Promise.all([fetchStatus(), fetchConfig(), fetchInterfaces()]);
      setLoading(false);
    })();
  }, [fetchStatus, fetchConfig, fetchInterfaces]);

  /* -- Actions ------------------------------------------------------ */

  const reportToFeedback = (r: ApplyReport, fallback: string) => {
    const msg = r.message || fallback;
    if (r.rolled_back) {
      showFeedback("error", `Rolled back: ${msg}`);
    } else if (r.enabled && !r.probe_udp) {
      showFeedback("error", `Not responding on :53 — ${msg}`);
    } else {
      showFeedback("success", msg);
    }
  };

  const serviceAction = async (action: ServiceAction) => {
    setActionLoading(action);
    try {
      const data: ApplyReport | { message?: string } =
        (await resolverServiceAction(action)) ?? {};
      if ("probe_udp" in data) {
        reportToFeedback(data as ApplyReport, `DNS Resolver ${action} completed`);
      } else {
        const msg = (data as { message?: string }).message || `DNS Resolver ${action} completed`;
        showFeedback("success", msg);
      }
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : `Failed to ${action} DNS Resolver`);
    } finally {
      setActionLoading(null);
    }
  };

  const saveConfig = async () => {
    setSaving(true);
    try {
      await saveResolverConfigApi(config);
      showFeedback("success", "DNS Resolver settings saved");
      setIsDirty(false);
      await fetchConfig();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to save config");
    } finally {
      setSaving(false);
    }
  };

  const applyConfig = async () => {
    setApplying(true);
    try {
      // Save config first, then apply
      await saveResolverConfigApi(config);

      const data = await applyResolverConfigApi();
      reportToFeedback(data, "Configuration applied");
      setIsDirty(false);
      // If server rolled back, the persisted backend may have flipped —
      // refresh local config so the radio buttons reflect reality.
      if (data.rolled_back) await fetchConfig();
      await fetchStatus();
    } catch (err) {
      showFeedback("error", err instanceof Error ? err.message : "Failed to apply config");
    } finally {
      setApplying(false);
    }
  };

  const isAllInterfaces = config.listen_interfaces.length === 0 ||
    (config.listen_interfaces.length === 1 && config.listen_interfaces[0] === "0.0.0.0");

  const toggleInterface = (name: string) => {
    if (name === "__all__") {
      // Toggle "All" — set to 0.0.0.0 (listen on everything)
      setConfig((prev) => ({
        ...prev,
        listen_interfaces: ["0.0.0.0"],
      }));
      return;
    }
    // Clicking a specific interface: remove "all" wildcard, toggle this one
    setConfig((prev) => {
      const filtered = prev.listen_interfaces.filter((i) => i !== "0.0.0.0");
      return {
        ...prev,
        listen_interfaces: filtered.includes(name)
          ? filtered.filter((i) => i !== name)
          : [...filtered, name],
      };
    });
  };

  /* -- List helpers ------------------------------------------------- */

  const addToList = (field: keyof ResolverConfig, value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    setConfig((prev) => {
      const arr = prev[field] as string[];
      if (arr.includes(trimmed)) return prev;
      return { ...prev, [field]: [...arr, trimmed] };
    });
  };

  const removeFromList = (field: keyof ResolverConfig, index: number) => {
    setConfig((prev) => {
      const arr = [...(prev[field] as string[])];
      arr.splice(index, 1);
      return { ...prev, [field]: arr };
    });
  };

  return {
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
  };
}
