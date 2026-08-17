"use client";

// Per-resource data hooks for the Settings page (#428). Each hook owns the
// data/loading/saving state, mount fetch, and save/test actions for one
// settings section. The page composes these with presentational components.
//
// Feedback semantics preserved from the original page: sections that
// auto-dismissed messages did so after 4 seconds (useFeedback(4000));
// sections whose messages stayed visible until replaced use plain state.

import { useCallback, useEffect, useState } from "react";
import { Feedback, FeedbackType, useFeedback } from "@/hooks/useFeedback";
import {
  SyslogConfig,
  SyslogProcessStatus,
  defaultSyslogConfig,
  getSyslogConfig,
  getSyslogStatus,
  saveSyslogConfig,
  testSyslog,
} from "@/lib/api/syslog";
import {
  AiProviderConfig,
  AiTestResult,
  ConsoleKind,
  HistoryMode,
  IdsAlertStats,
  S3ConfigPayload,
  S3TestResult,
  SmtpConfigPayload,
  SmtpTls,
  getAiModels,
  getAiSettings,
  getAuthSettings,
  getConfigRetention,
  getDashboardHistorySettings,
  getDnsConfig,
  getIdsAlertSettings,
  getPfTuning,
  getS3Config,
  getSmtpConfig,
  getSystemBanner,
  getSystemConsole,
  getSystemGeneral,
  getSystemSsh,
  getTimezones,
  getTlsPolicy,
  getValkeySettings,
  rebootSystem,
  saveAiSettings,
  saveApiServerSettings,
  getApiServerSettings,
  saveAuthSettings,
  saveConfigRetention,
  saveDashboardHistorySettings,
  saveDnsConfig,
  saveIdsAlertSettings,
  saveMetricsSettings,
  savePfTuning,
  saveS3Config,
  saveSmtpConfig,
  saveSystemBanner,
  saveSystemConsole,
  saveSystemGeneral,
  saveSystemSsh,
  saveTlsPolicy,
  saveValkeySettings,
  testAiConnection,
  testS3Config,
  testSmtpConfig,
} from "@/lib/api/settings";

// --- DNS Configuration ---

export function useDnsSettings() {
  const [servers, setServers] = useState<string[]>([]);
  const [newDns, setNewDns] = useState("");
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  // Load errors stayed visible until replaced; save/validation messages
  // auto-dismissed after 4s. Compose both behaviors over one banner.
  const { feedback: timed, showFeedback, clearFeedback } = useFeedback(4000);
  const [loadError, setLoadError] = useState<Feedback | null>(null);
  const feedback = timed ?? loadError;

  const show = useCallback(
    (type: FeedbackType, msg: string) => {
      setLoadError(null);
      showFeedback(type, msg);
    },
    [showFeedback],
  );

  useEffect(() => {
    (async () => {
      try {
        const data = await getDnsConfig();
        setServers(data.servers || []);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setLoadError({ type: "error", msg: `Failed to load DNS servers: ${msg}` });
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    setLoadError(null);
    clearFeedback();
    try {
      await saveDnsConfig(servers);
      show("success", "DNS servers saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      show("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  const addServer = () => {
    const trimmed = newDns.trim();
    if (!trimmed) return;
    // Basic IPv4/IPv6 validation
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6 = /^[0-9a-fA-F:]+$/;
    if (!ipv4.test(trimmed) && !ipv6.test(trimmed)) {
      show("error", "Invalid IP address format.");
      return;
    }
    if (servers.includes(trimmed)) {
      show("error", "Server already in list.");
      return;
    }
    setServers((prev) => [...prev, trimmed]);
    setNewDns("");
  };

  const removeServer = (index: number) => {
    setServers((prev) => prev.filter((_, i) => i !== index));
  };

  return { servers, newDns, setNewDns, loading, saving, feedback, addServer, removeServer, save };
}

// --- Metrics Storage ---

export function useMetricsSettings() {
  const [backend, setBackend] = useState("local");
  const [postgresUrl, setPostgresUrl] = useState("");
  const [collectionInterval, setCollectionInterval] = useState("1");
  const [retentionDays, setRetentionDays] = useState("365");
  const [saving, setSaving] = useState(false);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      await saveMetricsSettings({
        backend,
        postgres_url: backend === "postgres" ? postgresUrl : undefined,
        collection_interval: Number(collectionInterval),
        retention_days: Number(retentionDays),
      });
      showFeedback("success", "Metrics settings saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return {
    backend,
    setBackend,
    postgresUrl,
    setPostgresUrl,
    collectionInterval,
    setCollectionInterval,
    retentionDays,
    setRetentionDays,
    saving,
    feedback,
    save,
  };
}

// --- API Server ---

export function useApiServerSettings() {
  const [port, setPort] = useState("8080");
  const [corsOrigins, setCorsOrigins] = useState("*");
  const [trustedProxies, setTrustedProxies] = useState("");
  const [saving, setSaving] = useState(false);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const s = await getApiServerSettings();
        if (s.port) setPort(String(s.port));
        if (s.cors_origins) setCorsOrigins(s.cors_origins);
        if (s.trusted_proxies !== undefined) setTrustedProxies(s.trusted_proxies);
      } catch {
        // endpoint may not exist yet
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      await saveApiServerSettings({
        port: Number(port),
        cors_origins: corsOrigins,
        trusted_proxies: trustedProxies,
      });
      showFeedback("success", "API settings saved — applied at the next aifw-api restart.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return { port, setPort, corsOrigins, setCorsOrigins, trustedProxies, setTrustedProxies, saving, feedback, save };
}

// --- TLS Policy ---

export function useTlsPolicy() {
  const [minVersion, setMinVersion] = useState("tls12");
  const [blockExpired, setBlockExpired] = useState(true);
  const [blockWeakKeys, setBlockWeakKeys] = useState(true);
  const [saving, setSaving] = useState(false);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const data = await getTlsPolicy();
        if (data.min_version) setMinVersion(data.min_version);
        if (data.block_expired !== undefined) setBlockExpired(data.block_expired);
        if (data.block_weak_keys !== undefined) setBlockWeakKeys(data.block_weak_keys);
      } catch {
        // endpoint may not exist yet
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      await saveTlsPolicy({
        min_version: minVersion,
        block_expired: blockExpired,
        block_weak_keys: blockWeakKeys,
      });
      showFeedback("success", "TLS policy saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return {
    minVersion,
    setMinVersion,
    blockExpired,
    setBlockExpired,
    blockWeakKeys,
    setBlockWeakKeys,
    saving,
    feedback,
    save,
  };
}

// --- Auth Settings ---

export function useAuthSettings() {
  const [sessionTimeout, setSessionTimeout] = useState(480);
  const [maxLoginAttempts, setMaxLoginAttempts] = useState(5);
  const [lockoutDuration, setLockoutDuration] = useState(300);
  const [requireMfa, setRequireMfa] = useState(false);
  const [allowRegistration, setAllowRegistration] = useState(false);
  const [passwordMinLength, setPasswordMinLength] = useState(8);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  // Load errors persisted; save results auto-dismissed after 4s.
  const { feedback: timed, showFeedback, clearFeedback } = useFeedback(4000);
  const [loadError, setLoadError] = useState<Feedback | null>(null);
  const feedback = timed ?? loadError;

  useEffect(() => {
    (async () => {
      try {
        const data = await getAuthSettings();
        if (data.access_token_expiry_mins !== undefined) setSessionTimeout(data.access_token_expiry_mins);
        if (data.require_totp !== undefined) setRequireMfa(data.require_totp);
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : "Unknown error";
        setLoadError({ type: "error", msg: `Failed to load auth settings: ${msg}` });
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    setLoadError(null);
    clearFeedback();
    try {
      await saveAuthSettings({
        access_token_expiry_mins: sessionTimeout,
        require_totp: requireMfa,
      });
      showFeedback("success", "Auth settings saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return {
    sessionTimeout,
    setSessionTimeout,
    maxLoginAttempts,
    setMaxLoginAttempts,
    lockoutDuration,
    setLockoutDuration,
    requireMfa,
    setRequireMfa,
    allowRegistration,
    setAllowRegistration,
    passwordMinLength,
    setPasswordMinLength,
    loading,
    saving,
    feedback,
    save,
  };
}

// --- Valkey/Metrics Persistence ---

export function useValkeySettings() {
  const [enabled, setEnabled] = useState(true);
  const [url, setUrl] = useState("redis://127.0.0.1:6379");
  const [retention, setRetention] = useState(30);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState<string>("unknown");
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const data = await getValkeySettings();
        if (data.enabled !== undefined) setEnabled(data.enabled);
        if (data.url) setUrl(data.url);
        if (data.retention_minutes) setRetention(data.retention_minutes);
        if (data.status) setStatus(data.status);
      } catch {
        // endpoint may not exist yet
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const data = await saveValkeySettings({
        enabled,
        url,
        retention_minutes: retention,
      });
      if (data.status) setStatus(data.status);
      showFeedback("success", "Valkey settings saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return { enabled, setEnabled, url, setUrl, retention, setRetention, status, loading, saving, feedback, save };
}

// --- Dashboard History ---

export function useDashboardHistory() {
  const [mode, setMode] = useState<HistoryMode>("duration");
  const [minutes, setMinutes] = useState(30);
  const [ramMb, setRamMb] = useState(512);
  const [entries, setEntries] = useState(0);
  const [estRamMb, setEstRamMb] = useState(0);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const data = await getDashboardHistorySettings();
        if (data.mode === "duration" || data.mode === "ram") setMode(data.mode);
        if (data.history_seconds) setMinutes(Math.round(data.history_seconds / 60));
        if (data.current_entries !== undefined) setEntries(data.current_entries);
        if (data.estimated_ram_mb !== undefined) setEstRamMb(data.estimated_ram_mb);
        if (data.ram_limit_mb) setRamMb(data.ram_limit_mb);
      } catch {
        // endpoint may not exist yet
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const body =
        mode === "ram"
          ? { mode: "ram" as const, ram_limit_mb: ramMb }
          : { mode: "duration" as const, history_seconds: Math.max(5, minutes) * 60 };
      const data = await saveDashboardHistorySettings(body);
      if (data.estimated_ram_mb !== undefined) setEstRamMb(data.estimated_ram_mb);
      if (data.history_seconds) setMinutes(Math.round(data.history_seconds / 60));
      showFeedback("success", "Dashboard history updated. Takes effect immediately.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return {
    mode,
    setMode,
    minutes,
    setMinutes,
    ramMb,
    setRamMb,
    entries,
    estRamMb,
    loading,
    saving,
    feedback,
    save,
  };
}

// --- pf state-table tuning ---

export function usePfTuning() {
  const [maxStates, setMaxStates] = useState(100000);
  const [configured, setConfigured] = useState(100000);
  const [live, setLive] = useState<number | null>(null);
  const [current, setCurrent] = useState(0);
  const [min, setMin] = useState(1000);
  const [max, setMax] = useState(4000000);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const d = await getPfTuning();
        if (typeof d.configured_max_states === "number") {
          setConfigured(d.configured_max_states);
          setMaxStates(d.configured_max_states);
        }
        if (typeof d.live_max_states === "number") setLive(d.live_max_states);
        if (typeof d.current_states === "number") setCurrent(d.current_states);
        if (typeof d.min_states === "number") setMin(d.min_states);
        if (typeof d.max_states === "number") setMax(d.max_states);
      } catch { /* silent */ }
      finally { setLoading(false); }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const d = await savePfTuning(maxStates);
      setConfigured(d.configured_max_states);
      setLive(d.live_max_states);
      showFeedback("success", "pf state-table limit applied (no reload of rules required).");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return { maxStates, setMaxStates, configured, live, current, min, max, loading, saving, feedback, save };
}

// --- Config History (auto-snapshots) ---

export function useConfigRetention() {
  const [maxVersions, setMaxVersions] = useState(200);
  const [currentCount, setCurrentCount] = useState(0);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const data = await getConfigRetention();
        if (typeof data.max_versions === "number") setMaxVersions(data.max_versions);
        if (typeof data.current_count === "number") setCurrentCount(data.current_count);
      } catch {
        /* silent */
      } finally {
        setLoading(false);
      }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const data = await saveConfigRetention(maxVersions);
      if (typeof data.max_versions === "number") setMaxVersions(data.max_versions);
      if (typeof data.current_count === "number") setCurrentCount(data.current_count);
      showFeedback("success", "Config history retention saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  return { maxVersions, setMaxVersions, currentCount, loading, saving, feedback, save };
}

// --- S3 Backup Sync ---

export function useS3Backup() {
  const [enabled, setEnabled] = useState(false);
  const [bucket, setBucket] = useState("");
  const [region, setRegion] = useState("us-east-1");
  const [endpoint, setEndpoint] = useState("");
  const [prefix, setPrefix] = useState("");
  const [pathStyle, setPathStyle] = useState(false);
  const [accessKey, setAccessKey] = useState("");
  const [secret, setSecret] = useState("");             // "" means "unchanged" on save
  const [hasSecret, setHasSecret] = useState(false);
  const [backupPassphrase, setBackupPassphrase] = useState(""); // "" = unchanged; " " sentinel never sent
  const [clearBackupPassphrase, setClearBackupPassphrase] = useState(false);
  const [hasBackupPassphrase, setHasBackupPassphrase] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<S3TestResult | null>(null);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const d = await getS3Config();
        setEnabled(!!d.enabled);
        setBucket(d.bucket || "");
        setRegion(d.region || "us-east-1");
        setEndpoint(d.endpoint || "");
        setPrefix(d.prefix || "");
        setPathStyle(!!d.path_style);
        setAccessKey(d.access_key_id || "");
        setHasSecret(!!d.has_secret);
        setSecret(""); // always blank in UI (means "unchanged")
        setHasBackupPassphrase(!!d.has_secrets_passphrase);
        setBackupPassphrase("");
        setClearBackupPassphrase(false);
      } catch { /* silent */ } finally {
        setLoading(false);
      }
    })();
  }, []);

  // Build the S3 payload from current form state. Secret field is left
  // undefined (not null) when the user didn't touch it — the server reads
  // `None` as "unchanged", avoiding accidental wipes.
  const buildPayload = (): S3ConfigPayload => ({
    enabled,
    bucket: bucket.trim(),
    region: region.trim() || "us-east-1",
    endpoint: endpoint.trim() || null,
    prefix: prefix.trim(),
    path_style: pathStyle,
    access_key_id: accessKey.trim() || null,
    secret_access_key: secret === "" ? null : secret,
    // #313: null = unchanged, "" = clear, otherwise set.
    secrets_passphrase: clearBackupPassphrase ? "" : backupPassphrase === "" ? null : backupPassphrase,
  });

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const d = await saveS3Config(buildPayload());
      setHasSecret(!!d.has_secret);
      setSecret("");
      setHasBackupPassphrase(!!d.has_secrets_passphrase);
      setBackupPassphrase("");
      setClearBackupPassphrase(false);
      showFeedback("success", "S3 settings saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const d = await testS3Config(buildPayload());
      setTestResult({
        ok: !!d.ok,
        message: d.message || "",
        write: !!d.write,
        read: !!d.read,
        delete: !!d.delete,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setTestResult({ ok: false, message: msg, write: false, read: false, delete: false });
    } finally {
      setTesting(false);
    }
  };

  return {
    enabled,
    setEnabled,
    bucket,
    setBucket,
    region,
    setRegion,
    endpoint,
    setEndpoint,
    prefix,
    setPrefix,
    pathStyle,
    setPathStyle,
    accessKey,
    setAccessKey,
    secret,
    setSecret,
    hasSecret,
    backupPassphrase,
    setBackupPassphrase,
    clearBackupPassphrase,
    setClearBackupPassphrase,
    hasBackupPassphrase,
    saving,
    testing,
    testResult,
    loading,
    feedback,
    save,
    test,
  };
}

// --- SMTP notifications ---

export function useSmtpSettings() {
  const [enabled, setEnabled] = useState(false);
  const [host, setHost] = useState("");
  const [port, setPort] = useState(587);
  const [tls, setTls] = useState<SmtpTls>("starttls");
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");             // "" means "unchanged"
  const [hasPass, setHasPass] = useState(false);
  const [from, setFrom] = useState("aifw@localhost");
  const [recipients, setRecipients] = useState("");
  const [events, setEvents] = useState<string[]>([
    "s3_upload_failed", "restore_failed", "cert_renew_failed", "cert_expiring_soon",
  ]);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [loading, setLoading] = useState(true);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const d = await getSmtpConfig();
        setEnabled(!!d.enabled);
        setHost(d.host || "");
        setPort(Number(d.port) || 587);
        setTls((d.tls || "starttls") as SmtpTls);
        setUser(d.username || "");
        setHasPass(!!d.has_password);
        setPass("");
        setFrom(d.from_address || "aifw@localhost");
        setRecipients(d.recipients || "");
        setEvents(Array.isArray(d.enabled_events) ? d.enabled_events : []);
      } catch { /* silent */ } finally {
        setLoading(false);
      }
    })();
  }, []);

  const buildPayload = (): SmtpConfigPayload => ({
    enabled,
    host: host.trim(),
    port: Number(port) || 587,
    tls,
    username: user.trim() || null,
    password: pass === "" ? null : pass,
    from_address: from.trim(),
    recipients: recipients.trim(),
    enabled_events: events,
  });

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const d = await saveSmtpConfig(buildPayload());
      setHasPass(!!d.has_password);
      setPass("");
      showFeedback("success", "SMTP settings saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  const test = async () => {
    setTesting(true);
    clearFeedback();
    try {
      const d = await testSmtpConfig(buildPayload());
      showFeedback(
        d.ok ? "success" : "error",
        d.message || (d.ok ? "Test email sent." : "Test failed."),
      );
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Test failed: ${msg}`);
    } finally {
      setTesting(false);
    }
  };

  return {
    enabled,
    setEnabled,
    host,
    setHost,
    port,
    setPort,
    tls,
    setTls,
    user,
    setUser,
    pass,
    setPass,
    hasPass,
    from,
    setFrom,
    recipients,
    setRecipients,
    events,
    setEvents,
    saving,
    testing,
    loading,
    feedback,
    save,
    test,
  };
}

// --- IDS Alert Buffer ---

export function useIdsAlertSettings() {
  const [maxMb, setMaxMb] = useState(64);
  const [maxAge, setMaxAge] = useState(86400);
  const [stats, setStats] = useState<IdsAlertStats | null>(null);
  const [saving, setSaving] = useState(false);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const data = await getIdsAlertSettings();
        if (data.max_mb) setMaxMb(data.max_mb);
        if (data.max_age_secs) setMaxAge(data.max_age_secs);
        if (data.stats) setStats(data.stats);
      } catch { /* endpoint may not exist */ }
    })();
  }, []);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      const data = await saveIdsAlertSettings(maxMb, maxAge);
      if (data.stats) setStats(data.stats);
      showFeedback("success", "IDS alert settings saved.");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally { setSaving(false); }
  };

  return { maxMb, setMaxMb, maxAge, setMaxAge, stats, saving, feedback, save };
}

// --- AI Providers ---

export function useAiProviders() {
  const [enabled, setEnabled] = useState(false);
  const [activeProvider, setActiveProvider] = useState("");
  const [providers, setProviders] = useState<AiProviderConfig[]>([]);
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);
  const [editingProvider, setEditingProvider] = useState<string | null>(null);
  const [editKey, setEditKey] = useState("");
  const [editEndpoint, setEditEndpoint] = useState("");
  const [editModel, setEditModel] = useState("");
  const [editTlsInsecure, setEditTlsInsecure] = useState(false);
  const [models, setModels] = useState<string[]>([]);
  const [modelsLoading, setModelsLoading] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<AiTestResult | null>(null);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  useEffect(() => {
    (async () => {
      try {
        const data = await getAiSettings();
        if (data.enabled !== undefined) setEnabled(data.enabled);
        if (data.active_provider) setActiveProvider(data.active_provider);
        if (data.providers) setProviders(data.providers);
      } catch { /* endpoint may not exist yet */ }
      finally { setLoading(false); }
    })();
  }, []);

  const saveProvider = async (provider: string, providerEnabled?: boolean) => {
    setSaving(true);
    clearFeedback();
    try {
      const body: Record<string, unknown> = { provider };
      if (providerEnabled !== undefined) body.provider_enabled = providerEnabled;
      if (editKey) body.api_key = editKey;
      if (editEndpoint) body.endpoint = editEndpoint;
      if (editModel) body.model = editModel;
      body.tls_insecure = editTlsInsecure;
      await saveAiSettings(body);
      showFeedback("success", `${provider} settings saved.`);
      setEditingProvider(null);
      setEditKey("");
      // Refresh (best-effort — a failed refresh shouldn't flag the save as failed)
      const d = await getAiSettings().catch(() => null);
      if (d) {
        setProviders(d.providers || []);
        setActiveProvider(d.active_provider || "");
        setEnabled(d.enabled ?? false);
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally { setSaving(false); }
  };

  const saveGlobal = async (nextEnabled: boolean, active?: string) => {
    setSaving(true);
    try {
      const body: Record<string, unknown> = { enabled: nextEnabled };
      if (active) body.active_provider = active;
      await saveAiSettings(body);
      setEnabled(nextEnabled);
      if (active) setActiveProvider(active);
      showFeedback("success", nextEnabled ? "AI analysis enabled." : "AI analysis disabled.");
    } catch { /* ignore */ }
    finally { setSaving(false); }
  };

  const fetchModels = async (provider: string) => {
    setModelsLoading(true);
    setModels([]);
    try {
      const data = await getAiModels(provider);
      setModels(data.models || []);
    } catch { /* ignore */ }
    finally { setModelsLoading(false); }
  };

  const testConnection = async (provider: string) => {
    setTesting(true);
    setTestResult(null);
    try {
      const body: Record<string, unknown> = { provider };
      if (editEndpoint) body.endpoint = editEndpoint;
      if (editKey) body.api_key = editKey;
      body.tls_insecure = editTlsInsecure;
      const data = await testAiConnection(body);
      setTestResult({ success: data.success, status_code: data.status_code });
    } catch {
      setTestResult({ success: false, status_code: "error" });
    } finally { setTesting(false); }
  };

  return {
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
  };
}

// --- System General ---

export function useSystemGeneral() {
  const [hostname, setHostname] = useState("");
  const [domain, setDomain] = useState("");
  const [timezone, setTimezone] = useState("UTC");
  const [timezoneList, setTimezoneList] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  useEffect(() => {
    // Fetch System General
    (async () => {
      try {
        const d = await getSystemGeneral();
        setHostname(d.hostname || "");
        setDomain(d.domain || "");
        setTimezone(d.timezone || "UTC");
      } catch { /* silent */ }
    })();

    // Fetch timezone list
    (async () => {
      try {
        const d = await getTimezones();
        setTimezoneList(Array.isArray(d) ? d : ["UTC"]);
      } catch { setTimezoneList(["UTC"]); }
    })();
  }, []);

  const save = async () => {
    setSaving(true); setFeedback(null);
    try {
      const res = await saveSystemGeneral({ hostname, domain, timezone });
      const msg = res.warning ? `Saved (warning: ${res.warning})` : "Saved.";
      setFeedback({ type: res.warning ? "error" : "success", msg });
    } catch (e) { setFeedback({ type: "error", msg: String(e) }); }
    finally { setSaving(false); }
  };

  return {
    hostname,
    setHostname,
    domain,
    setDomain,
    timezone,
    setTimezone,
    timezoneList,
    saving,
    feedback,
    save,
  };
}

// --- System Banner ---

export function useSystemBanner() {
  const [loginBanner, setLoginBanner] = useState("");
  const [motd, setMotd] = useState("");
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const d = await getSystemBanner();
        setLoginBanner(d.login_banner || "");
        setMotd(d.motd || "");
      } catch { /* silent */ }
    })();
  }, []);

  const save = async () => {
    setSaving(true); setFeedback(null);
    try {
      await saveSystemBanner({ login_banner: loginBanner, motd });
      setFeedback({ type: "success", msg: "Saved." });
    } catch (e) { setFeedback({ type: "error", msg: String(e) }); }
    finally { setSaving(false); }
  };

  return { loginBanner, setLoginBanner, motd, setMotd, saving, feedback, save };
}

// --- System SSH ---

export function useSystemSsh() {
  const [enabled, setEnabled] = useState(true);
  const [port, setPort] = useState(22);
  const [passwordAuth, setPasswordAuth] = useState(false);
  const [permitRoot, setPermitRoot] = useState(false);
  const [saving, setSaving] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const d = await getSystemSsh();
        if (d.enabled !== undefined) setEnabled(d.enabled);
        if (d.port !== undefined) setPort(d.port);
        if (d.password_auth !== undefined) setPasswordAuth(d.password_auth);
        if (d.permit_root_login !== undefined) setPermitRoot(d.permit_root_login);
      } catch { /* silent */ }
    })();
  }, []);

  const save = async () => {
    setSaving(true); setFeedback(null);
    try {
      await saveSystemSsh({ enabled, port, password_auth: passwordAuth, permit_root_login: permitRoot });
      setFeedback({ type: "success", msg: `Saved. sshd reloading${port !== 22 ? ` — reconnect on port ${port}` : ""}.` });
    } catch (e) { setFeedback({ type: "error", msg: String(e) }); }
    finally { setSaving(false); }
  };

  return {
    enabled,
    setEnabled,
    port,
    setPort,
    passwordAuth,
    setPasswordAuth,
    permitRoot,
    setPermitRoot,
    saving,
    feedback,
    save,
  };
}

// --- System Console ---

export function useSystemConsole() {
  const [kind, setKind] = useState<ConsoleKind>("video");
  const [baud, setBaud] = useState(115200);
  const [saving, setSaving] = useState(false);
  const [confirm, setConfirm] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const d = await getSystemConsole();
        if (d.kind) setKind(d.kind);
        if (d.baud) setBaud(d.baud);
      } catch { /* silent */ }
    })();
  }, []);

  const save = async () => {
    setSaving(true); setFeedback(null);
    try {
      await saveSystemConsole({ kind, baud });
      setFeedback({ type: "success", msg: "Saved. Reboot required. Verify console access before rebooting." });
      setConfirm(false);
    } catch (e) { setFeedback({ type: "error", msg: String(e) }); }
    finally { setSaving(false); }
  };

  return { kind, setKind, baud, setBaud, confirm, setConfirm, saving, feedback, save };
}

// --- System Actions (reboot) ---

export function useSystemActions() {
  const [confirmReboot, setConfirmReboot] = useState(false);
  const [rebooting, setRebooting] = useState(false);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const reboot = async () => {
    setRebooting(true);
    setFeedback(null);
    try {
      const data = await rebootSystem();
      setFeedback({ type: "success", msg: data.message || "System rebooting..." });
      setConfirmReboot(false);
    } catch {
      setFeedback({ type: "error", msg: "Failed to initiate reboot" });
    } finally {
      setRebooting(false);
    }
  };

  return { confirmReboot, setConfirmReboot, rebooting, feedback, reboot };
}

// --- Remote Logging (Syslog) ---

export function useSyslogSettings() {
  const [config, setConfig] = useState<SyslogConfig>(defaultSyslogConfig);
  const [status, setStatus] = useState<SyslogProcessStatus[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const { feedback, showFeedback, clearFeedback } = useFeedback(4000);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await getSyslogStatus());
    } catch {
      // endpoint may not exist yet (older API)
    }
  }, []);

  useEffect(() => {
    (async () => {
      try {
        setConfig(await getSyslogConfig());
      } catch {
        // endpoint may not exist yet
      } finally {
        setLoading(false);
      }
      refreshStatus();
    })();
  }, [refreshStatus]);

  const save = async () => {
    setSaving(true);
    clearFeedback();
    try {
      await saveSyslogConfig(config);
      showFeedback("success", "Syslog settings saved.");
      refreshStatus();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Save failed: ${msg}`);
    } finally {
      setSaving(false);
    }
  };

  // Tests with the CURRENT form values (unsaved drafts included) so the
  // server can be verified before committing the config.
  const test = async () => {
    if (!config.host.trim()) {
      showFeedback("error", "Enter a syslog server host first.");
      return;
    }
    setTesting(true);
    clearFeedback();
    try {
      const r = await testSyslog(config);
      showFeedback(r.ok ? "success" : "error", r.message);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      showFeedback("error", `Test failed: ${msg}`);
    } finally {
      setTesting(false);
    }
  };

  return {
    config,
    setConfig,
    status,
    refreshStatus,
    loading,
    saving,
    testing,
    feedback,
    save,
    test,
  };
}
