"use client";

import { useCallback, useMemo } from "react";
import { useSearchParams, useRouter, usePathname } from "next/navigation";
import {
  useAiProviders,
  useApiServerSettings,
  useAuthSettings,
  useConfigRetention,
  useDashboardHistory,
  useDnsSettings,
  useIdsAlertSettings,
  useMetricsSettings,
  usePfTuning,
  useS3Backup,
  useSmtpSettings,
  useSyslogSettings,
  useSystemActions,
  useSystemBanner,
  useSystemConsole,
  useSystemGeneral,
  useSystemSsh,
  useTlsPolicy,
  useValkeySettings,
} from "@/hooks/useSettings";
import { AiProvidersSection } from "./components/AiProvidersSection";
import { ApiServerSection } from "./components/ApiServerSection";
import { AuthSection } from "./components/AuthSection";
import { BannerSection } from "./components/BannerSection";
import { ConfigHistorySection } from "./components/ConfigHistorySection";
import { ConsoleSection } from "./components/ConsoleSection";
import { DashboardHistorySection } from "./components/DashboardHistorySection";
import { DnsSection } from "./components/DnsSection";
import { GeneralSection } from "./components/GeneralSection";
import { IdsAlertSection } from "./components/IdsAlertSection";
import { MetricsSection } from "./components/MetricsSection";
import { PfStateTableSection } from "./components/PfStateTableSection";
import { S3BackupSection } from "./components/S3BackupSection";
import { SmtpSection } from "./components/SmtpSection";
import { SshSection } from "./components/SshSection";
import { SyslogSection } from "./components/SyslogSection";
import { SystemActionsSection } from "./components/SystemActionsSection";
import { TlsPolicySection } from "./components/TlsPolicySection";
import { ValkeySection } from "./components/ValkeySection";

// Settings categories. `key` matches the `?cat=` URL param; `sections` lists
// the section <h2> labels that belong to the category. The render below uses
// `inCategory(label)` to decide whether to show a card. State lives in the
// per-section hooks (all mounted at once — e.g. DNS feeds into the rest of
// system config) but the category tabs make the long scroll navigable.
const CATEGORIES: { key: string; label: string; sections: string[] }[] = [
  { key: "system",  label: "System",          sections: ["General", "Login Banner & MOTD", "SSH Access", "Console", "System Actions", "pf State Table"] },
  { key: "api",     label: "API & Auth",      sections: ["API Server", "TLS Policy", "Authentication"] },
  { key: "dns",     label: "DNS",             sections: ["DNS Configuration"] },
  { key: "storage", label: "Storage & Metrics", sections: ["Metrics Storage", "Dashboard History", "Metrics Persistence (Valkey)", "IDS Alert Storage"] },
  { key: "backup",  label: "Backup & History", sections: ["Config History", "S3 Backup Sync", "Email Notifications (SMTP)"] },
  { key: "logging", label: "Logging",         sections: ["Remote Logging (Syslog)"] },
  { key: "ai",      label: "AI / LLM",        sections: ["AI / LLM Providers"] },
];

export default function SettingsPage() {
  const dns = useDnsSettings();
  const metrics = useMetricsSettings();
  const history = useDashboardHistory();
  const cfgRet = useConfigRetention();
  const s3 = useS3Backup();
  const smtp = useSmtpSettings();
  const syslog = useSyslogSettings();
  const apiServer = useApiServerSettings();
  const tls = useTlsPolicy();
  const auth = useAuthSettings();
  const valkey = useValkeySettings();
  const ids = useIdsAlertSettings();
  const ai = useAiProviders();
  const general = useSystemGeneral();
  const banner = useSystemBanner();
  const ssh = useSystemSsh();
  const consoleCfg = useSystemConsole();
  const pf = usePfTuning();
  const sysActions = useSystemActions();

  // Read ?cat= from the URL. "all" or unset => show every section.
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const activeCat = searchParams?.get("cat") || "all";
  const inCategory = useCallback((label: string): boolean => {
    if (activeCat === "all") return true;
    const cat = CATEGORIES.find((c) => c.key === activeCat);
    return !!cat && cat.sections.includes(label);
  }, [activeCat]);
  const setCat = useCallback((next: string) => {
    const params = new URLSearchParams(searchParams?.toString() || "");
    if (next === "all") params.delete("cat");
    else params.set("cat", next);
    const q = params.toString();
    router.replace(q ? `${pathname}?${q}` : pathname);
  }, [router, pathname, searchParams]);
  const activeLabel = useMemo(
    () => CATEGORIES.find((c) => c.key === activeCat)?.label || "All Settings",
    [activeCat],
  );

  return (
    <div className="space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold">Settings <span className="text-[var(--text-muted)] font-normal text-base">/ {activeLabel}</span></h1>
        <p className="text-sm text-[var(--text-muted)]">System configuration and preferences</p>
      </div>

      {/* Category tabs — quick in-page nav so the page is browseable even
          if the user lands here without clicking a sidebar child link. */}
      <nav className="flex flex-wrap gap-2 border-b border-[var(--border)] pb-3" aria-label="Settings categories">
        <button
          onClick={() => setCat("all")}
          className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
            activeCat === "all"
              ? "bg-[var(--accent)] text-white"
              : "bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] text-[var(--text-muted)]"
          }`}
        >
          All
        </button>
        {CATEGORIES.map((c) => (
          <button
            key={c.key}
            onClick={() => setCat(c.key)}
            className={`px-3 py-1.5 text-xs rounded-md transition-colors ${
              activeCat === c.key
                ? "bg-[var(--accent)] text-white"
                : "bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] text-[var(--text-muted)]"
            }`}
          >
            {c.label}
          </button>
        ))}
      </nav>

      <DnsSection visible={inCategory("DNS Configuration")} {...dns} />
      <MetricsSection visible={inCategory("Metrics Storage")} {...metrics} />
      <DashboardHistorySection visible={inCategory("Dashboard History")} {...history} />
      <ConfigHistorySection visible={inCategory("Config History")} {...cfgRet} />
      <S3BackupSection visible={inCategory("S3 Backup Sync")} {...s3} />
      <SmtpSection visible={inCategory("Email Notifications (SMTP)")} {...smtp} />
      <SyslogSection visible={inCategory("Remote Logging (Syslog)")} {...syslog} />
      <ApiServerSection visible={inCategory("API Server")} {...apiServer} />
      <TlsPolicySection visible={inCategory("TLS Policy")} {...tls} />
      <AuthSection visible={inCategory("Authentication")} {...auth} />
      <ValkeySection visible={inCategory("Metrics Persistence (Valkey)")} {...valkey} />
      <IdsAlertSection visible={inCategory("IDS Alert Storage")} {...ids} />
      <AiProvidersSection visible={inCategory("AI / LLM Providers")} {...ai} />
      <GeneralSection visible={inCategory("General")} {...general} />
      <BannerSection visible={inCategory("Login Banner & MOTD")} {...banner} />
      <SshSection visible={inCategory("SSH Access")} {...ssh} />
      <ConsoleSection visible={inCategory("Console")} {...consoleCfg} />
      <PfStateTableSection visible={inCategory("pf State Table")} {...pf} />
      <SystemActionsSection visible={inCategory("System Actions")} {...sysActions} />
    </div>
  );
}
