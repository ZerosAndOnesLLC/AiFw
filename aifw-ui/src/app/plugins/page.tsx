"use client";

import { useState } from "react";
import { LoaderCircle, Puzzle } from "lucide-react";
import Card from "@/components/Card";
import { useAuth } from "@/context/AuthContext";
import { usePlugins } from "@/hooks/usePlugins";
import { HOOK_LABELS } from "@/lib/api/plugins";
import { FeedbackBanner } from "@/app/settings/components/FeedbackBanner";
import { PluginCard } from "./components/PluginCard";
import { PluginDrawer, Tab } from "./components/PluginDrawer";

interface Open {
  name: string;
  tab: Tab;
  notice?: string;
}

export default function PluginsPage() {
  const { permissions } = useAuth();
  const canWrite = permissions.has("plugins:write");
  const { plugins, hooks, loading, loadError, busy, feedback, refresh, upsert, setEnabled } =
    usePlugins();
  const [open, setOpen] = useState<Open | null>(null);

  const running = plugins.filter((p) => p.state === "running").length;
  const errored = plugins.filter((p) => p.state === "error").length;
  const openPlugin = open ? plugins.find((p) => p.name === open.name) : undefined;

  const toggle = async (name: string, enabled: boolean) => {
    const p = plugins.find((x) => x.name === name);
    if (!p) return null;
    const err = await setEnabled(p, enabled);
    // A plugin that can't start yet needs configuring — take the operator there.
    if (err && enabled && !open) setOpen({ name, tab: "settings", notice: err });
    return err;
  };

  return (
    <div className="p-6 space-y-6 max-w-6xl mx-auto">
      <div>
        <h1 className="text-2xl font-bold text-white">Plugins</h1>
        <p className="text-sm text-[var(--text-muted)] mt-1 max-w-3xl">
          Optional features compiled into AiFw. On the firewall side a plugin can only fill its
          own pf tables and add <code>block</code>/<code>match</code> rules against them — never
          open, redirect or reroute traffic — and turning it off removes everything it added.
        </p>
      </div>

      <FeedbackBanner feedback={open ? null : feedback} />

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Card title="Available" value={plugins.length} subtitle="built-in plugins" color="blue" />
        <Card title="Running" value={running} subtitle="enabled and healthy" color="green" />
        <Card
          title="Need attention"
          value={errored}
          subtitle={errored ? "enabled but failed to start" : "no problems"}
          color={errored ? "red" : "cyan"}
        />
      </div>

      {loadError && (
        <div className="p-3 rounded-md border border-red-500/30 bg-red-500/10 text-sm text-red-300">
          Could not load plugins: {loadError}{" "}
          <button type="button" onClick={refresh} className="underline">
            Retry
          </button>
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center gap-2 py-16 text-sm text-[var(--text-muted)]">
          <LoaderCircle className="h-4 w-4 animate-spin" aria-hidden /> Loading plugins…
        </div>
      ) : plugins.length === 0 && !loadError ? (
        <div className="py-16 text-center text-[var(--text-muted)]">
          <Puzzle className="h-8 w-8 mx-auto mb-2 opacity-50" aria-hidden />
          No plugins are available in this build.
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {plugins.map((p) => (
            <PluginCard
              key={p.name}
              plugin={p}
              canWrite={canWrite}
              busy={busy.has(p.name)}
              onToggle={(enabled) => toggle(p.name, enabled)}
              onOpen={() => setOpen({ name: p.name, tab: p.state === "stopped" ? "settings" : "overview" })}
            />
          ))}
        </div>
      )}

      {hooks.length > 0 && (
        <details className="group bg-[var(--bg-card)] border border-[var(--border)] rounded-lg">
          <summary className="cursor-pointer px-4 py-3 text-sm font-medium text-[var(--text-secondary)] hover:text-white">
            For developers: events plugins can subscribe to
          </summary>
          <div className="px-4 pb-4 space-y-3">
            <ul className="grid gap-2 sm:grid-cols-2">
              {hooks.map((h) => (
                <li key={h.id} className="text-sm">
                  <span className="font-medium text-[var(--text-primary)]">{HOOK_LABELS[h.id] ?? h.id}</span>{" "}
                  <code className="text-xs text-[var(--text-muted)]">{h.id}</code>
                  <div className="text-xs text-[var(--text-muted)]">{h.description}</div>
                </li>
              ))}
            </ul>
            <p className="text-xs text-[var(--text-muted)]">
              Plugins are Rust crates compiled into AiFw. See <code>docs/plugins.md</code> for a
              walkthrough that builds the Threat Intel Feeds plugin step by step.
            </p>
          </div>
        </details>
      )}

      {open && openPlugin && (
        <PluginDrawer
          key={open.name}
          summary={openPlugin}
          canWrite={canWrite}
          busy={busy.has(open.name)}
          initialTab={open.tab}
          notice={open.notice}
          onToggle={(enabled) => toggle(open.name, enabled)}
          onSummary={upsert}
          onClose={() => setOpen(null)}
        />
      )}
    </div>
  );
}
