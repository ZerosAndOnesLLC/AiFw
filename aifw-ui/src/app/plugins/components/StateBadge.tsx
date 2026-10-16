import { PluginState } from "@/lib/api/plugins";

const STYLES: Record<PluginState, { cls: string; label: string }> = {
  running: { cls: "bg-green-500/15 text-green-400 border-green-500/30", label: "Running" },
  stopped: { cls: "bg-gray-500/15 text-[var(--text-muted)] border-[var(--border)]", label: "Disabled" },
  error: { cls: "bg-red-500/15 text-red-400 border-red-500/30", label: "Error" },
};

export function StateBadge({ state }: { state: PluginState }) {
  const s = STYLES[state];
  return (
    <span
      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full border text-xs font-medium ${s.cls}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${
          state === "running" ? "bg-green-400 animate-pulse" : state === "error" ? "bg-red-400" : "bg-gray-500"
        }`}
      />
      {s.label}
    </span>
  );
}
