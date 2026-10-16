import { BellRing, Puzzle, ShieldBan } from "lucide-react";

const ICONS: Record<string, { Icon: typeof Puzzle; cls: string }> = {
  "threat-feeds": { Icon: ShieldBan, cls: "bg-red-500/10 text-red-400 border-red-500/20" },
  notifier: { Icon: BellRing, cls: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
};

export function PluginIcon({ name, size = "md" }: { name: string; size?: "md" | "lg" }) {
  const { Icon, cls } = ICONS[name] ?? {
    Icon: Puzzle,
    cls: "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  };
  const box = size === "lg" ? "h-11 w-11" : "h-9 w-9";
  return (
    <div className={`${box} ${cls} flex-shrink-0 rounded-lg border flex items-center justify-center`}>
      <Icon className={size === "lg" ? "h-6 w-6" : "h-5 w-5"} aria-hidden />
    </div>
  );
}
