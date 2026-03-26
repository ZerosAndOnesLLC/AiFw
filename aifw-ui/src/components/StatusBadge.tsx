interface StatusBadgeProps {
  status: string;
  size?: "sm" | "md";
}

const statusColors: Record<string, string> = {
  active: "bg-green-500/20 text-green-400 border-green-500/30",
  up: "bg-green-500/20 text-green-400 border-green-500/30",
  running: "bg-green-500/20 text-green-400 border-green-500/30",
  healthy: "bg-green-500/20 text-green-400 border-green-500/30",
  master: "bg-green-500/20 text-green-400 border-green-500/30",
  pass: "bg-green-500/20 text-green-400 border-green-500/30",
  allow: "bg-green-500/20 text-green-400 border-green-500/30",
  disabled: "bg-gray-500/20 text-gray-400 border-gray-500/30",
  down: "bg-red-500/20 text-red-400 border-red-500/30",
  error: "bg-red-500/20 text-red-400 border-red-500/30",
  block: "bg-red-500/20 text-red-400 border-red-500/30",
  unreachable: "bg-red-500/20 text-red-400 border-red-500/30",
  degraded: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  backup: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  init: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  unknown: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

export default function StatusBadge({ status, size = "sm" }: StatusBadgeProps) {
  const color = statusColors[status.toLowerCase()] || statusColors.unknown;
  const sizeClass = size === "sm" ? "text-[10px] px-1.5 py-0.5" : "text-xs px-2 py-1";

  return (
    <span className={`inline-flex items-center rounded border font-medium uppercase tracking-wider ${color} ${sizeClass}`}>
      {status}
    </span>
  );
}
