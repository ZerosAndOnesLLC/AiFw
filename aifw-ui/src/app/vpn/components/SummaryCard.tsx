"use client";

/* ────────────────────────── Summary card ────────────────────────── */

export function SummaryCard({
  label,
  value,
  color,
  subtitle,
}: {
  label: string;
  value: number;
  color: "cyan" | "blue" | "green";
  subtitle?: string;
}) {
  const borderColors: Record<string, string> = {
    cyan: "border-cyan-500/30",
    blue: "border-blue-500/30",
    green: "border-green-500/30",
  };
  const textColors: Record<string, string> = {
    cyan: "text-cyan-400",
    blue: "text-blue-400",
    green: "text-green-400",
  };

  return (
    <div className={`bg-gray-800 border ${borderColors[color]} rounded-lg p-4`}>
      <p className="text-xs text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${textColors[color]}`}>{value}</p>
      {subtitle && <p className="text-[10px] text-gray-500 mt-0.5">{subtitle}</p>}
    </div>
  );
}
