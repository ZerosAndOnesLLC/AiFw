export function Stat({
  label,
  value,
  color,
}: {
  label: string;
  value: string;
  color: "green" | "yellow" | "blue" | "red";
}) {
  const c = {
    green: "text-green-400",
    yellow: "text-yellow-400",
    blue: "text-blue-400",
    red: "text-red-400",
  }[color];
  return (
    <div className="bg-black/30 border border-[var(--border)] rounded p-3">
      <div className="text-xs text-[var(--text-muted)] uppercase">{label}</div>
      <div className={`text-2xl font-bold ${c}`}>{value}</div>
    </div>
  );
}
