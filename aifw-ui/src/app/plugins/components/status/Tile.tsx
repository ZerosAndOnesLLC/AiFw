export function Tile({
  label,
  value,
  sub,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  tone?: "default" | "good" | "bad" | "warn";
}) {
  const color = {
    default: "text-white",
    good: "text-green-400",
    bad: "text-red-400",
    warn: "text-amber-400",
  }[tone];
  return (
    <div className="p-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)]/40">
      <div className="text-[11px] uppercase tracking-wider text-[var(--text-muted)]">{label}</div>
      <div className={`mt-1 text-lg font-semibold ${color}`}>{value}</div>
      {sub && <div className="text-xs text-[var(--text-muted)] mt-0.5">{sub}</div>}
    </div>
  );
}
