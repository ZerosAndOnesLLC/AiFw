export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <h3 className="text-xs uppercase tracking-wider text-[var(--text-muted)] font-semibold">
        {title}
      </h3>
      <div className="space-y-2">{children}</div>
    </div>
  );
}
