export function Field({
  label,
  err,
  required,
  children,
}: {
  label: string;
  err?: string;
  required?: boolean;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label className="block text-xs text-[var(--text-muted)] mb-1">
        {label}
        {required && <span className="text-red-400 ml-1">*</span>}
      </label>
      {children}
      {err && <p className="text-xs text-red-400 mt-1">{err}</p>}
    </div>
  );
}
