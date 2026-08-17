/**
 * Route-level loading state (#452): shown by `app/loading.tsx` while a
 * page's chunk is fetched during client-side navigation. Skeleton rather
 * than a bare spinner so the layout doesn't jump when content lands.
 */
export function PageLoading({ label = "Loading…" }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" aria-label={label} className="animate-pulse space-y-4">
      <div className="h-7 w-48 rounded bg-[var(--bg-card)]" />
      <div className="h-4 w-80 max-w-full rounded bg-[var(--bg-card)]" />
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
        <div className="h-24 rounded-lg bg-[var(--bg-card)]" />
        <div className="h-24 rounded-lg bg-[var(--bg-card)]" />
        <div className="h-24 rounded-lg bg-[var(--bg-card)]" />
      </div>
      <div className="h-64 rounded-lg bg-[var(--bg-card)]" />
      <span className="sr-only">{label}</span>
    </div>
  );
}
