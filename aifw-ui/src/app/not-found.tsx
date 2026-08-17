import Link from "next/link";

/**
 * 404 page (#452). Rendered as `out/404.html`; aifw-api serves it (with a
 * 404 status) for any UI path that isn't a known route or static file.
 */
export default function NotFound() {
  return (
    <div className="max-w-xl">
      <div className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg p-6">
        <p className="text-xs uppercase tracking-wider text-[var(--text-muted)]">404</p>
        <h1 className="mt-1 text-lg font-semibold text-[var(--text-primary)]">Page not found</h1>
        <p className="mt-2 text-sm text-[var(--text-muted)]">
          There is no page at this address. It may have moved in a newer release, or the link
          is out of date.
        </p>
        <div className="mt-4 flex items-center gap-3">
          <Link
            href="/"
            className="px-3 py-1.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-xs font-medium transition-colors"
          >
            Go to dashboard
          </Link>
          <Link
            href="/settings/"
            className="text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
          >
            Settings
          </Link>
        </div>
      </div>
    </div>
  );
}
