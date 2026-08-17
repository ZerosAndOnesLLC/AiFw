"use client";

import Link from "next/link";

/**
 * Shared "something broke here" panel (#452). Used by the Next.js
 * `error.tsx` boundaries and by the widget-level <ErrorBoundary>. Keeps
 * the rest of the shell usable: the operator can retry the failed
 * section, go back to the dashboard, or reload.
 */
export interface ErrorFallbackProps {
  /** The caught error (message shown; stack only in dev). */
  error: Error & { digest?: string };
  /** Re-mount the failed subtree. */
  reset?: () => void;
  /** Where the error happened, e.g. "Rules page" — shown in the heading. */
  scope?: string;
  /** Compact variant for small widgets. */
  compact?: boolean;
}

export function ErrorFallback({ error, reset, scope, compact = false }: ErrorFallbackProps) {
  const message = error?.message || "Unknown error";
  const isDev = process.env.NODE_ENV !== "production";
  return (
    <div
      role="alert"
      className={`bg-[var(--bg-card)] border border-red-500/40 rounded-lg ${
        compact ? "p-3" : "p-6"
      }`}
    >
      <div className="flex items-start gap-3">
        <span className="mt-0.5 text-red-400" aria-hidden="true">
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
            />
          </svg>
        </span>
        <div className="min-w-0 flex-1">
          <h2 className={`font-semibold text-[var(--text-primary)] ${compact ? "text-sm" : "text-base"}`}>
            {scope ? `${scope} failed to render` : "Something went wrong"}
          </h2>
          <p className="mt-1 text-xs text-[var(--text-muted)] break-words">
            {message}
            {error?.digest && <span className="ml-1 opacity-70">(ref {error.digest})</span>}
          </p>
          {isDev && error?.stack && (
            <pre className="mt-2 max-h-40 overflow-auto text-[10px] leading-snug text-[var(--text-muted)] bg-[var(--bg-primary)] border border-[var(--border)] rounded p-2">
              {error.stack}
            </pre>
          )}
          <div className={`flex flex-wrap items-center gap-2 ${compact ? "mt-2" : "mt-4"}`}>
            {reset && (
              <button
                onClick={reset}
                className="px-3 py-1.5 bg-[var(--accent)] hover:bg-[var(--accent-hover)] text-white rounded-md text-xs font-medium transition-colors"
              >
                Try again
              </button>
            )}
            {!compact && (
              <>
                <Link
                  href="/"
                  className="px-3 py-1.5 bg-[var(--bg-card-secondary)] hover:bg-[var(--bg-hover)] border border-[var(--border)] text-[var(--text-primary)] rounded-md text-xs font-medium transition-colors"
                >
                  Go to dashboard
                </Link>
                <button
                  onClick={() => window.location.reload()}
                  className="px-3 py-1.5 text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] transition-colors"
                >
                  Reload page
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
