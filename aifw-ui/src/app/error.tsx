"use client";

import { ErrorFallback } from "@/components/feedback/ErrorFallback";

/**
 * Route-segment error boundary (#452). Catches render/runtime errors in
 * any page under `app/` while keeping the shell (sidebar, banners) alive.
 * Next.js resets it automatically on navigation; "Try again" re-mounts
 * the failed page in place.
 */
export default function PageError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="max-w-3xl">
      <ErrorFallback error={error} reset={reset} scope="This page" />
    </div>
  );
}
