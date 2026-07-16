import { useEffect } from "react";

/// How long after the last poll a window-focus event may trigger an early
/// refresh. Prevents rapid focus/blur cycles from spamming the API.
const FOCUS_THROTTLE_MS = 5_000;

/// Runs `fn` immediately, then every `intervalMs` — but only while the page
/// is visible (PERF-H22 #366). Background tabs stop polling entirely; when
/// the tab becomes visible (or the window regains focus) the data is
/// refreshed right away and the interval restarts.
///
/// Overlapping runs are deduplicated: if the previous `fn` call is still in
/// flight when the next tick fires, that tick is skipped.
///
/// `fn` must be referentially stable (wrap it in `useCallback`); a new
/// identity restarts polling with an immediate refresh, mirroring the old
/// per-page `useEffect` + `setInterval` behavior. Pass `enabled: false` to
/// suspend polling (no initial call either), e.g. while a modal owns the
/// screen or the poll target doesn't exist yet.
export function usePolling(
  fn: () => void | Promise<void>,
  intervalMs: number,
  enabled: boolean = true,
): void {
  useEffect(() => {
    if (!enabled) return;

    let timer: ReturnType<typeof setInterval> | null = null;
    let inFlight = false;
    let lastTick = 0;

    const tick = () => {
      if (inFlight) return;
      inFlight = true;
      lastTick = Date.now();
      Promise.resolve()
        .then(fn)
        .catch(() => {
          /* poll errors are handled (or ignored) inside `fn` */
        })
        .finally(() => {
          inFlight = false;
        });
    };

    const start = () => {
      if (timer === null) timer = setInterval(tick, intervalMs);
    };
    const stop = () => {
      if (timer !== null) {
        clearInterval(timer);
        timer = null;
      }
    };

    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        tick();
        start();
      } else {
        stop();
      }
    };

    const onFocus = () => {
      if (document.visibilityState !== "visible") return;
      if (Date.now() - lastTick >= FOCUS_THROTTLE_MS) tick();
    };

    tick();
    if (document.visibilityState === "visible") start();
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("focus", onFocus);

    return () => {
      stop();
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("focus", onFocus);
    };
  }, [fn, intervalMs, enabled]);
}
