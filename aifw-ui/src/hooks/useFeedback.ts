"use client";

import { useCallback, useEffect, useRef, useState } from "react";

export type FeedbackType = "success" | "error";

export interface Feedback {
  type: FeedbackType;
  msg: string;
}

/// Shared success/error banner state used by the resource pages (#428).
/// `showFeedback` replaces any visible banner and auto-dismisses after
/// `durationMs` (default 6s — pass a different value to match pages that
/// historically used 4s/5s/8s).
export function useFeedback(durationMs = 6000) {
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const showFeedback = useCallback(
    (type: FeedbackType, msg: string) => {
      setFeedback({ type, msg });
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setFeedback(null), durationMs);
    },
    [durationMs],
  );

  const clearFeedback = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    setFeedback(null);
  }, []);

  // Drop any pending dismiss timer on unmount.
  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  return { feedback, showFeedback, clearFeedback };
}
