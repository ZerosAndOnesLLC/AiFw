"use client";

import { useState, useRef, useEffect } from "react";

/**
 * Small contextual help button. Drops in next to section titles or field labels.
 * Click the "?" to toggle a popover. Click outside or press Esc to close.
 *
 * Example:
 *   <Help title="Hysteresis">
 *     Number of consecutive passes/fails required before a state change.
 *     Higher = more stable, slower to react.
 *   </Help>
 */
export default function Help({
  title,
  size = "sm",
  children,
}: {
  title?: string;
  size?: "xs" | "sm" | "md";
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClick(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onClick);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onClick);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const sizeCls = {
    xs: "w-4 h-4 text-[10px]",
    sm: "w-5 h-5 text-xs",
    md: "w-6 h-6 text-sm",
  }[size];

  return (
    <div className="relative inline-block" ref={ref}>
      <button
        type="button"
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen((o) => !o);
        }}
        aria-label={title ? `Help: ${title}` : "Help"}
        className={`${sizeCls} inline-flex items-center justify-center rounded-full border border-blue-500/40 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 hover:text-blue-300 transition-colors font-bold`}
      >
        ?
      </button>
      {open && (
        <div
          role="dialog"
          className="absolute z-50 mt-2 left-0 w-80 max-w-[90vw] p-3 rounded-lg border border-blue-500/40 bg-[var(--bg-card)] shadow-xl text-xs leading-relaxed text-[var(--text-primary)]"
        >
          {title && (
            <div className="font-semibold text-white mb-1 flex items-center justify-between">
              <span>{title}</span>
              <button
                onClick={() => setOpen(false)}
                className="text-[var(--text-muted)] hover:text-white"
                aria-label="Close help"
              >
                ✕
              </button>
            </div>
          )}
          <div className="space-y-2 text-[var(--text-muted)]">{children}</div>
        </div>
      )}
    </div>
  );
}

/** Page-level help card — larger, always open, sits at the top of a page. */
export function HelpBanner({
  title,
  children,
  storageKey,
}: {
  title: string;
  children: React.ReactNode;
  storageKey?: string;
}) {
  const [dismissed, setDismissed] = useState(() => {
    if (typeof window === "undefined" || !storageKey) return false;
    return localStorage.getItem(`help:${storageKey}`) === "dismissed";
  });

  if (dismissed) return null;

  return (
    <div className="bg-blue-500/5 border border-blue-500/30 rounded-lg p-4 text-sm text-[var(--text-primary)] space-y-2">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 text-blue-400 font-semibold">
          <span className="inline-flex w-5 h-5 items-center justify-center rounded-full border border-blue-500/50 bg-blue-500/20 text-xs">
            ?
          </span>
          {title}
        </div>
        {storageKey && (
          <button
            onClick={() => {
              localStorage.setItem(`help:${storageKey}`, "dismissed");
              setDismissed(true);
            }}
            className="text-xs text-[var(--text-muted)] hover:text-white"
          >
            Hide
          </button>
        )}
      </div>
      <div className="text-[var(--text-muted)] leading-relaxed space-y-2">
        {children}
      </div>
    </div>
  );
}
