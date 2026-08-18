"use client";

import { useEffect, type ReactNode } from "react";

/**
 * Accessible modal chrome (QUAL-M16 #451). Renders the dimmed backdrop and
 * the dialog panel:
 * - Escape closes (keyboard users had no way to dismiss click-only overlays);
 * - clicking the backdrop itself closes, clicks inside the panel don't
 *   (no `stopPropagation` handlers on non-interactive elements);
 * - the panel is announced as a modal dialog.
 *
 * `className` styles the backdrop (position/z-index/color), `panelClassName`
 * the dialog box. Put a visible close button in the panel as well.
 */
export function ModalOverlay({
  onClose,
  children,
  className = "fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4",
  panelClassName = "",
  ariaLabel,
}: {
  onClose: () => void;
  children: ReactNode;
  className?: string;
  panelClassName?: string;
  /** Accessible name for the dialog when the title isn't linked by id. */
  ariaLabel?: string;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div
      role="presentation"
      className={className}
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div role="dialog" aria-modal="true" aria-label={ariaLabel} className={panelClassName}>
        {children}
      </div>
    </div>
  );
}
