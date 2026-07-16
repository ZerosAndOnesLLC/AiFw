import { useEffect, useState, type RefObject } from "react";

/// Distance in pixels from the top of the document to `ref`'s element,
/// for use as `scrollMargin` on a window virtualizer (PERF-H24 #368).
///
/// Re-measured whenever the document body resizes, so banners or panels
/// above the element toggling open/closed don't skew the virtualizer's
/// visible-range calculation.
export function useDocumentOffset(ref: RefObject<HTMLElement | null>): number {
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    const measure = () => {
      setOffset(
        ref.current
          ? ref.current.getBoundingClientRect().top + window.scrollY
          : 0,
      );
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(document.body);
    return () => observer.disconnect();
  }, [ref]);

  return offset;
}
