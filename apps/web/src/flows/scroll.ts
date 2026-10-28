// Stick-to-bottom math for the flow list, kept pure so it can be tested without a browser.

/** True when the viewport's bottom edge is within `tolerance` px of the end of the content. */
export function isAtBottom(scrollTop: number, viewportHeight: number, totalSize: number, tolerance: number): boolean {
  if (totalSize <= viewportHeight) return true;
  return scrollTop + viewportHeight >= totalSize - tolerance;
}

/** The index range the virtualizer should render for a viewport (mirrors @tanstack/virtual-core for fixed rows). */
export function windowRange(scrollTop: number, viewportHeight: number, rowHeight: number, count: number, overscan: number): { start: number; end: number } {
  if (count === 0 || rowHeight <= 0) return { start: 0, end: -1 };
  const first = Math.floor(scrollTop / rowHeight);
  const last = Math.ceil((scrollTop + viewportHeight) / rowHeight) - 1;
  return { start: Math.max(0, first - overscan), end: Math.min(count - 1, last + overscan) };
}

/** Rows that arrived since the operator scrolled away from the bottom. */
export const newSince = (count: number, countWhenLeft: number): number => Math.max(0, count - countWhenLeft);
