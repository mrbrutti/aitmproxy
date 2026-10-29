// Positioning for menus and popovers: anchored to a trigger rect (or a pointer point), flipped
// to stay inside the viewport, with the transform-origin set to the side it grows from (§2.8:
// "popovers 160ms from scale 0.97 at the trigger").

export interface AnchorRect {
  left: number;
  top: number;
  right: number;
  bottom: number;
}

export type Placement = 'bottom-start' | 'bottom-end' | 'top-start' | 'right-start';

export interface Placed {
  left: number;
  top: number;
  origin: string;
}

export const pointAnchor = (x: number, y: number): AnchorRect => ({ left: x, top: y, right: x, bottom: y });

export const rectAnchor = (r: DOMRect): AnchorRect => ({ left: r.left, top: r.top, right: r.right, bottom: r.bottom });

/**
 * Pure placement: given the anchor, the floating element's size, and the viewport, return the
 * fixed-position coordinates and a transform-origin. `gap` is the distance from the anchor.
 */
export function place(
  anchor: AnchorRect,
  size: { width: number; height: number },
  viewport: { width: number; height: number },
  placement: Placement = 'bottom-start',
  gap = 4,
  margin = 8,
): Placed {
  let left: number;
  let top: number;
  let ox = 'left';
  let oy = 'top';

  if (placement === 'right-start') {
    left = anchor.right + 2;
    top = anchor.top - 4;
    if (left + size.width > viewport.width - margin) {
      left = anchor.left - size.width - 2;
      ox = 'right';
    }
  } else {
    const below = placement !== 'top-start';
    top = below ? anchor.bottom + gap : anchor.top - gap - size.height;
    if (below && top + size.height > viewport.height - margin && anchor.top - gap - size.height >= margin) {
      top = anchor.top - gap - size.height;
      oy = 'bottom';
    } else if (!below && top < margin) {
      top = anchor.bottom + gap;
    } else if (!below) {
      oy = 'bottom';
    }
    if (placement === 'bottom-end') {
      left = anchor.right - size.width;
      ox = 'right';
    } else {
      left = anchor.left;
    }
  }

  // Final clamp inside the viewport.
  if (left + size.width > viewport.width - margin) left = Math.max(margin, viewport.width - margin - size.width);
  if (left < margin) left = margin;
  if (top + size.height > viewport.height - margin) top = Math.max(margin, viewport.height - margin - size.height);
  if (top < margin) top = margin;

  return { left: Math.round(left), top: Math.round(top), origin: `${oy} ${ox}` };
}
