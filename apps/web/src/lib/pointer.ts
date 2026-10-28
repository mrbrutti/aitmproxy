// "Keyboard-initiated actions never animate" (§2.8). Surfaces that open from either a shortcut or
// a toolbar click ask `openedByPointer()` at mount: true when a pointer went down within the last
// few hundred milliseconds, which is how a click-opened surface differs from a ⌘K / `n` one.

let lastPointerDown = -Infinity;
let installed = false;

function install() {
  if (installed || typeof document === 'undefined') return;
  installed = true;
  document.addEventListener('pointerdown', () => (lastPointerDown = performance.now()), { capture: true, passive: true });
}

export function openedByPointer(withinMs = 400): boolean {
  install();
  return performance.now() - lastPointerDown < withinMs;
}

install();
