// "Edit & repeat" hands the sheet a flow id through a window CustomEvent (`aitm:compose-prefill`,
// detail `{ flowId }` or `{ id }`). The event may fire before the sheet mounts, so the last id is
// held here at module level and consumed by the sheet on open.
import { createSignal } from 'solid-js';

const EVENT = 'aitm:compose-prefill';

const [pending, setPending] = createSignal<string | null>(null);

export const pendingPrefill = pending;

export function consumePrefill(): string | null {
  const id = pending();
  setPending(null);
  return id;
}

/** Exported for tests; the module installs it once on import. */
export function onPrefillEvent(e: Event) {
  const detail = (e as CustomEvent<{ flowId?: unknown; id?: unknown }>).detail;
  const id = detail?.flowId ?? detail?.id;
  if (typeof id === 'string' && id) setPending(id);
}

if (typeof window !== 'undefined') window.addEventListener(EVENT, onPrefillEvent);
