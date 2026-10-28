// Periodic fetch gated on a reactive `enabled` flag and on document visibility: the live
// screenshot stream pauses when the tab is hidden or the Browser panel is not showing, and
// fetches immediately when it resumes. One tick in flight at a time; the interval is measured
// from the end of the previous tick, so a slow bus never piles requests up.
import { createEffect, createMemo, createSignal, onCleanup, type Accessor } from 'solid-js';

export interface PollerOptions {
  intervalMs: number;
  enabled: Accessor<boolean>;
  tick: () => Promise<void>;
  /** Injectable for tests. */
  doc?: Document | undefined;
}

export function createPoller(o: PollerOptions): { polling: Accessor<boolean> } {
  const doc = o.doc ?? (typeof document !== 'undefined' ? document : null);
  const [visible, setVisible] = createSignal(doc ? doc.visibilityState !== 'hidden' : true);
  if (doc) {
    const onVisibility = () => setVisible(doc.visibilityState !== 'hidden');
    doc.addEventListener('visibilitychange', onVisibility);
    onCleanup(() => doc.removeEventListener('visibilitychange', onVisibility));
  }

  const polling = createMemo(() => o.enabled() && visible());

  createEffect(() => {
    if (!polling()) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const run = async () => {
      if (!alive) return;
      try {
        await o.tick();
      } catch {
        /* the tick reports its own errors */
      }
      if (alive) timer = setTimeout(() => void run(), o.intervalMs);
    };
    void run();
    onCleanup(() => {
      alive = false;
      if (timer) clearTimeout(timer);
    });
  });

  return { polling };
}
