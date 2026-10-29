import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createRoot, createSignal } from 'solid-js';
import { createPoller } from './poller';

/** A document stand-in with a controllable visibilityState. */
function fakeDoc() {
  let state: DocumentVisibilityState = 'visible';
  const listeners = new Set<() => void>();
  const doc = {
    get visibilityState() {
      return state;
    },
    addEventListener: (_: string, fn: () => void) => listeners.add(fn),
    removeEventListener: (_: string, fn: () => void) => listeners.delete(fn),
  } as unknown as Document;
  return {
    doc,
    set(s: DocumentVisibilityState) {
      state = s;
      for (const l of listeners) l();
    },
    listeners,
  };
}

describe('createPoller', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('ticks immediately, then every interval while enabled; stops when disabled', async () => {
    const d = fakeDoc();
    const [enabled, setEnabled] = createSignal(true);
    const tick = vi.fn(async () => {});
    const { polling, dispose } = createRoot((dispose) => ({ ...createPoller({ intervalMs: 800, enabled, tick, doc: d.doc }), dispose }));
    expect(polling()).toBe(true);
    expect(tick).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(800);
    expect(tick).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1600);
    expect(tick).toHaveBeenCalledTimes(4);
    setEnabled(false);
    expect(polling()).toBe(false);
    await vi.advanceTimersByTimeAsync(5000);
    expect(tick).toHaveBeenCalledTimes(4);
    setEnabled(true);
    expect(tick).toHaveBeenCalledTimes(5); // resumes with an immediate fetch
    dispose();
    await vi.advanceTimersByTimeAsync(5000);
    expect(tick).toHaveBeenCalledTimes(5);
    expect(d.listeners.size).toBe(0);
  });

  it('pauses while the document is hidden and resumes on visibilitychange', async () => {
    const d = fakeDoc();
    const tick = vi.fn(async () => {});
    const { polling, dispose } = createRoot((dispose) => ({ ...createPoller({ intervalMs: 800, enabled: () => true, tick, doc: d.doc }), dispose }));
    expect(tick).toHaveBeenCalledTimes(1);
    d.set('hidden');
    expect(polling()).toBe(false);
    await vi.advanceTimersByTimeAsync(4000);
    expect(tick).toHaveBeenCalledTimes(1);
    d.set('visible');
    expect(polling()).toBe(true);
    expect(tick).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(800);
    expect(tick).toHaveBeenCalledTimes(3);
    dispose();
  });

  it('measures the interval from the end of a slow tick and never overlaps', async () => {
    const d = fakeDoc();
    let inFlight = 0;
    let maxInFlight = 0;
    const tick = vi.fn(async () => {
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 1000));
      inFlight--;
    });
    const dispose = createRoot((dispose) => {
      createPoller({ intervalMs: 800, enabled: () => true, tick, doc: d.doc });
      return dispose;
    });
    await vi.advanceTimersByTimeAsync(1700); // first tick ends at 1000, next starts at 1800
    expect(tick).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(200);
    expect(tick).toHaveBeenCalledTimes(2);
    expect(maxInFlight).toBe(1);
    dispose();
  });
});
