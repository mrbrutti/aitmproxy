// Tester (unit (c), stage 5): the L4 store's behaviour on the bus (tasks C3, C5; spec §1, §2, §4,
// §7(c) "Polling"; AC20, AC23). `args.test.ts` pins the store's source; this suite drives
// `createL4Store` against a stub app whose `call` answers from literals written here and records
// every `l4.*` call, so what the store puts on the wire — and how often — is asserted directly.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createRoot } from 'solid-js';
import { BusError } from '~/bus/types';
import type { AppStore } from '~/state/app';
import { createL4Store, type L4Store } from './store';
import { L4_ACTIVE_MS, type L4FlowWire } from './model';

type Reply = unknown | ((args: Record<string, unknown>) => unknown);

interface Harness {
  store: L4Store;
  /** Every `l4.*` call in order: `[tool, args]`. */
  calls: [string, Record<string, unknown>][];
  count(tool: string): number;
  argsOf(tool: string): Record<string, unknown>[];
  notices: [string, string | undefined][];
  replies: Record<string, Reply>;
  setSelected(id: string | null): void;
  dispose(): void;
}

const L4_TOOLS = [
  'l4.flow.list',
  'l4.flow.get',
  'l4.capture.status',
  'l4.capture.start',
  'l4.capture.stop',
  'l4.intercept.status',
  'l4.intercept.list',
  'l4.intercept.forward',
  'l4.intercept.drop',
  'l4.intercept.mutate',
  'l4.intercept.revert',
  'l4.scope.list',
  'l4.scope.add',
  'l4.agent.status',
  'l4.craft',
  'l4.inject',
];

const UNAVAILABLE_CAPTURE = { available: false, code: 'needs_privilege', reason: 'no read+write access to any /dev/bpf* device', captures: [] };
const UNAVAILABLE_INTERCEPT = { available: false, code: 'unsupported_platform', reason: 'in-path interception is unsupported on macOS', sessions: [] };

const flowWire = (id: string, p: Partial<L4FlowWire> = {}): L4FlowWire => ({
  id,
  kind: 'capture',
  interface: 'lo0',
  filter: null,
  queue: null,
  packet_count: 0,
  injected_count: 0,
  packets: [],
  ...p,
});

/** A store over a stub app: `tools` is the catalogue (with the window on `l4.flow.get` unless `window: false`), `replies` answers each tool. */
function harness(opts: { tools?: string[]; window?: boolean; replies?: Record<string, Reply> } = {}): Harness {
  const calls: [string, Record<string, unknown>][] = [];
  const notices: [string, string | undefined][] = [];
  const replies: Record<string, Reply> = {
    'l4.flow.list': [],
    'l4.capture.status': UNAVAILABLE_CAPTURE,
    'l4.intercept.status': UNAVAILABLE_INTERCEPT,
    'l4.scope.list': [],
    'l4.agent.status': { capture: false, inject: false, intercept: false, widen: false },
    ...opts.replies,
  };
  const tools = (opts.tools ?? L4_TOOLS).map((name) => ({
    name,
    description: name,
    inputSchema: { type: 'object', properties: name === 'l4.flow.get' && opts.window !== false ? { id: {}, offset: {}, limit: {} } : { id: {} } },
  }));
  let selected: string | null = null;
  let l4Ids: string[] = [];
  const app = {
    proxy: { tools },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      calls.push([tool, args]);
      if (!(tool in replies)) throw new BusError(`${tool}: not served by the test app`);
      const r = replies[tool];
      const value = typeof r === 'function' ? (r as (a: Record<string, unknown>) => unknown)(args) : r;
      if (value instanceof Error) throw value;
      return value as T;
    },
    notice(text: string, kind?: string) {
      notices.push([text, kind]);
    },
    setL4Ids(ids: string[]) {
      l4Ids = ids;
    },
    selectedId: () => selected,
    l4Ids: () => new Set(l4Ids),
  };
  let store!: L4Store;
  const dispose = createRoot((d) => {
    store = createL4Store(app as unknown as AppStore);
    return d;
  });
  return {
    store,
    calls,
    count: (tool) => calls.filter(([t]) => t === tool).length,
    argsOf: (tool) => calls.filter(([t]) => t === tool).map(([, a]) => a),
    notices,
    replies,
    setSelected: (id) => (selected = id),
    dispose,
  };
}

/** Call `refresh()` the way the app's 1.5 s timer does, for `ms` of fake time, starting at the current fake clock. */
async function driveTimer(h: Harness, ms: number): Promise<void> {
  const start = Date.now();
  for (let t = 0; t < ms; t += L4_ACTIVE_MS) {
    vi.setSystemTime(start + t);
    await h.store.refresh();
  }
}

let h: Harness | null = null;
beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(1_761_900_000_000);
});
afterEach(() => {
  h?.dispose();
  h = null;
  vi.useRealTimers();
});

describe('L4 store: availability from the status replies (spec §1)', () => {
  it('starts pending, then maps the new status objects; the capture ids come from the same reply', async () => {
    h = harness({ replies: { 'l4.capture.status': { ...UNAVAILABLE_CAPTURE, available: true, code: 'available', reason: null, captures: ['C1', 'C2'] } } });
    expect(h.store.captureAvailability().reason).toBe('Reading L4 availability…');
    expect(h.store.interceptAvailability().reason).toBe('Reading L4 availability…');
    await h.store.refresh();
    expect(h.store.captureAvailability()).toEqual({ available: true, code: 'available', reason: null });
    expect(h.store.captureIds()).toEqual(['C1', 'C2']);
    expect(h.store.interceptAvailability()).toEqual({
      available: false,
      code: 'unsupported_platform',
      reason: 'in-path interception is unsupported on macOS',
    });
    expect(h.notices).toEqual([]);
  });

  it('an older core refusing the status verb with "L4 unavailable: " is an availability answer, not a logged read failure', async () => {
    h = harness({ replies: { 'l4.capture.status': new BusError('l4.capture.status: L4 unavailable: OLD-CORE-REASON') } });
    await h.store.refresh();
    expect(h.store.captureAvailability()).toEqual({ available: false, code: null, reason: 'OLD-CORE-REASON' });
    expect(h.notices).toEqual([]);
    expect(h.store.error()).toBeNull();
  });

  it('an older core answering a bare array means available', async () => {
    h = harness({ replies: { 'l4.capture.status': ['C9'] } });
    await h.store.refresh();
    expect(h.store.captureAvailability()).toEqual({ available: true, code: null, reason: null });
    expect(h.store.captureIds()).toEqual(['C9']);
  });

  it('availability is re-read on every tick, never cached: a flip on the core shows without a rebuild', async () => {
    h = harness();
    await h.store.refresh();
    expect(h.store.captureAvailability().available).toBe(false);
    h.replies['l4.capture.status'] = { available: true, code: 'available', reason: null, captures: [] };
    await h.store.refresh(true);
    expect(h.store.captureAvailability()).toEqual({ available: true, code: 'available', reason: null });
  });
});

describe('L4 store: idle-lane polling budget (AC23; spec §7(c))', () => {
  it('capture unavailable and no flows: 40 timer calls in 60 s make 20 l4.* calls (≤ 30) and never read l4.intercept.list', async () => {
    h = harness();
    await driveTimer(h, 60_000);
    const l4Calls = h.calls.filter(([t]) => t.startsWith('l4.'));
    expect(l4Calls.length).toBe(20);
    expect(l4Calls.length).toBeLessThanOrEqual(30);
    expect(h.count('l4.flow.list')).toBe(6);
    expect(h.count('l4.capture.status')).toBe(6);
    expect(h.count('l4.intercept.status')).toBe(6);
    expect(h.count('l4.scope.list')).toBe(1);
    expect(h.count('l4.agent.status')).toBe(1);
    expect(h.count('l4.intercept.list')).toBe(0);
    expect(h.count('l4.flow.get')).toBe(0);
    expect(h.notices).toEqual([]);
  });

  it('a second idle minute reads scope and agent status again (the slow group is 60 s, not once)', async () => {
    h = harness();
    await driveTimer(h, 120_000);
    expect(h.count('l4.scope.list')).toBe(2);
    expect(h.count('l4.agent.status')).toBe(2);
    expect(h.calls.filter(([t]) => t.startsWith('l4.')).length).toBe(40);
  });

  it('not idle (capture available): every timer call reads the fast and slow groups', async () => {
    h = harness({ replies: { 'l4.capture.status': { available: true, code: 'available', reason: null, captures: [] } } });
    await driveTimer(h, 60_000);
    expect(h.count('l4.flow.list')).toBe(40);
    expect(h.count('l4.scope.list')).toBe(40);
  });

  it('with no l4.flow.list in tools/list the store makes no call at all', async () => {
    h = harness({ tools: ['flow.list', 'l4.craft'] });
    await driveTimer(h, 60_000);
    expect(h.calls).toEqual([]);
    expect(h.store.present()).toBe(false);
  });
});

describe('L4 store: once-per-message failure log (spec §7(c))', () => {
  it('a read that fails on every tick is noticed once, and again only after a clean pass', async () => {
    h = harness({ replies: { 'l4.flow.list': new BusError('boom') } });
    // Force both groups each call so the failure repeats on every refresh.
    for (let i = 0; i < 5; i++) await h.store.refresh(true);
    expect(h.count('l4.flow.list')).toBe(5);
    expect(h.notices).toEqual([['l4.flow.list: boom', 'error']]);
    expect(h.store.error()).toBe('l4.flow.list: boom');
    // Recovery clears the log; a recurrence is logged once more.
    h.replies['l4.flow.list'] = [];
    await h.store.refresh(true);
    expect(h.store.error()).toBeNull();
    h.replies['l4.flow.list'] = new BusError('boom');
    await h.store.refresh(true);
    await h.store.refresh(true);
    expect(h.notices).toEqual([
      ['l4.flow.list: boom', 'error'],
      ['l4.flow.list: boom', 'error'],
    ]);
  });

  it('idle cadence: l4.flow.list failing on every tick is noticed exactly once across a slow-only pass at 60 s (fix 3: per-label recovery)', async () => {
    h = harness({ replies: { 'l4.flow.list': new BusError('boom') } });
    // Ticks at 0, 10.5, …, 52.5 all fail; at 60 s only the slow group is due and it succeeds — that
    // clean slow-only pass must not forget the still-failing fast-group message (re-logged at 63 s).
    await driveTimer(h, 65_000);
    expect(h.count('l4.flow.list')).toBe(7);
    expect(h.count('l4.scope.list')).toBe(2);
    expect(h.notices).toEqual([['l4.flow.list: boom', 'error']]);
  });

  it('recovery is per label: scope.list recovering does not re-arm the flow.list message', async () => {
    h = harness({ replies: { 'l4.flow.list': new BusError('boom'), 'l4.scope.list': new BusError('scope closed') } });
    await h.store.refresh(true);
    h.replies['l4.scope.list'] = [];
    await h.store.refresh(true);
    await h.store.refresh(true);
    expect(h.notices).toEqual([
      ['l4.flow.list: boom', 'error'],
      ['l4.scope.list: scope closed', 'error'],
    ]);
    // scope.list fails again → logged once more (it recovered in between); flow.list still once.
    h.replies['l4.scope.list'] = new BusError('scope closed');
    await h.store.refresh(true);
    expect(h.notices.map(([t]) => t)).toEqual(['l4.flow.list: boom', 'l4.scope.list: scope closed', 'l4.scope.list: scope closed']);
  });

  it('recovery is per call, not per verb: flow A\'s l4.flow.get failing on every tick while B\'s succeeds is noticed exactly once (fix 4)', async () => {
    h = harness({
      replies: {
        'l4.flow.list': ['A', 'B'],
        'l4.flow.get': (a: Record<string, unknown>) => (a.id === 'A' ? new BusError('A broke') : flowWire('B')),
      },
    });
    for (let i = 0; i < 3; i++) await h.store.refresh(true);
    expect(h.argsOf('l4.flow.get').filter((a) => a.id === 'A')).toHaveLength(3);
    expect(h.argsOf('l4.flow.get').filter((a) => a.id === 'B')).toHaveLength(3);
    // B's success must not forget A's still-failing message.
    expect(h.notices).toEqual([['l4.flow.get: A broke', 'error']]);
    expect(h.store.rows().map((r) => r.id)).toEqual(['A', 'B']);
  });

  it('two flows failing with distinct messages, both recovering, then A failing again: A\'s message is logged again (fix 4)', async () => {
    let broken = new Set(['A', 'B']);
    h = harness({
      replies: {
        'l4.flow.list': ['A', 'B'],
        'l4.flow.get': (a: Record<string, unknown>) => (broken.has(String(a.id)) ? new BusError(`${a.id} broke`) : flowWire(String(a.id))),
      },
    });
    await h.store.refresh(true);
    expect(h.notices).toEqual([
      ['l4.flow.get: A broke', 'error'],
      ['l4.flow.get: B broke', 'error'],
    ]);
    broken = new Set();
    await h.store.refresh(true);
    expect(h.store.error()).toBeNull();
    broken = new Set(['A']);
    // A's recurrence is logged on the very pass it recurs (its own recovery re-armed it), …
    await h.store.refresh(true);
    expect(h.notices.map(([t]) => t)).toEqual(['l4.flow.get: A broke', 'l4.flow.get: B broke', 'l4.flow.get: A broke']);
    // … and B's continuing success does not re-arm it again: still exactly once per recurrence.
    await h.store.refresh(true);
    await h.store.refresh(true);
    expect(h.notices.map(([t]) => t)).toEqual(['l4.flow.get: A broke', 'l4.flow.get: B broke', 'l4.flow.get: A broke']);
  });

  it('two distinct failure messages are each noticed once', async () => {
    h = harness({ replies: { 'l4.flow.list': new BusError('boom'), 'l4.scope.list': new BusError('scope closed') } });
    for (let i = 0; i < 3; i++) await h.store.refresh(true);
    expect(h.notices).toEqual([
      ['l4.flow.list: boom', 'error'],
      ['l4.scope.list: scope closed', 'error'],
    ]);
  });

  it('a non-"L4 unavailable" status error is a read failure that leaves the previous availability in place', async () => {
    h = harness({ replies: { 'l4.capture.status': new BusError('bus closed (1006)') } });
    await h.store.refresh();
    expect(h.store.captureAvailability().reason).toBe('Reading L4 availability…');
    expect(h.notices).toEqual([['l4.capture.status: bus closed (1006)', 'error']]);
  });
});

describe('L4 store: windowed reads (spec §2)', () => {
  it('list rows are read with {id, limit: 0}; the inspector with {id, offset: 0, limit: 256}', async () => {
    h = harness({ replies: { 'l4.flow.list': ['F1', 'F2'], 'l4.flow.get': (a: Record<string, unknown>) => flowWire(String(a.id), { packet_count: 3 }) } });
    await h.store.refresh();
    expect(h.argsOf('l4.flow.get')).toEqual([
      { id: 'F1', limit: 0 },
      { id: 'F2', limit: 0 },
    ]);
    expect(h.store.ids()).toEqual(['F1', 'F2']);
    expect(h.store.rows().map((r) => r.id)).toEqual(['F1', 'F2']);
    await h.store.inspect('F2');
    expect(h.argsOf('l4.flow.get').at(-1)).toEqual({ id: 'F2', offset: 0, limit: 256 });
    expect(h.store.inspected()?.id).toBe('F2');
  });

  it('against an older core (no limit in the l4.flow.get schema) only {id} is sent', async () => {
    h = harness({ window: false, replies: { 'l4.flow.list': ['F1'], 'l4.flow.get': (a: Record<string, unknown>) => flowWire(String(a.id)) } });
    await h.store.refresh();
    await h.store.inspect('F1');
    expect(h.argsOf('l4.flow.get')).toEqual([{ id: 'F1' }, { id: 'F1' }]);
  });

  it('loadMore reads from next_offset after a truncated window and appends the packets', async () => {
    const pkt = (n: number) => ({ dir: 'inbound' as const, length: n, injected: false, layers: ['IPv4', 'UDP'] });
    h = harness({
      replies: {
        'l4.flow.list': ['F1'],
        'l4.flow.get': (a: Record<string, unknown>) =>
          a.limit === 0
            ? flowWire('F1', { packet_count: 3 })
            : a.offset === 0
              ? flowWire('F1', { packet_count: 3, packets: [pkt(1), pkt(2)], offset: 0, truncated: true, next_offset: 2 })
              : flowWire('F1', { packet_count: 3, packets: [pkt(3)], offset: 2, truncated: false, next_offset: null }),
      },
    });
    await h.store.refresh();
    await h.store.inspect('F1');
    expect(h.store.inspected()?.truncated).toBe(true);
    await h.store.loadMore();
    expect(h.argsOf('l4.flow.get').at(-1)).toEqual({ id: 'F1', offset: 2, limit: 256 });
    expect(h.store.inspected()?.packets.map((p) => p.length)).toEqual([1, 2, 3]);
    expect(h.store.inspected()?.truncated).toBe(false);
    // Complete: a further loadMore is a no-op.
    const before = h.count('l4.flow.get');
    await h.store.loadMore();
    expect(h.count('l4.flow.get')).toBe(before);
  });

  it('a second loadMore while the first is in flight for the same next_offset is ignored: one read, packets appended once (fix 3)', async () => {
    const pkt = (n: number) => ({ dir: 'inbound' as const, length: n, injected: false, layers: ['IPv4', 'UDP'] });
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    h = harness({
      replies: {
        'l4.flow.list': ['F1'],
        'l4.flow.get': (a: Record<string, unknown>) =>
          a.limit === 0
            ? flowWire('F1', { packet_count: 3 })
            : a.offset === 0
              ? flowWire('F1', { packet_count: 3, packets: [pkt(1), pkt(2)], offset: 0, truncated: true, next_offset: 2 })
              : gate.then(() => flowWire('F1', { packet_count: 3, packets: [pkt(3)], offset: 2, truncated: false, next_offset: null })),
      },
    });
    await h.store.refresh();
    await h.store.inspect('F1');
    const first = h.store.loadMore();
    const second = h.store.loadMore();
    release();
    await Promise.all([first, second]);
    expect(h.argsOf('l4.flow.get').filter((a) => a.offset === 2)).toHaveLength(1);
    expect(h.store.inspected()?.packets.map((p) => p.length)).toEqual([1, 2, 3]);
    expect(h.store.inspected()?.truncated).toBe(false);
  });

  it('the in-flight guard is per flow: a load-more on flow B is not dropped while flow A\'s read for the same next_offset is in flight (fix 4)', async () => {
    const pkt = (n: number) => ({ dir: 'inbound' as const, length: n, injected: false, layers: ['IPv4', 'UDP'] });
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    h = harness({
      replies: {
        'l4.flow.list': ['A', 'B'],
        'l4.flow.get': (a: Record<string, unknown>) => {
          const id = String(a.id);
          if (a.limit === 0) return flowWire(id, { packet_count: 3 });
          if (a.offset === 0) return flowWire(id, { packet_count: 3, packets: [pkt(1), pkt(2)], offset: 0, truncated: true, next_offset: 2 });
          const tail = flowWire(id, { packet_count: 3, packets: [pkt(3)], offset: 2, truncated: false, next_offset: null });
          return id === 'A' ? gate.then(() => tail) : tail;
        },
      },
    });
    await h.store.refresh();
    await h.store.inspect('A');
    const aMore = h.store.loadMore();
    // The operator selects B (also truncated at the same next_offset) and clicks load more while A's read is still out.
    await h.store.inspect('B');
    await h.store.loadMore();
    expect(h.argsOf('l4.flow.get').filter((a) => a.offset === 2)).toEqual([
      { id: 'A', offset: 2, limit: 256 },
      { id: 'B', offset: 2, limit: 256 },
    ]);
    expect(h.store.inspected()?.id).toBe('B');
    expect(h.store.inspected()?.packets.map((p) => p.length)).toEqual([1, 2, 3]);
    // A's late reply belongs to a flow no longer shown: B's window is untouched.
    release();
    await aMore;
    expect(h.store.inspected()?.id).toBe('B');
    expect(h.store.inspected()?.packets.map((p) => p.length)).toEqual([1, 2, 3]);
    // And a second click for B's same window while nothing is in flight for it is still a no-op (complete).
    const before = h.count('l4.flow.get');
    await h.store.loadMore();
    expect(h.count('l4.flow.get')).toBe(before);
  });

  it('loadMore releases its guard after a failed read, so the next click reads the same window again (tester pass 2)', async () => {
    const pkt = (n: number) => ({ dir: 'inbound' as const, length: n, injected: false, layers: ['IPv4', 'UDP'] });
    let tailReads = 0;
    h = harness({
      replies: {
        'l4.flow.list': ['F1'],
        'l4.flow.get': (a: Record<string, unknown>) => {
          if (a.limit === 0) return flowWire('F1', { packet_count: 3 });
          if (a.offset === 0) return flowWire('F1', { packet_count: 3, packets: [pkt(1), pkt(2)], offset: 0, truncated: true, next_offset: 2 });
          if (++tailReads === 1) throw new BusError('tail boom');
          return flowWire('F1', { packet_count: 3, packets: [pkt(3)], offset: 2, truncated: false, next_offset: null });
        },
      },
    });
    await h.store.refresh();
    await h.store.inspect('F1');
    await h.store.loadMore();
    expect(h.notices).toEqual([['l4.flow.get: tail boom', 'error']]);
    expect(h.store.inspected()?.packets.map((p) => p.length)).toEqual([1, 2]);
    expect(h.store.inspected()?.truncated).toBe(true);
    // The failed read must not leave the guard armed: the retry goes to the wire and lands.
    await h.store.loadMore();
    expect(h.argsOf('l4.flow.get').filter((a) => a.offset === 2)).toHaveLength(2);
    expect(h.store.inspected()?.packets.map((p) => p.length)).toEqual([1, 2, 3]);
    expect(h.store.inspected()?.truncated).toBe(false);
  });
});

describe('L4 store: refresh(force) while a pass is in flight (fix 3)', () => {
  it('a forced refresh arriving mid-pass runs one more pass after the current one instead of being dropped', async () => {
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    let listCalls = 0;
    h = harness({ replies: { 'l4.flow.list': () => (++listCalls === 1 ? gate.then(() => []) : []) } });
    const timerPass = h.store.refresh();
    expect(h.count('l4.flow.list')).toBe(1);
    const forced = h.store.refresh(true);
    // Still one read: the forced pass waits for the in-flight one.
    expect(h.count('l4.flow.list')).toBe(1);
    release();
    await Promise.all([timerPass, forced]);
    expect(h.count('l4.flow.list')).toBe(2);
    expect(h.count('l4.capture.status')).toBe(2);
    expect(h.count('l4.scope.list')).toBe(2);
  });

  it('two forced refreshes arriving mid-pass collapse into one extra pass, not two (tester pass 2)', async () => {
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    let listCalls = 0;
    h = harness({ replies: { 'l4.flow.list': () => (++listCalls === 1 ? gate.then(() => []) : []) } });
    const timerPass = h.store.refresh();
    const forcedA = h.store.refresh(true);
    const forcedB = h.store.refresh(true);
    expect(h.count('l4.flow.list')).toBe(1);
    release();
    await Promise.all([timerPass, forcedA, forcedB]);
    expect(h.count('l4.flow.list')).toBe(2);
    expect(h.count('l4.scope.list')).toBe(2);
    // The queued force is consumed: a later ordinary tick inside the idle 10 s window reads nothing more.
    await h.store.refresh();
    expect(h.count('l4.flow.list')).toBe(2);
  });

  it('a forced refresh queued behind a pass that failed still runs, and the failure is noticed once (tester pass 2)', async () => {
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    let listCalls = 0;
    h = harness({ replies: { 'l4.flow.list': () => (++listCalls === 1 ? gate.then(() => Promise.reject(new BusError('boom'))) : []) } });
    const timerPass = h.store.refresh();
    const forced = h.store.refresh(true);
    release();
    await Promise.all([timerPass, forced]);
    expect(h.count('l4.flow.list')).toBe(2);
    expect(h.notices).toEqual([['l4.flow.list: boom', 'error']]);
    // The forced pass read the list clean, so the store's error is clear again.
    expect(h.store.error()).toBeNull();
  });

  it('a plain timer call arriving mid-pass is still dropped (no queueing of ordinary ticks)', async () => {
    let release!: () => void;
    const gate = new Promise<void>((res) => (release = res));
    let listCalls = 0;
    h = harness({ replies: { 'l4.flow.list': () => (++listCalls === 1 ? gate.then(() => []) : []) } });
    const a = h.store.refresh();
    const b = h.store.refresh();
    release();
    await Promise.all([a, b]);
    expect(h.count('l4.flow.list')).toBe(1);
  });
});

describe('L4 store: parked packets and verdicts (spec §4; AC20)', () => {
  const PARKED = [
    { id: 'P1', flow: 'I1', state: 'parked', dir: 'inbound', length: 60, layers: ['IPv4', 'TCP'], parked_at: 1 },
    { id: 'P2', flow: 'I1', state: 'parked', dir: 'inbound', length: 60, layers: ['IPv4', 'TCP'], parked_at: 2 },
  ];

  it('reads l4.intercept.list only once intercept is available, in the core order', async () => {
    h = harness({
      replies: {
        'l4.intercept.status': { available: true, code: 'available', reason: null, sessions: [{ flow: 'I1', interface: 'lo', queue: 0, parked: 2 }] },
        'l4.intercept.list': PARKED,
      },
    });
    await h.store.refresh();
    expect(h.count('l4.intercept.list')).toBe(1);
    expect(h.store.parked().map((p) => p.id)).toEqual(['P1', 'P2']);
    expect(h.store.parked()).toHaveLength(2);
    // The class goes away (D0-style flip): the list is not polled and the parked set is cleared.
    h.replies['l4.intercept.status'] = UNAVAILABLE_INTERCEPT;
    await h.store.refresh(true);
    expect(h.count('l4.intercept.list')).toBe(1);
    expect(h.store.parked()).toEqual([]);
  });

  it('forward / drop / revert send {id: <parked id>} and mutate sends {id, spec}; the flow id never appears', async () => {
    h = harness({
      replies: {
        'l4.intercept.forward': { forwarded: true },
        'l4.intercept.drop': { dropped: true },
        'l4.intercept.revert': { reverted: true },
        'l4.intercept.mutate': { mutated: true },
      },
    });
    const spec = { layers: [{ ipv4: { dst: '127.0.0.1' } }, { udp: { dst_port: 9 } }, { raw: [1] }] };
    expect((await h.store.forward('P1')).kind).toBe('done');
    expect((await h.store.drop('P1')).kind).toBe('done');
    expect((await h.store.revert('P1')).kind).toBe('done');
    expect((await h.store.mutate('P1', spec)).kind).toBe('done');
    expect(h.argsOf('l4.intercept.forward')).toEqual([{ id: 'P1' }]);
    expect(h.argsOf('l4.intercept.drop')).toEqual([{ id: 'P1' }]);
    expect(h.argsOf('l4.intercept.revert')).toEqual([{ id: 'P1' }]);
    expect(h.argsOf('l4.intercept.mutate')).toEqual([{ id: 'P1', spec }]);
    for (const [, args] of h.calls) expect(JSON.stringify(args)).not.toContain('I1');
  });

  it('a needs_confirmation reply on a verdict is surfaced as a confirm outcome with the core prompt and token', async () => {
    h = harness({ replies: { 'l4.intercept.forward': { status: 'needs_confirmation', prompt: 'Forward 60 B TCP to 127.0.0.1:9000?', confirm_token: 'tok-1' } } });
    const out = await h.store.forward('P1');
    expect(out).toEqual({ kind: 'confirm', prompt: 'Forward 60 B TCP to 127.0.0.1:9000?', token: 'tok-1' });
  });

  it('a core refusal on a verdict is a refused outcome carrying the message, not a throw', async () => {
    h = harness({ replies: { 'l4.intercept.drop': new BusError('L4 unavailable: in-path interception is unsupported on macOS') } });
    const out = await h.store.drop('P1');
    expect(out).toEqual({ kind: 'refused', message: 'L4 unavailable: in-path interception is unsupported on macOS' });
  });
});

describe('L4 store: capture and scope actions through the builders (AC18, AC19, AC22)', () => {
  it('startCapture sends exactly {interface, direction}, stopCapture {id}, each followed by a forced refresh', async () => {
    h = harness({ replies: { 'l4.capture.start': 'C1', 'l4.capture.stop': true } });
    await h.store.refresh();
    const before = h.count('l4.flow.list');
    await h.store.startCapture('en0', 'outbound');
    expect(h.argsOf('l4.capture.start')).toEqual([{ interface: 'en0', direction: 'outbound' }]);
    expect(Object.keys(h.argsOf('l4.capture.start')[0]!)).toEqual(['interface', 'direction']);
    expect(h.count('l4.flow.list')).toBe(before + 1);
    await h.store.stopCapture('C1');
    expect(h.argsOf('l4.capture.stop')).toEqual([{ id: 'C1' }]);
    expect(h.notices.map(([t]) => t)).toEqual(['Capture started on en0 (outbound)', 'Capture C1 stopped']);
  });

  it('a start refusal is one error notice carrying the core text, and nothing else is sent', async () => {
    h = harness({ replies: { 'l4.capture.start': new BusError('L4 unavailable: no read+write access to any /dev/bpf* device') } });
    await h.store.startCapture('lo0', 'inbound');
    expect(h.notices).toEqual([['l4.capture.start: L4 unavailable: no read+write access to any /dev/bpf* device', 'error']]);
    expect(h.count('l4.flow.list')).toBe(0);
  });

  it('addScope sends the draft one-to-one; a done outcome re-reads l4.scope.list; confirmAddScope adds _confirm', async () => {
    const draft = { cidr: '127.0.0.1/32', ports: '9100-9199', interface: 'lo0', direction: 'inbound' as const, capability: 'capture' as const };
    h = harness({
      replies: {
        'l4.scope.add': (a: Record<string, unknown>) => ('_confirm' in a ? 's-new' : { status: 'needs_confirmation', prompt: 'Add 127.0.0.1/32 9100-9199 lo0 inbound capture', confirm_token: 'T' }),
        'l4.scope.list': [{ ...draft, id: 's-new', inject_rate: { pps: 0, burst: 0 }, source: 'runtime' }],
      },
    });
    const first = await h.store.addScope(draft);
    expect(first).toEqual({ kind: 'confirm', prompt: 'Add 127.0.0.1/32 9100-9199 lo0 inbound capture', token: 'T' });
    expect(h.argsOf('l4.scope.add')).toEqual([draft]);
    expect(h.count('l4.scope.list')).toBe(0);
    const second = await h.store.confirmAddScope(draft, 'T');
    expect(second.kind).toBe('done');
    expect(h.argsOf('l4.scope.add')[1]).toEqual({ ...draft, _confirm: 'T' });
    expect(h.count('l4.scope.list')).toBe(1);
    expect(h.store.scope().map((e) => e.source)).toEqual(['runtime']);
  });
});
