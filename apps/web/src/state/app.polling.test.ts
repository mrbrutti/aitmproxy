// The live flow list: the store polls `flow.list` on every real bus, whether or not the core
// advertises `flow.subscribe`, and only backs off while notifications are actually arriving.
//
// Regression: the core started advertising `flow.subscribe`, the old bootstrap took that as "push
// works", fetched `flow.list` once and never polled — but nothing in the UI calls flow.subscribe and
// the /bus bridge pushes nothing, so the list froze at its load-time snapshot.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createMockBus, type MockControls } from '~/bus/mock';
import { generateRequest, generateResponse, mulberry32 } from '~/bus/fixtures';
import { BusError, type BusClient, type NotificationHandler, type StateNotification, type ToolDef } from '~/bus/types';
import { createAppStore } from './app';

const SUBSCRIBE: ToolDef = {
  name: 'flow.subscribe',
  description: 'Stream flow events (streaming MCP connections only).',
  inputSchema: { type: 'object', properties: {} },
};

type TestBus = BusClient &
  MockControls & {
    /** Every tool called through the store, in order. */
    calls: string[];
    count(tool: string): number;
    /** Deliver a server notification to the store, as a streaming bus would. */
    emit(method: string, params: unknown): void;
    /**
     * Failure / latency injection: `flow.list` fails or is held, the next `tools/list` rejects, and
     * the next `failStatus` `proxy.status` calls throw. Set these BEFORE `start()` to fail bootstrap.
     */
    ctl: { failFlowList: boolean; holdFlowList: Promise<void> | null; failToolsOnce: boolean; failStatus: number };
  };

/**
 * A real-looking bus (not the `fixtures` one): the mock command set, an address that is not
 * `fixtures`, `flow.subscribe` advertised, and NO notifications of its own — like the /bus bridge.
 */
function bridgeBus(address = '127.0.0.1:8082'): TestBus {
  const mock = createMockBus({ initial: 0, rate: 0, agentActive: false });
  const handlers = new Set<NotificationHandler>();
  const calls: string[] = [];
  const ctl: TestBus['ctl'] = { failFlowList: false, holdFlowList: null, failToolsOnce: false, failStatus: 0 };
  return {
    ...mock,
    address,
    calls,
    ctl,
    count: (tool) => calls.filter((c) => c === tool).length,
    async tools() {
      if (ctl.failToolsOnce) {
        ctl.failToolsOnce = false;
        throw new BusError('tools/list: bus closed (1006)');
      }
      return [...(await mock.tools()), SUBSCRIBE];
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      calls.push(tool);
      if (tool === 'flow.list') {
        if (ctl.holdFlowList) await ctl.holdFlowList;
        if (ctl.failFlowList) throw new BusError('bus unreachable');
      }
      if (tool === 'proxy.status' && ctl.failStatus > 0) {
        ctl.failStatus--;
        throw new BusError('proxy.status: bus closed (1006)');
      }
      return mock.call<T>(tool, args);
    },
    onNotification(h) {
      handlers.add(h);
      return () => handlers.delete(h);
    },
    emit(method, params) {
      for (const h of handlers) h(method, params);
    },
  };
}

/** A flow appears in the core with no notification — what the bridge does for every capture. */
function captureSilently(bus: TestBus, seq: number): string {
  const now = Date.now();
  const flow = generateResponse(generateRequest({ rng: mulberry32(seq), seq, now, armed: false, scope: [] }), mulberry32(seq), now);
  bus.flowsById().set(flow.id, flow);
  return flow.id;
}

const STATE: StateNotification = { listening: true, intercept_armed: false, paused: 0, agent: 'all' };
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);

let open: TestBus[] = [];
const start = (bus: TestBus = bridgeBus()) => {
  open.push(bus);
  return { bus, app: createAppStore(bus) };
};

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  // Closing the bus stops the store's poll loop and the mock's own timers.
  for (const b of open) b.close();
  open = [];
  vi.useRealTimers();
});

describe('app store — live flow list', () => {
  it('picks up flows captured after bootstrap even though the bus advertises flow.subscribe', async () => {
    const { bus, app } = start();
    await tick(200); // bootstrap: tools/list, side data, first flow.list
    expect((await bus.tools()).some((t) => t.name === 'flow.subscribe')).toBe(true);
    expect(app.entries).toHaveLength(0);

    const id = captureSilently(bus, 1);
    await tick(1000); // one poll interval is 500 ms

    expect(app.entries.map((e) => e.id)).toEqual([id]);
    expect(app.byId.get(id)?.raw).toMatchObject({ id: 'f_1', method: 'GET', authority: 'cdn.shop-staging.test', path: '/assets/app.css', status: 304 });
    // No notification ever arrived, so the poll loop is the live source.
    expect(app.proxy.polling).toBe(true);
  });

  it('keeps polling every ~500 ms, one flow.list per tick', async () => {
    const { bus } = start();
    await tick(200);
    const base = bus.count('flow.list');
    expect(base).toBe(1); // the bootstrap snapshot

    await tick(5000);

    // 5 s of 500 ms ticks (each tick also waits out the call's few ms of latency): 9 or 10 polls.
    expect(bus.count('flow.list') - base).toBeGreaterThanOrEqual(9);
    expect(bus.count('flow.list') - base).toBeLessThanOrEqual(10);
  });

  it('polls proxy.status about every 2 s so armed/listening state follows the core', async () => {
    const { bus } = start();
    await tick(200);
    const base = bus.count('proxy.status'); // bootstrap's refreshSide

    await tick(8000);

    expect(bus.count('proxy.status') - base).toBeGreaterThanOrEqual(3);
    expect(bus.count('proxy.status') - base).toBeLessThanOrEqual(4);
  });

  it('never overlaps itself: a slow flow.list holds the loop instead of stacking calls', async () => {
    const { bus } = start();
    await tick(200);
    const base = bus.count('flow.list');
    let release!: () => void;
    bus.ctl.holdFlowList = new Promise<void>((r) => (release = r));

    await tick(5000);

    expect(bus.count('flow.list') - base).toBe(1); // one in flight, none queued behind it
    release();
    bus.ctl.holdFlowList = null;
    await tick(1000);
    expect(bus.count('flow.list') - base).toBeGreaterThanOrEqual(2);
  });

  it('swallows a failing flow.list and recovers on a later tick', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.ctl.failFlowList = true;
    const id = captureSilently(bus, 2);
    await tick(3000); // several failed ticks, nothing thrown
    expect(app.entries).toHaveLength(0);

    bus.ctl.failFlowList = false;
    await tick(1000);

    expect(app.entries.map((e) => e.id)).toEqual([id]);
  });

  it('still polls after bootstrap fails: tools/list rejects once, the toast says so, the list does not freeze', async () => {
    const bus = bridgeBus();
    bus.ctl.failToolsOnce = true; // bootstrap's very first call throws
    const { app } = start(bus);
    await tick(200);

    expect(app.toast()).toEqual({ text: 'tools/list: bus closed (1006)', kind: 'error' });
    expect(app.proxy.tools).toEqual([]); // the catalogue never arrived…

    const id = captureSilently(bus, 6);
    await tick(1000);

    // …yet the loop runs (summaries via flow.get, since flow.detail was never learned).
    expect(app.entries.map((e) => e.id)).toEqual([id]);
    expect(app.proxy.polling).toBe(true);
  });

  it('still polls when the first proxy.status throws during bootstrap', async () => {
    const bus = bridgeBus();
    bus.ctl.failStatus = 1;
    const { app } = start(bus);
    await tick(200);
    expect(bus.count('proxy.status')).toBe(1); // it was attempted, and failed
    const id = captureSilently(bus, 7);

    await tick(1000);

    expect(app.entries.map((e) => e.id)).toEqual([id]);
    expect(app.proxy.polling).toBe(true);
  });

  it('stops polling once the bus is closed', async () => {
    const { bus, app } = start();
    await tick(200);
    await tick(2000);
    expect(app.proxy.polling).toBe(true);
    expect(bus.count('flow.list')).toBeGreaterThan(2); // it was polling

    bus.close();
    await tick(600); // let an already-scheduled tick find the bus closed
    const frozen = bus.count('flow.list');
    await tick(5000);

    expect(bus.count('flow.list')).toBe(frozen);
    expect(app.proxy.polling).toBe(false);
  });
});

describe('app store — push-capable bus stays cheap', () => {
  it('skips the flow and status polls while notifications keep arriving', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const statuses = bus.count('proxy.status');

    for (let s = 0; s < 8; s++) {
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }

    // 8 s of push, under the 10 s heartbeat: not one poll of either kind.
    expect(bus.count('flow.list')).toBe(lists);
    expect(bus.count('proxy.status')).toBe(statuses);
    // The live source is push, not the poll loop.
    expect(app.proxy.polling).toBe(false);
  });

  it('counts notifications/aitm/flow as push too', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const id = captureSilently(bus, 3);

    for (let s = 0; s < 5; s++) {
      bus.emit('notifications/aitm/flow', { event: 'created', id, summary: bus.flowsById().get(id) });
      await tick(1000);
    }

    expect(bus.count('flow.list')).toBe(lists); // no poll
    expect(app.byId.has(id)).toBe(true); // and the flow still arrived, via the notification
  });

  it('resumes polling after 10 s without a notification', async () => {
    const { bus, app } = start();
    await tick(200);
    const base = bus.count('flow.list');
    bus.emit('notifications/aitm/state', STATE); // push is live at t = 200 ms…
    await tick(9000); // …and falls silent
    expect(bus.count('flow.list')).toBe(base); // t = 9.2 s: still inside the window

    const id = captureSilently(bus, 4);
    await tick(3000); // t = 12.2 s: the window closed at 10.2 s

    expect(app.entries.map((e) => e.id)).toEqual([id]);
    expect(bus.count('flow.list') - base).toBeGreaterThanOrEqual(3); // back on the 500 ms cadence
    expect(app.proxy.polling).toBe(true);
  });

  it('still runs a heartbeat poll every ~10 s so a push that stops delivering flows cannot freeze the list', async () => {
    const { bus, app } = start();
    await tick(200);
    const id = captureSilently(bus, 5); // captured, but only state notifications ever arrive

    for (let s = 0; s < 9; s++) {
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }
    expect(app.entries).toHaveLength(0); // t = 9.2 s: push is "live", the heartbeat is not due yet

    for (let s = 0; s < 3; s++) {
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }

    expect(app.entries.map((e) => e.id)).toEqual([id]); // t = 12.2 s: the heartbeat poll found it
  });
});

describe('app store — the static fixtures bus', () => {
  it('fetches the snapshot once and never polls', async () => {
    const { bus, app } = start(bridgeBus('fixtures'));

    await tick(10_000);

    expect(bus.count('flow.list')).toBe(1);
    expect(app.proxy.polling).toBe(false);
  });
});
