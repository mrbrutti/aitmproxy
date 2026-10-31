// The live flow list: the store polls `flow.list` on every real bus, whether or not the core
// advertises `flow.subscribe`, and only backs off while notifications are actually arriving.
//
// Regression: the core started advertising `flow.subscribe`, the old bootstrap took that as "push
// works", fetched `flow.list` once and never polled — but nothing in the UI called flow.subscribe and
// the /bus bridge pushed nothing, so the list froze at its load-time snapshot.
//
// The store now subscribes (ws.ts) and treats each push as a trigger to refetch; those cases live in
// `app.push.test.ts`. The bridge-shaped test bus is shared from `bridgeBus.testkit.ts`.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { StateNotification } from '~/bus/types';
import { createAppStore } from './app';
import { FLOW_PING, bridgeBus, captureInFlight, captureSilently, complete, tick, type TestBus } from './bridgeBus.testkit';

const STATE: StateNotification = { listening: true, intercept_armed: false, paused: 0, agent: 'all' };

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

  it('has the poll flag set the moment the loop starts, before its first tick', async () => {
    const { app } = start();

    await tick(200); // bootstrap is done (a few tens of ms); the first tick is not due until 500 ms

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

    // …yet the loop runs (summaries via flow.get until the catalogue heals).
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

  it('heals a degraded bootstrap: the catalogue, version and armed state arrive on a later tick', async () => {
    const bus = bridgeBus();
    bus.ctl.failToolsOnce = true;
    const { app } = start(bus);
    await tick(200);
    expect(app.proxy.tools).toEqual([]);
    expect(app.proxy.version).toBe('');
    const arming = bus.call<boolean>('flow.intercept', { enabled: true }); // armed in the core; only proxy.status can tell the UI
    await tick(50);
    expect(await arming).toBe(true);
    expect(app.proxy.armed).toBe(false);

    await tick(1000); // the next tick retries tools/list, then refreshSide

    expect(app.proxy.tools.some((t) => t.name === 'flow.detail')).toBe(true);
    expect(app.proxy.version).toBe('0.0.0-fixtures');
    expect(app.proxy.armed).toBe(true);
    await tick(5000);
    expect(bus.count('tools/list')).toBe(2); // one failure, one success — then it stops asking
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

  it('makes no calls while the bus is not open, then resumes within one tick of it opening', async () => {
    const { bus, app } = start();
    await tick(1200); // bootstrapped and a couple of ticks in
    expect(app.proxy.polling).toBe(true);
    const lists = bus.count('flow.list');
    const statuses = bus.count('proxy.status');
    const id = captureSilently(bus, 8);

    bus.ctl.setState('reconnecting');
    await tick(5000);

    expect(bus.count('flow.list')).toBe(lists); // nothing is sent into a dead bus…
    expect(bus.count('proxy.status')).toBe(statuses);
    expect(app.entries).toHaveLength(0);
    expect(app.proxy.polling).toBe(false); // …and the flag does not claim a loop that is not polling

    bus.ctl.setState('open');
    await tick(700); // one tick: 500 ms plus a call's latency

    expect(app.entries.map((e) => e.id)).toEqual([id]);
    expect(app.proxy.polling).toBe(true);
  });
});

describe('app store — a core with a large backlog', () => {
  const capture = (bus: TestBus, n: number) => Array.from({ length: n }, (_, i) => captureSilently(bus, i + 1));

  it('caps the flow.detail fan-out per poll and fetches the rest on later ticks, oldest first', async () => {
    const bus = bridgeBus();
    const ids = capture(bus, 450);
    const { app } = start(bus);

    await tick(300); // the bootstrap snapshot: not all 450 at once

    expect(app.entries.map((e) => e.id)).toEqual(ids.slice(0, 200));
    expect(bus.peak.detail).toBe(200);

    await tick(1500); // two more polls

    expect(app.entries.map((e) => e.id)).toEqual(ids);
    expect(bus.peak.detail).toBe(200);
  });

  it('keeps draining that backlog on the normal cadence even while flow push is live', async () => {
    const bus = bridgeBus();
    const ids = capture(bus, 450);
    const { app } = start(bus);

    for (let s = 0; s < 3; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING); // push is alive; the old flows still need fetching
      await tick(1000);
    }

    expect(app.entries.map((e) => e.id)).toEqual(ids);
  });
});

describe('app store — flows the core cannot render', () => {
  const capture = (bus: TestBus, n: number) => Array.from({ length: n }, (_, i) => captureSilently(bus, i + 1));

  it('a cap-sized run of unreadable flows does not starve the healthy ones behind it, nor spin the loop', async () => {
    const bus = bridgeBus();
    const ids = capture(bus, 250);
    for (const id of ids.slice(0, 201)) bus.ctl.failDetail.add(id); // the oldest 201 always error
    const { app } = start(bus);

    for (let s = 0; s < 3; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING); // push is live, so only backlog can force polls
      await tick(1000);
    }

    // The 49 readable flows behind the 201 bad ones are in, in capture order, within a few ticks…
    expect(app.entries.map((e) => e.id)).toEqual(ids.slice(201));

    // …and the loop is NOT hammering the bad ones at the 500 ms cadence: over the next 10 s of live
    // push it makes only the heartbeat's polls (the bad flows are retried only after a pause).
    const lists = bus.count('flow.list');
    const details = bus.count('flow.detail');
    for (let s = 0; s < 10; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING);
      await tick(1000);
    }
    expect(bus.count('flow.list') - lists).toBeLessThanOrEqual(3); // ~1 heartbeat + its follow-up, not ~20
    expect(bus.count('flow.detail') - details).toBeLessThanOrEqual(2 * 201);
  });

  it('does not let flows that cannot be re-read crowd the healthy in-flight ones out of the refresh window', async () => {
    const bus = bridgeBus();
    const ids = Array.from({ length: 60 }, (_, i) => captureInFlight(bus, i + 1));
    const { app } = start(bus);
    await tick(300); // all 60 are known, none has a status yet
    expect(ids.every((id) => app.byId.get(id)?.raw.status == null)).toBe(true);

    for (const id of ids.slice(0, 50)) bus.ctl.failDetail.add(id); // the oldest 50 can no longer be read
    const healthy = ids.slice(50);
    for (const id of healthy) complete(bus, id); // the core finished the other 10

    await tick(1500); // the refresh window is 50 flows wide: the bad ones must not fill it forever

    expect(healthy.map((id) => app.byId.get(id)?.raw.status != null)).toEqual(healthy.map(() => true));
  });

  it('retries an unreadable flow after a pause, so a flow that recovers still arrives', async () => {
    const bus = bridgeBus();
    const [id] = capture(bus, 1);
    bus.ctl.failDetail.add(id!);
    const { app } = start(bus);
    await tick(2000);
    expect(app.entries).toHaveLength(0); // unreadable for now

    bus.ctl.failDetail.delete(id!); // the core recovers
    await tick(6000); // longer than the retry pause

    expect(app.entries.map((e) => e.id)).toEqual([id]);
  });
});

describe('app store — push-capable bus stays cheap', () => {
  it('skips the flow and status polls while flow and state notifications keep arriving', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const statuses = bus.count('proxy.status');

    for (let s = 0; s < 8; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING);
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }

    // 8 s of push, under the 10 s heartbeat: not one poll of either kind.
    expect(bus.count('flow.list')).toBe(lists);
    expect(bus.count('proxy.status')).toBe(statuses);
    // The live source is push, not the poll loop.
    expect(app.proxy.polling).toBe(false);
  });

  it('counts notifications/aitm/flow as push for the flow list', async () => {
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

  it('a bridge that pushes only state (throughput ticks) does not slow the list down to the heartbeat', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const statuses = bus.count('proxy.status');
    const id = captureSilently(bus, 9);

    for (let s = 0; s < 3; s++) {
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }

    expect(app.entries.map((e) => e.id)).toEqual([id]); // found on the 500 ms cadence, not at 10 s
    expect(bus.count('flow.list') - lists).toBeGreaterThanOrEqual(5);
    expect(bus.count('proxy.status')).toBe(statuses); // state IS pushed, so status is not polled
    expect(app.proxy.polling).toBe(true); // the list is still being polled
  });

  it('flow push alone does not stop the status poll', async () => {
    const { bus } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const statuses = bus.count('proxy.status');

    for (let s = 0; s < 8; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING);
      await tick(1000);
    }

    expect(bus.count('flow.list')).toBe(lists);
    expect(bus.count('proxy.status') - statuses).toBeGreaterThanOrEqual(3); // still ~every 2 s
    expect(bus.count('proxy.status') - statuses).toBeLessThanOrEqual(4);
  });

  it('resumes polling after 10 s without a flow notification', async () => {
    const { bus, app } = start();
    await tick(200);
    const base = bus.count('flow.list');
    bus.emit('notifications/aitm/flow', FLOW_PING); // push is live at t = 200 ms…
    await tick(9000); // …and falls silent
    expect(bus.count('flow.list')).toBe(base); // t = 9.2 s: still inside the window

    const id = captureSilently(bus, 4);
    await tick(3000); // t = 12.2 s: the window closed at 10.2 s

    expect(app.entries.map((e) => e.id)).toEqual([id]);
    expect(bus.count('flow.list') - base).toBeGreaterThanOrEqual(3); // back on the 500 ms cadence
    expect(app.proxy.polling).toBe(true);
  });

  it('still runs a heartbeat poll every ~10 s so a flow stream that loses an event cannot freeze the list', async () => {
    const { bus, app } = start();
    await tick(200);
    const id = captureSilently(bus, 5); // captured, but its notification never arrives; others keep coming

    for (let s = 0; s < 9; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING);
      await tick(1000);
    }
    expect(app.entries).toHaveLength(0); // t = 9.2 s: push is "live", the heartbeat is not due yet

    for (let s = 0; s < 3; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING);
      await tick(1000);
    }

    expect(app.entries.map((e) => e.id)).toEqual([id]); // t = 12.2 s: the heartbeat poll found it
  });

  it('the heartbeat polls proxy.status as well as flow.list', async () => {
    const { bus } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const statuses = bus.count('proxy.status');

    for (let s = 0; s < 12; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING);
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }

    // t = 12.2 s with both streams live throughout: exactly one heartbeat, covering both polls.
    expect(bus.count('flow.list') - lists).toBe(1);
    expect(bus.count('proxy.status') - statuses).toBe(1);
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
