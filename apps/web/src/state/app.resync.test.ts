// Resync: the server's `{lagged:true}` marker (its notification lane overflowed and dropped lines) is
// never applied as state; it distrusts push freshness and runs `flow.list` now, single-flight with the
// loop's own poll. A partial state payload writes nothing and advances no clock. Only a FLOW
// notification makes the flow stream fresh. A reconnect resets both clocks and the failure hold-off,
// so the first tick after an outage takes a fresh snapshot. The push path is `app.push.test.ts`;
// the loop itself is `app.polling.test.ts`.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { StateNotification } from '~/bus/types';
import { createAppStore } from './app';
import { bridgeBus, captureSilently, type TestBus } from './bridgeBus.testkit';

const STATE: StateNotification = { listening: true, intercept_armed: false, paused: 0, agent: 'all', memory_bytes: 123, throughput: { up: 1, down: 2 } };
/** What the server sends on `notifications/aitm/state` when its per-connection lane overflowed. */
const LAGGED = { lagged: true };
/** A flow notification that changes nothing (no summary) but proves the flow stream is alive. */
const FLOW_PING = { event: 'meta', id: 'f_none' };
/** An audit line as the server sends it: epoch ms, `client_label`, `args` as a JSON string. */
const AGENT_LINE = { at: 1730000000000, origin: 'mcp', client_label: 'claude-code', command: 'flow.replay', args: '{"id":"f_1"}', result: 'ok' };
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);
/** A promise the test releases by hand, for `ctl.holdFlowList`. */
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((r) => (release = r));
  return { promise, release };
}

let open: TestBus[] = [];
const start = (bus: TestBus = bridgeBus()) => {
  open.push(bus);
  return { bus, app: createAppStore(bus) };
};

beforeEach(() => {
  vi.useFakeTimers();
});
afterEach(() => {
  for (const b of open) b.close();
  open = [];
  vi.useRealTimers();
});

describe('app store — the lagged marker', () => {
  it('lagged triggers an immediate flow.list and is never applied', async () => {
    const { bus, app } = start();
    await tick(200); // bootstrap: tools/list, side data, first flow.list
    bus.emit('notifications/aitm/state', STATE);
    const lists = bus.count('flow.list');
    captureSilently(bus, 1); // its notification was among the dropped lines

    bus.emit('notifications/aitm/state', LAGGED);
    await tick(50); // well inside the 500 ms tick: the resync is immediate

    expect(bus.count('flow.list')).toBe(lists + 1);
    expect(app.entries.map((e) => e.id)).toEqual(['f_1']);
    // The marker is not state: what the full payload set is still there.
    expect(app.proxy.listening).toBe(true);
    expect(app.proxy.armed).toBe(false);
    expect(app.proxy.agent).toBe('all');
    expect(app.proxy.memoryBytes).toBe(123);
    expect(app.proxy.throughput).toEqual({ up: 1, down: 2 });
  });

  it('lagged does not back the status poll off', async () => {
    const { bus } = start();
    await tick(200);
    const statuses = bus.count('proxy.status');

    for (let s = 0; s < 8; s++) {
      bus.emit('notifications/aitm/state', LAGGED); // once a second, and no real state push
      await tick(1000);
    }

    // The marker is not a state push: proxy.status keeps its 2 s cadence (3 or 4 calls in 8 s).
    expect(bus.count('proxy.status') - statuses).toBeGreaterThanOrEqual(3);
    expect(bus.count('proxy.status') - statuses).toBeLessThanOrEqual(4);
  });

  it('lagged distrusts push freshness until the next flow push', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.emit('notifications/aitm/flow', FLOW_PING); // push is fresh…
    await tick(1000);
    const lists = bus.count('flow.list');
    captureSilently(bus, 2);

    bus.emit('notifications/aitm/state', LAGGED); // …a second ago, and the lane overflowed
    await tick(50);
    expect(bus.count('flow.list')).toBe(lists + 1); // the immediate resync
    expect(app.entries.map((e) => e.id)).toEqual(['f_2']);

    captureSilently(bus, 3);
    await tick(1000);
    expect(app.byId.has('f_3')).toBe(true); // the 500 ms cadence ran though a push was fresh a second ago

    const afterPing = bus.count('flow.list');
    bus.emit('notifications/aitm/flow', FLOW_PING); // the next flow push restores trust
    await tick(3000);
    expect(bus.count('flow.list') - afterPing).toBeLessThanOrEqual(1);
  });

  it('lagged during a poll schedules one trailing poll', async () => {
    const { bus } = start();
    await tick(200);
    const lists = bus.count('flow.list');
    const g = gate();
    bus.ctl.holdFlowList = g.promise;

    for (let s = 0; s < 3; s++) bus.emit('notifications/aitm/state', LAGGED);
    await tick(10);
    expect(bus.count('flow.list')).toBe(lists + 1); // one in flight; the other two fold into one trailing poll

    g.release();
    bus.ctl.holdFlowList = null;
    await tick(100);
    expect(bus.count('flow.list')).toBe(lists + 2);
  });
});

describe('app store — state payloads and freshness', () => {
  it('a partial state payload writes nothing', async () => {
    const { bus, app } = start();
    await tick(200);
    const statuses = bus.count('proxy.status');

    // Partial payloads for 8 s: nothing is written, and they do not count as a state push (the
    // status poll keeps its 2 s cadence instead of backing off to the 10 s heartbeat).
    for (let s = 0; s < 8; s++) {
      bus.emit('notifications/aitm/state', { listening: false });
      await tick(1000);
    }
    expect(app.proxy.listening).toBe(true);
    expect(bus.count('proxy.status') - statuses).toBeGreaterThanOrEqual(3);
    expect(bus.count('proxy.status') - statuses).toBeLessThanOrEqual(4);

    // A complete payload is applied; a partial one after it does not undo any of it.
    bus.emit('notifications/aitm/state', { ...STATE, intercept_armed: true });
    expect(app.proxy.armed).toBe(true);
    bus.emit('notifications/aitm/state', { listening: false });
    expect(app.proxy.listening).toBe(true);
    expect(app.proxy.armed).toBe(true);
    expect(app.proxy.agent).toBe('all');
  });

  it('agent and state notifications do not make the flow stream fresh', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');

    for (let s = 0; s < 8; s++) {
      bus.emit('notifications/aitm/agent', AGENT_LINE);
      bus.emit('notifications/aitm/state', STATE);
      await tick(1000);
    }

    // Neither stream says anything about flows: the list keeps its 500 ms cadence.
    expect(bus.count('flow.list') - lists).toBeGreaterThanOrEqual(12);
    expect(app.proxy.polling).toBe(true);
  });
});

describe('app store — a reconnect is a new stream', () => {
  it('a reconnect resnapshots even when push was fresh', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.emit('notifications/aitm/flow', FLOW_PING); // push is fresh at t = 200 ms
    captureSilently(bus, 1); // captured during the outage; its push never reaches this page

    bus.ctl.setState('reconnecting');
    await tick(300);
    expect(app.entries).toHaveLength(0);
    bus.ctl.setState('open');
    await tick(700); // one tick: 500 ms plus a call's latency

    expect(app.entries.map((e) => e.id)).toEqual(['f_1']); // not at the 10 s heartbeat
  });

  it('a reconnect forgets held failures', async () => {
    const bus = bridgeBus();
    bus.ctl.failDetail.add('f_1');
    captureSilently(bus, 1);
    const { app } = start(bus);
    await tick(1000); // the bootstrap read failed; the flow is held for FAILED_RETRY_MS
    expect(app.entries).toHaveLength(0);
    bus.ctl.failDetail.delete('f_1'); // the core recovers

    bus.ctl.setState('reconnecting');
    await tick(100);
    bus.ctl.setState('open');
    await tick(700);

    expect(app.entries.map((e) => e.id)).toEqual(['f_1']); // t ≈ 1.8 s: well inside the 5 s hold
  });
});
