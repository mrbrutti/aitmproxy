// Push as a trigger: on a real bus a `notifications/aitm/flow` line never writes its (sparse) summary
// into the list. It queues the id; a 100 ms coalescer refetches through the same helper the poll uses
// (`flow.detail {id, body:'none'}`, or `flow.get` without the catalogue entry), in waves of 16, under
// the same failure hold-off, with stale replies discarded by ticket and `cleared` by epoch. The
// `fixtures` bus keeps the old direct-apply path. The poll loop itself is covered by
// `app.polling.test.ts`; this file only checks that push and poll coexist (the heartbeat case).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FlowEventKind } from '~/bus/types';
import { createAppStore } from './app';
import { bridgeBus, captureInFlight, captureSilently, complete, type TestBus } from './bridgeBus.testkit';

/** What the server really sends with a flow event: a thin summary, `kind:"ws"` spelled its way, no times, no sizes. */
const sparse = (id: string) => ({ id, kind: 'ws', method: 'GET', authority: 'x.test', path: '/p', status: null });
const push = (bus: TestBus, event: FlowEventKind, id: string) => bus.emit('notifications/aitm/flow', { event, id, summary: sparse(id) });
/** A flow notification that changes nothing (no summary) but proves the flow stream is alive. */
const FLOW_PING = { event: 'meta', id: 'f_none' };
const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);
/** A promise the test releases by hand, for `ctl.holdReply`. */
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

describe('app store — a flow push is a trigger, never data', () => {
  it('a flow push for a new flow is refetched via flow.detail', async () => {
    const { bus, app } = start();
    await tick(200); // bootstrap: tools/list, side data, first flow.list
    const lists = bus.count('flow.list');
    captureSilently(bus, 1);

    bus.emit('notifications/aitm/flow', { event: 'created', id: 'f_1', summary: { id: 'f_1', kind: 'ws', method: 'GET', authority: 'x.test', path: '/p', status: null } });
    await tick(150); // one coalescing window plus the call's few ms

    expect(bus.callArgs('flow.detail')).toEqual([{ id: 'f_1', body: 'none' }]);
    expect(bus.count('flow.list')).toBe(lists); // no list scan for a push
    // The row is what the core has, not what the push said.
    expect(app.byId.get('f_1')!.raw).toMatchObject({ id: 'f_1', kind: 'http', method: 'GET', authority: 'cdn.shop-staging.test', path: '/assets/app.css', status: 304 });
  });

  it('a sparse push does not overwrite a rich row', async () => {
    const bus = bridgeBus();
    captureSilently(bus, 1); // before start, so the bootstrap poll loads it rich
    const { app } = start(bus);
    await tick(200);
    const before = structuredClone(app.byId.get('f_1')!.raw);
    expect(before.seq).toBe(1);

    push(bus, 'meta', 'f_1');
    await tick(250);

    expect(app.byId.get('f_1')!.raw).toEqual(before);
    expect(app.byId.get('f_1')!.raw.seq).toBe(1);
  });

  it('events for one flow within the window make one detail call', async () => {
    const { bus } = start();
    await tick(200);
    captureSilently(bus, 1);

    for (const event of ['created', 'request', 'response', 'response', 'meta'] as const) push(bus, event, 'f_1');
    await tick(150);

    expect(bus.callArgs('flow.detail').filter((a) => a.id === 'f_1')).toHaveLength(1);
  });

  it('an event during an in-flight fetch is refetched after it', async () => {
    const { bus } = start();
    await tick(200);
    captureSilently(bus, 1);
    const g = gate();
    bus.ctl.holdReply.set('f_1', g.promise);

    push(bus, 'created', 'f_1');
    await tick(120);
    expect(bus.count('flow.detail')).toBe(1); // issued, held

    push(bus, 'response', 'f_1');
    await tick(150);
    expect(bus.count('flow.detail')).toBe(1); // not while the first is in flight

    g.release();
    await tick(250);
    expect(bus.count('flow.detail')).toBe(2); // refetched after it
  });

  it('new flows land in notification order even if replies reorder', async () => {
    const { bus, app } = start();
    await tick(200);
    for (let s = 1; s <= 3; s++) captureSilently(bus, s);
    const g = gate();
    bus.ctl.holdReply.set('f_1', g.promise); // the first flow's reply comes back last

    for (const id of ['f_1', 'f_2', 'f_3']) push(bus, 'created', id);
    await tick(150);
    expect(app.entries).toHaveLength(0); // one wave: nothing is applied until every reply is in

    g.release();
    await tick(10);

    expect(app.entries.map((e) => e.id)).toEqual(['f_1', 'f_2', 'f_3']);
    expect(app.entries.map((e) => e.raw.seq)).toEqual([1, 2, 3]);
  });

  it('a known flow keeps its seq', async () => {
    const bus = bridgeBus();
    for (let s = 1; s <= 3; s++) captureSilently(bus, s);
    const { app } = start(bus);
    await tick(200);
    expect(app.byId.get('f_2')!.raw.seq).toBe(2);

    push(bus, 'meta', 'f_2');
    await tick(150);

    expect(bus.callArgs('flow.detail').filter((a) => a.id === 'f_2')).toHaveLength(2); // the bootstrap read and the refetch
    expect(app.byId.get('f_2')!.raw.seq).toBe(2);
  });

  it('a push for an unreadable flow is held off then retried', async () => {
    const { bus } = start();
    await tick(200);
    bus.ctl.failDetail.add('f_1');
    captureSilently(bus, 1);

    for (let s = 0; s < 4; s++) {
      push(bus, 'created', 'f_1'); // once a second for 4 s
      await tick(1000);
    }
    expect(bus.callArgs('flow.detail').filter((a) => a.id === 'f_1')).toHaveLength(1); // failed once at ~0.3 s, then held

    await tick(2200); // t ≈ 6.4 s: more than FAILED_RETRY_MS past the failure
    push(bus, 'created', 'f_1');
    await tick(150);

    expect(bus.callArgs('flow.detail').filter((a) => a.id === 'f_1')).toHaveLength(2);
  });

  it('a burst of pushes never has more than 16 detail calls in flight', async () => {
    const { bus, app } = start();
    await tick(200);

    for (let s = 1; s <= 100; s++) push(bus, 'created', captureSilently(bus, s));
    await tick(1000);

    expect(bus.peak.detail).toBeLessThanOrEqual(16);
    expect(bus.count('flow.detail')).toBe(100); // every one fetched, once
    expect(app.entries).toHaveLength(100);
  });

  it('overflowing the pending cap hands the rest to the poll', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');

    for (let s = 1; s <= 300; s++) push(bus, 'created', captureSilently(bus, s));
    await tick(5000);

    expect(app.entries).toHaveLength(300);
    expect(bus.count('flow.list')).toBeGreaterThan(lists); // the surplus set `backlog`, so the poll ran
  });

  it('falls back to flow.get without the flow.detail tool', async () => {
    const bus = bridgeBus();
    bus.ctl.hideTools.add('flow.detail');
    const { app } = start(bus);
    await tick(200);
    captureSilently(bus, 1);

    push(bus, 'created', 'f_1');
    await tick(150);

    expect(bus.count('flow.get')).toBe(1);
    expect(bus.count('flow.detail')).toBe(0);
    expect(app.byId.has('f_1')).toBe(true);
  });

  it('an older reply never overwrites a newer one', async () => {
    const bus = bridgeBus();
    captureInFlight(bus, 1); // loaded by the bootstrap with status null
    const { app } = start(bus);
    await tick(200);
    expect(app.byId.get('f_1')!.raw.status).toBeNull();
    const details = bus.count('flow.detail');
    const g = gate();
    bus.ctl.holdReply.set('f_1', g.promise);

    push(bus, 'response', 'f_1');
    await tick(150); // the flush's fetch is issued; its reply (status null) is computed and held
    expect(bus.count('flow.detail') - details).toBe(1);
    complete(bus, 'f_1'); // the core now has the response

    for (let s = 0; s < 12; s++) {
      bus.emit('notifications/aitm/flow', FLOW_PING); // push stays fresh, so only the 10 s heartbeat polls
      await tick(1000);
    }
    expect(app.byId.get('f_1')!.raw.status).toBe(304); // the heartbeat re-read the pending row

    g.release(); // the older reply lands now
    await tick(50);

    expect(app.byId.get('f_1')!.raw.status).toBe(304);
  });

  it('a cleared event drops pending and in-flight fetches', async () => {
    // (a) pending: queued and cleared in the same tick, nothing is fetched.
    const a = start();
    await tick(200);
    captureSilently(a.bus, 1);
    push(a.bus, 'created', 'f_1');
    a.bus.emit('notifications/aitm/flow', { event: 'cleared', id: '' });
    await tick(300);
    expect(a.bus.callArgs('flow.detail')).toEqual([]);
    expect(a.app.entries).toHaveLength(0);

    // (b) in flight: a reply that lands after `cleared` is discarded, no ghost row.
    const b = start();
    await tick(200);
    captureSilently(b.bus, 1);
    const g = gate();
    b.bus.ctl.holdReply.set('f_1', g.promise);
    push(b.bus, 'created', 'f_1');
    await tick(120);
    expect(b.bus.count('flow.detail')).toBe(1); // in flight
    b.bus.emit('notifications/aitm/flow', { event: 'cleared', id: '' });
    g.release();
    await tick(300);
    expect(b.app.entries).toHaveLength(0);
  });

  it('a response push invalidates cached detail and reloads the selected flow', async () => {
    const bus = bridgeBus();
    captureSilently(bus, 1);
    const { app } = start(bus);
    await tick(200);
    app.select('f_1');
    await tick(50);
    expect(app.details['f_1']).toBeDefined();
    const before = bus.callArgs('flow.detail').length;

    push(bus, 'response', 'f_1');
    await tick(150);

    const since = bus.callArgs('flow.detail').slice(before);
    expect(since).toContainEqual({ id: 'f_1' }); // the inspector reload (no `body`)
    expect(since).toContainEqual({ id: 'f_1', body: 'none' }); // the row refetch
  });

  it('an intercepted push marks the flow paused after the refetch', async () => {
    const { bus, app } = start();
    await tick(200);
    captureSilently(bus, 1);
    bus.flowsById().set('f_1', { ...bus.flowsById().get('f_1')!, intercept: 'paused' });

    push(bus, 'intercepted', 'f_1');
    await tick(50);
    expect(app.proxy.pausedIds).toEqual([]); // not from the push itself
    await tick(100);
    expect(app.proxy.pausedIds).toEqual(['f_1']); // from the refetched row
  });

  it('a released push clears the paused mark', async () => {
    const bus = bridgeBus();
    captureSilently(bus, 1);
    bus.flowsById().set('f_1', { ...bus.flowsById().get('f_1')!, intercept: 'paused' });
    const { app } = start(bus);
    await tick(200);
    expect(app.proxy.pausedIds).toEqual(['f_1']);
    bus.flowsById().set('f_1', { ...bus.flowsById().get('f_1')!, intercept: 'resumed' });

    push(bus, 'released', 'f_1');
    await tick(150);

    expect(app.proxy.pausedIds).toEqual([]);
    expect(app.byId.get('f_1')!.raw.intercept).toBe('resumed');
  });

  it('ws_message pushes refetch only unknown flows', async () => {
    const bus = bridgeBus();
    captureSilently(bus, 1);
    const { app } = start(bus);
    await tick(200);
    const details = bus.count('flow.detail');

    push(bus, 'ws_message', 'f_1'); // known: a chatty socket must not refetch its detail per message
    await tick(150);
    expect(bus.count('flow.detail')).toBe(details);

    captureSilently(bus, 2);
    push(bus, 'ws_message', 'f_2'); // unknown: the first we hear of it
    await tick(150);
    expect(bus.callArgs('flow.detail').slice(details)).toEqual([{ id: 'f_2', body: 'none' }]);
    expect(app.byId.has('f_2')).toBe(true);
  });

  it('the fixtures bus still applies the summary directly', async () => {
    const { bus, app } = start(bridgeBus('fixtures'));
    await tick(200);
    const id = captureSilently(bus, 1);

    bus.emit('notifications/aitm/flow', { event: 'created', id, summary: bus.flowsById().get(id) });
    await tick(0);

    expect(app.byId.has(id)).toBe(true);
    expect(bus.count('flow.detail')).toBe(0);
  });

  it('a flush does nothing while the bus is not open', async () => {
    const { bus, app } = start();
    await tick(200);
    captureSilently(bus, 1);

    push(bus, 'created', 'f_1');
    bus.ctl.setState('reconnecting'); // before the coalescing timer fires
    await tick(500);

    expect(bus.callArgs('flow.detail')).toEqual([]);
    expect(app.entries).toHaveLength(0);
  });

  it('a flush waits for the tool catalogue', async () => {
    const bus = bridgeBus();
    bus.ctl.failToolsOnce = true; // bootstrap gets no catalogue; the loop heals it on its first tick
    start(bus);
    await tick(100);
    captureSilently(bus, 1);

    push(bus, 'created', 'f_1');
    await tick(250);
    expect(bus.count('flow.get')).toBe(0); // not the thinner row either
    expect(bus.count('flow.detail')).toBe(0);

    await tick(1500);

    expect(bus.callArgs('flow.detail')).toContainEqual({ id: 'f_1', body: 'none' });
    expect(bus.count('flow.get')).toBe(0);
  });
});

describe('app store — push and the poll loop together', () => {
  it('with healthy push, flow.list runs only on the heartbeat', async () => {
    const { bus, app } = start();
    await tick(200);
    const lists = bus.count('flow.list');

    for (let s = 0; s < 25; s++) {
      push(bus, 'created', captureSilently(bus, s + 1)); // a capture and its push every second
      await tick(1000);
    }

    expect(bus.count('flow.list') - lists).toBeLessThanOrEqual(3); // the 10 s heartbeats only
    expect(app.proxy.polling).toBe(false);
    expect(app.entries).toHaveLength(25);
    expect(app.entries.every((e) => e.raw.status != null)).toBe(true); // every row came from flow.detail, not the sparse push
  });
});
