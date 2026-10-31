// Push as a trigger: on a real bus a `notifications/aitm/flow` line never writes its (sparse) summary
// into the list. It queues the id; a 100 ms coalescer refetches through the same helper the poll uses
// (`flow.detail {id, body:'none'}`, or `flow.get` without the catalogue entry), in waves of 16, under
// the same failure hold-off, with stale replies discarded by ticket and `cleared` by epoch. The
// `fixtures` bus keeps the old direct-apply path. The poll loop itself is covered by
// `app.polling.test.ts`; this file only checks that push and poll coexist (the heartbeat case).

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FlowEventKind } from '~/bus/types';
import { createAppStore } from './app';
import { FLOW_PING, bridgeBus, captureInFlight, captureSilently, complete, gate, tick, type TestBus } from './bridgeBus.testkit';

/**
 * The sparse summary an OLDER core sends with a flow event (`kind:"ws"`, no times, no sizes). A
 * current core sends the full `flow.get` object with `kind:"websocket"`; the store treats either as
 * a trigger, and the old shape is kept here because it is the one a direct apply would corrupt.
 */
const sparse = (id: string) => ({ id, kind: 'ws', method: 'GET', authority: 'x.test', path: '/p', status: null });
const push = (bus: TestBus, event: FlowEventKind, id: string) => bus.emit('notifications/aitm/flow', { event, id, summary: sparse(id) });

let open: TestBus[] = [];
const start = (bus: TestBus = bridgeBus()) => {
  open.push(bus);
  // The real core's flow.detail / flow.get replies carry no `seq`; the fixture flows do, and
  // `toSummary` prefers a reply's own `seq` to the store's position. Strip it, so the `seq`
  // assertions below prove the store's numbering (`entries.length + 1` / the poll's position)
  // and not the fixture's.
  bus.ctl.stripSeq = true;
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
    expect(app.byId.has('f_1')).toBe(false); // the summary itself is never written: no row until the refetch answers
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
    // Not even for an instant: the summary (here the sparse old shape, which a direct apply would
    // corrupt) is never written, so the row is intact before the refetch answers, not merely
    // repaired by it.
    expect(app.byId.get('f_1')!.raw).toEqual(before);
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

  it('a steady stream of pushes is flushed every window, not starved by a debounce', async () => {
    const { bus, app } = start();
    await tick(200);
    const ids = Array.from({ length: 20 }, (_, i) => captureSilently(bus, i + 1)); // (fixture ids are base 36)

    // A new flow every 40 ms for 800 ms. A debounce would re-arm on each push and flush only once the
    // stream went quiet; the throttle's first timer is not re-armed by traffic, so ids[0] lands in ~100 ms.
    for (let i = 0; i < ids.length; i++) {
      push(bus, 'created', ids[i]!);
      await tick(40);
      if (i === 4) expect(app.byId.has(ids[0]!)).toBe(true); // t = 200 ms: the stream is still running
    }
    expect(app.entries.length).toBeLessThan(ids.length); // (and it really is a stream, not one late flush of all 20)
    await tick(300);

    expect(app.entries.map((e) => e.id)).toEqual(ids);
    expect(app.entries.map((e) => e.raw.seq)).toEqual(ids.map((_, i) => i + 1));
  });

  it('a push that names no flow is ignored', async () => {
    const { bus, app } = start();
    await tick(200);

    push(bus, 'created', '');
    bus.emit('notifications/aitm/flow', { event: 'created' });
    await tick(300);

    expect(bus.callArgs('flow.detail')).toEqual([]);
    expect(app.entries).toHaveLength(0);
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

  // The cap is 256 exactly (spec D3): 256 distinct ids all fit, so nothing is left for the poll (push is
  // fresh, the heartbeat is 10 s away) and `flow.list` stays quiet; the 257th is the first one dropped, which
  // sets `backlog` and makes the poll run. Pins both sides of the boundary, not just "300 is too many".
  it('the pending cap is exactly 256 ids: the 257th is left to the poll', async () => {
    const fits = start();
    await tick(200);
    const listsFits = fits.bus.count('flow.list');
    for (let s = 1; s <= 256; s++) push(fits.bus, 'created', captureSilently(fits.bus, s));
    await tick(3000);
    expect(fits.app.entries).toHaveLength(256);
    expect(fits.bus.count('flow.detail')).toBe(256);
    expect(fits.bus.count('flow.list')).toBe(listsFits); // no surplus, no backlog, no poll

    const over = start();
    await tick(200);
    const listsOver = over.bus.count('flow.list');
    for (let s = 1; s <= 257; s++) push(over.bus, 'created', captureSilently(over.bus, s));
    await tick(3000);
    expect(over.app.entries).toHaveLength(257); // the poll delivered the one the coalescer dropped
    expect(over.bus.count('flow.list')).toBeGreaterThan(listsOver);
  });

  // The flush runs from a timer and nobody awaits it: an error thrown while applying a reply (here a row that
  // blows up in `toSummary`) must not escape as an unhandled rejection, and must not wedge the flusher.
  it('an apply that throws does not escape the flush timer or stop later pushes', async () => {
    // The web tsconfig carries no node types; the runner is node, and that is where rejections are reported.
    const proc = (globalThis as unknown as { process: { on(e: 'unhandledRejection', h: (r: unknown) => void): void; off(e: 'unhandledRejection', h: (r: unknown) => void): void } }).process;
    const { bus, app } = start();
    // `start` strips `seq` by spreading each reply (the kit's `withoutSeq`), which would run the getter below inside
    // the bus call, where `.catch` turns it into a failed read: not the apply error this case is about.
    bus.ctl.stripSeq = false;
    await tick(200);
    captureSilently(bus, 1);
    captureSilently(bus, 2);
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => unhandled.push(reason);
    proc.on('unhandledRejection', onUnhandled);
    try {
      bus.ctl.replyWith.set('f_1', {
        id: 'f_1',
        get method(): string {
          throw new Error('toSummary blew up');
        },
      });

      push(bus, 'created', 'f_1');
      await tick(300); // `advanceTimersByTimeAsync` yields to the real event loop between timers, where rejections surface
      await tick(300);
      expect(unhandled).toEqual([]);
      expect(app.byId.has('f_1')).toBe(false);

      // The flusher is free: a later push for a healthy flow is fetched and applied.
      push(bus, 'created', 'f_2');
      await tick(150);
      expect(app.byId.has('f_2')).toBe(true);
    } finally {
      proc.off('unhandledRejection', onUnhandled);
    }
  });

  it('a reply that is not the requested flow makes no row and is held off', async () => {
    const { bus, app } = start();
    await tick(200);
    for (let s = 1; s <= 3; s++) captureSilently(bus, s);
    bus.ctl.replyWith.set('f_1', {}); // a reply with no id at all
    bus.ctl.replyWith.set('f_2', bus.flowsById().get('f_3')); // a reply that is another flow's row

    push(bus, 'created', 'f_1');
    push(bus, 'created', 'f_2');
    await tick(150);

    expect(bus.callArgs('flow.detail')).toEqual([
      { id: 'f_1', body: 'none' },
      { id: 'f_2', body: 'none' },
    ]);
    // Keyed by the id that was asked for: no ghost row `''`, and f_3 is not written under f_2's fetch.
    expect(app.entries).toHaveLength(0);
    expect(app.byId.has('')).toBe(false);
    expect(app.byId.has('f_3')).toBe(false);

    // Both count as failed reads: pushes inside FAILED_RETRY_MS make no further call.
    push(bus, 'created', 'f_1');
    push(bus, 'created', 'f_2');
    await tick(150);
    expect(bus.count('flow.detail')).toBe(2);
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

  it('a cleared event during a multi-wave flush stops the later waves too', async () => {
    // 40 ids are three waves of 16. `cleared` lands while wave 1 is in flight: not only is that wave's
    // reply discarded, waves 2 and 3 are never issued, or they would resurrect 24 rows the operator
    // just cleared.
    const { bus, app } = start();
    await tick(200);
    const ids = Array.from({ length: 40 }, (_, i) => captureSilently(bus, i + 1));
    const g = gate();
    bus.ctl.holdReply.set(ids[0]!, g.promise); // wave 1 cannot complete until released

    for (const id of ids) push(bus, 'created', id);
    await tick(120);
    expect(bus.count('flow.detail')).toBe(16); // wave 1 issued and held

    bus.emit('notifications/aitm/flow', { event: 'cleared', id: '' });
    g.release();
    await tick(300);

    expect(bus.count('flow.detail')).toBe(16); // no further wave
    expect(app.entries).toHaveLength(0);
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
    expect(app.details['f_1']).toBeUndefined(); // stale detail is dropped at once, before the reload answers
    await tick(150);

    const since = bus.callArgs('flow.detail').slice(before);
    expect(since).toContainEqual({ id: 'f_1' }); // the inspector reload (no `body`)
    expect(since).toContainEqual({ id: 'f_1', body: 'none' }); // the row refetch
    expect(app.details['f_1']).toBeDefined(); // and the reload put a fresh one back
  });

  it('a response push drops the cached detail of a flow nobody is inspecting, without reloading it', async () => {
    const bus = bridgeBus();
    captureSilently(bus, 1);
    captureSilently(bus, 2);
    const { app } = start(bus);
    await tick(200);
    app.select('f_1');
    await tick(50);
    app.select('f_2'); // f_2 is the inspected flow now; f_1's detail is still cached
    await tick(50);
    expect(app.details['f_1']).toBeDefined();
    const before = bus.callArgs('flow.detail').length;

    push(bus, 'response', 'f_1');
    expect(app.details['f_1']).toBeUndefined();
    await tick(150);

    const since = bus.callArgs('flow.detail').slice(before);
    expect(since).toEqual([{ id: 'f_1', body: 'none' }]); // the row refetch only: no inspector reload for an unselected flow
    expect(app.details['f_1']).toBeUndefined();
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

  // The fixtures bus keeps the pre-push direct-apply path (spec D3): complete summaries land synchronously
  // and the same post-event work still runs from them (`cleared`, detail invalidation, `pausedIds`).
  describe('on the fixtures bus', () => {
    /** The mock's own flow as the summary of a push: complete and correctly spelled, as the fixtures bus sends it. */
    const fx = (bus: TestBus, event: FlowEventKind, id: string, over: Record<string, unknown> = {}) =>
      bus.emit('notifications/aitm/flow', { event, id, summary: { ...bus.flowsById().get(id), ...over } });

    it('a cleared push empties the list, and a later push applies again', async () => {
      const { bus, app } = start(bridgeBus('fixtures'));
      await tick(200);
      const id = captureSilently(bus, 1);
      fx(bus, 'created', id);
      expect(app.entries.map((e) => e.id)).toEqual([id]);

      bus.emit('notifications/aitm/flow', { event: 'cleared', id: '' });
      expect(app.entries).toHaveLength(0);
      expect(app.byId.size).toBe(0);

      fx(bus, 'created', id);
      expect(app.entries.map((e) => e.id)).toEqual([id]);
    });

    it('a response push drops the cached detail and reloads the inspected flow', async () => {
      const { bus, app } = start(bridgeBus('fixtures'));
      await tick(200);
      const id = captureSilently(bus, 1);
      fx(bus, 'created', id);
      app.select(id);
      await tick(50);
      expect(app.details[id]).toBeDefined();
      const before = bus.callArgs('flow.detail').length;

      fx(bus, 'response', id);
      expect(app.details[id]).toBeUndefined(); // dropped at once, before the reload answers
      await tick(50);

      expect(bus.callArgs('flow.detail').slice(before)).toEqual([{ id }]); // the inspector reload only: no row refetch
      expect(app.details[id]).toBeDefined();
    });

    it('intercepted and released pushes recompute pausedIds from the applied row', async () => {
      const { bus, app } = start(bridgeBus('fixtures'));
      await tick(200);
      const id = captureSilently(bus, 1);
      fx(bus, 'created', id);
      expect(app.proxy.pausedIds).toEqual([]);

      fx(bus, 'intercepted', id, { intercept: 'paused' });
      expect(app.proxy.pausedIds).toEqual([id]); // synchronous: the summary is applied, not fetched

      fx(bus, 'released', id, { intercept: 'resumed' });
      expect(app.proxy.pausedIds).toEqual([]);
      expect(bus.count('flow.detail')).toBe(0);
    });
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

    bus.ctl.setState('open');
    await tick(700); // one tick: the reopened bus takes a fresh snapshot, pending push or not

    expect(app.entries.map((e) => e.id)).toEqual(['f_1']);
  });

  it('a reconnect drops the ids queued for the old socket; the snapshot covers them', async () => {
    const { bus, app } = start();
    await tick(200);
    captureSilently(bus, 1);

    push(bus, 'created', 'f_1'); // queued; the 100 ms timer is armed
    bus.ctl.setState('reconnecting');
    bus.ctl.setState('open'); // back inside the window: the queued id belongs to the connection that is gone
    await tick(150);
    expect(bus.callArgs('flow.detail')).toEqual([]); // the stale timer did not fire a flush

    await tick(700); // the first tick after the reopen takes a fresh snapshot, which finds the flow
    expect(app.entries.map((e) => e.id)).toEqual(['f_1']);
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
  // `pollOnce` and the flush share one fetcher, so they share its id check: a reply names the flow it is for
  // or it is a failed read (no ghost row `''`, no row written under a foreign id), held off like any other.
  it('the poll applies the same id check as the flush', async () => {
    const bus = bridgeBus();
    for (let s = 1; s <= 3; s++) captureSilently(bus, s);
    bus.ctl.replyWith.set('f_1', {}); // no id at all
    bus.ctl.replyWith.set('f_2', { ...bus.flowsById().get('f_3'), id: 'f_zzz' }); // another flow's row
    const { app } = start(bus);

    await tick(1500); // the bootstrap poll and two more ticks

    expect(app.entries.map((e) => e.id)).toEqual(['f_3']); // only the flow that answered as itself
    expect(app.byId.has('')).toBe(false);
    expect(app.byId.has('f_zzz')).toBe(false);
    // Both are held off for FAILED_RETRY_MS: the poll asked once each, not on every 500 ms tick.
    expect(bus.callArgs('flow.detail').filter((a) => a.id === 'f_1')).toHaveLength(1);
    expect(bus.callArgs('flow.detail').filter((a) => a.id === 'f_2')).toHaveLength(1);
  });

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
