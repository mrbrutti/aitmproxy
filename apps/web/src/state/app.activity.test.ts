// Activity intake (push spec D6, D7): every audit line, pushed on `notifications/aitm/agent` or read
// as the `agent.activity` snapshot, goes through one intake that normalizes the server's wire shape
// to the model the log renders, drops this UI's own successful background reads (the bridge echoes
// every call back to us), numbers what it keeps, and keeps the newest ACTIVITY_CAP. The bridge role
// is `operator`, so the UI's own origin is `operator`. The push path for flows is `app.push.test.ts`.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAppStore } from './app';
import { bridgeBus, type TestBus } from './bridgeBus.testkit';

const T0 = 1730000000000; // 2024-10-27T03:33:20.000Z
/** An audit line as the server sends it: epoch ms, `client_label`, `args` as redacted JSON text. */
const AGENT_LINE = { at: T0, origin: 'mcp', client_label: 'claude-code', command: 'flow.replay', args: '{"id":"f_1"}', result: 'ok' };
/** This UI's own poll, echoed back: unlabelled (the bridge labels nothing), our origin, a background read that succeeded. */
const ownPoll = (i: number) => ({ at: T0 + i, origin: 'operator', client_label: null, command: 'flow.list', args: '{}', result: 'ok' });
/** An operator action: same connection, but what the panel exists to show. */
const ownKill = (i: number) => ({ at: T0 + i, origin: 'operator', client_label: null, command: 'flow.kill', args: `{"id":"f_${i}"}`, result: 'ok' });
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
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
  for (const b of open) b.close();
  open = [];
  vi.useRealTimers();
});

describe('app store — activity intake', () => {
  it('a pushed audit line is normalized', async () => {
    const { bus, app } = start();
    await tick(200); // bootstrap: the snapshot (empty here) has replaced the log

    bus.emit('notifications/aitm/agent', AGENT_LINE);

    expect(app.proxy.activity).toEqual([
      { seq: 1, at: '2024-10-27T03:33:20.000Z', origin: 'mcp', clientLabel: 'claude-code', command: 'flow.replay', args: { id: 'f_1' }, result: 'ok' },
    ]);
  });

  it("the UI's own polling is dropped but actions and agent lines are kept", async () => {
    const { bus, app } = start();
    await tick(200);

    for (let i = 0; i < 200; i++) bus.emit('notifications/aitm/agent', ownPoll(i));
    expect(app.proxy.activity).toEqual([]);

    bus.emit('notifications/aitm/agent', ownKill(1));
    bus.emit('notifications/aitm/agent', AGENT_LINE);
    expect(app.proxy.activity).toHaveLength(2);
    expect(app.proxy.activity.map((e) => e.command)).toEqual(['flow.kill', 'flow.replay']);
    // Dropped lines take no number: what is shown is numbered 1, 2, ...
    expect(app.proxy.activity.map((e) => e.seq)).toEqual([1, 2]);
  });

  it('the log is capped at 500, newest', async () => {
    const { bus, app } = start();
    await tick(200);

    for (let i = 0; i < 600; i++) bus.emit('notifications/aitm/agent', ownKill(i));

    const list = app.proxy.activity;
    expect(list).toHaveLength(500);
    expect((list[0]!.args as { id: string }).id).toBe('f_100');
    expect((list[499]!.args as { id: string }).id).toBe('f_599');
    expect(list[0]!.seq).toBe(101);
    expect(list[499]!.seq).toBe(600);
  });

  it('an approval request line is ignored', async () => {
    const { bus, app } = start();
    await tick(200);

    bus.emit('notifications/aitm/agent', { event: 'approval_requested', command: 'ca.install', args_summary: '{}', prompt: 'x', request_id: 'apr_1' });

    expect(app.proxy.activity).toHaveLength(0);
  });

  it('the snapshot is normalized, filtered and capped', async () => {
    const { bus, app } = start();
    await tick(200);

    // 700 wire lines: every seventh is this UI's own `flow.list` (100 of them), the other 600 are
    // kept; the kept ones are numbered k_0 .. k_599 in ring order.
    const wire: unknown[] = [];
    let kept = 0;
    for (let i = 0; i < 700; i++) {
      if (i % 7 === 6) wire.push(ownPoll(i));
      else wire.push({ at: T0 + i, origin: 'operator', client_label: null, command: 'flow.kill', args: `{"id":"k_${kept++}"}`, result: 'ok' });
    }
    expect(kept).toBe(600);
    bus.ctl.activityWire = wire;

    const refreshed = app.refreshSide();
    await tick(50); // the side reads answer with the mock's few ms of latency
    await refreshed;

    const list = app.proxy.activity;
    expect(list).toHaveLength(500);
    for (const e of list) expect(e.at).toMatch(ISO);
    expect(list.some((e) => e.command === 'flow.list')).toBe(false);
    expect((list[0]!.args as { id: string }).id).toBe('k_100');
    expect((list[499]!.args as { id: string }).id).toBe('k_599');
    expect(list[0]!.at).toBe(new Date(T0 + 116).toISOString()); // k_100 is wire index 116 (100 + 16 polls before it)
  });

  // Over `aitm web` the ring `agent.activity` reads is empty (the web server's own ring is not the one
  // it reads), so the log is fed by push alone there; a snapshot that keeps nothing must not replace it,
  // or every side refresh (scope.add, poc.run, the catalogue heal) wipes the Activity panel.
  it('an empty snapshot does not wipe the pushed log', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.emit('notifications/aitm/agent', AGENT_LINE);
    expect(app.proxy.activity).toHaveLength(1);
    bus.ctl.activityWire = [];

    const refreshed = app.refreshSide();
    await tick(50);
    await refreshed;

    expect(app.proxy.activity).toHaveLength(1);
    expect(app.proxy.activity[0]).toEqual({ seq: 1, at: '2024-10-27T03:33:20.000Z', origin: 'mcp', clientLabel: 'claude-code', command: 'flow.replay', args: { id: 'f_1' }, result: 'ok' });
  });

  it('a snapshot of only noise does not wipe the pushed log', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.emit('notifications/aitm/agent', AGENT_LINE);
    expect(app.proxy.activity).toHaveLength(1);
    bus.ctl.activityWire = [0, 1, 2, 3, 4].map(ownPoll);

    const refreshed = app.refreshSide();
    await tick(50);
    await refreshed;

    expect(app.proxy.activity).toHaveLength(1);
    expect(app.proxy.activity[0]!.command).toBe('flow.replay');
    expect(app.proxy.activity[0]!.seq).toBe(1);
  });
});
