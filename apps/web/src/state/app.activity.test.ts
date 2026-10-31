// Activity intake (push spec D6, D7): every audit line, pushed on `notifications/aitm/agent` or read
// as the `agent.activity` snapshot, goes through one intake that normalizes the server's wire shape
// to the model the log renders, numbers what it keeps, and keeps the newest ACTIVITY_CAP. Only the
// PUSH path drops this UI's own successful background reads (the bridge echoes every call back to
// us); the snapshot is the primary server's ring, which never holds this UI's calls, so it is never
// filtered. The bridge role is `operator`, so the UI's own origin is `operator`. The push path for
// flows is `app.push.test.ts`.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAppStore } from './app';
import { AGENT_LINE, bridgeBus, tick, type TestBus } from './bridgeBus.testkit';

const T0 = AGENT_LINE.at; // 1730000000000 = 2024-10-27T03:33:20.000Z
/** This UI's own poll, echoed back: unlabelled (the bridge labels nothing), our origin, a background read that succeeded. */
const ownPoll = (i: number) => ({ at: T0 + i, origin: 'operator', client_label: null, command: 'flow.list', args: '{}', result: 'ok' });
/** An operator action: same connection, but what the panel exists to show. */
const ownKill = (i: number) => ({ at: T0 + i, origin: 'operator', client_label: null, command: 'flow.kill', args: `{"id":"f_${i}"}`, result: 'ok' });
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

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
    await tick(200); // bootstrap: the `agent.activity` snapshot is empty here and keeps nothing, so the log is untouched

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

  // The snapshot is the primary server's ring: it holds other transports' calls and never this UI's, so a
  // line in it that LOOKS like our poll is some other client's and is shown (spec D7, third amendment).
  it('the snapshot is normalized and capped but not filtered', async () => {
    const { bus, app } = start();
    await tick(200);

    // 700 wire lines: every seventh looks like this UI's own `flow.list` (100 of them), the other 600
    // are kills numbered k_0 .. k_599 in ring order. All 700 are kept; the newest 500 are wire
    // indices 200 .. 699, which hold 72 of the polls.
    const wire: unknown[] = [];
    let kills = 0;
    for (let i = 0; i < 700; i++) {
      if (i % 7 === 6) wire.push(ownPoll(i));
      else wire.push({ at: T0 + i, origin: 'operator', client_label: null, command: 'flow.kill', args: `{"id":"k_${kills++}"}`, result: 'ok' });
    }
    expect(kills).toBe(600);
    bus.ctl.activityWire = wire;

    const refreshed = app.refreshSide();
    await tick(50); // the side reads answer with the mock's few ms of latency
    await refreshed;

    const list = app.proxy.activity;
    expect(list).toHaveLength(500);
    for (const e of list) expect(e.at).toMatch(ISO);
    expect(list.filter((e) => e.command === 'flow.list')).toHaveLength(72);
    expect(list[0]).toMatchObject({ seq: 201, command: 'flow.kill', args: { id: 'k_172' }, at: new Date(T0 + 200).toISOString() }); // wire index 200: 28 polls before it
    expect(list[499]).toMatchObject({ seq: 700, command: 'flow.list', origin: 'operator', clientLabel: null, args: {}, at: new Date(T0 + 699).toISOString() }); // wire index 699 is a poll
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

  it('a snapshot of only non-audit lines does not wipe the pushed log', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.emit('notifications/aitm/agent', AGENT_LINE);
    expect(app.proxy.activity).toHaveLength(1);
    // Every line normalizes to nothing: approval requests, a line with no command, one with no origin.
    bus.ctl.activityWire = [
      { event: 'approval_requested', command: 'ca.install', args_summary: '{}', prompt: 'x', request_id: 'apr_1' },
      { event: 'approval_requested', command: 'flow.kill', args_summary: '{"id":"f_1"}', prompt: 'y', request_id: 'apr_2' },
      { at: T0, origin: 'mcp', result: 'ok' },
      { at: T0, command: 'flow.kill', result: 'ok' },
    ];

    const refreshed = app.refreshSide();
    await tick(50);
    await refreshed;

    expect(app.proxy.activity).toHaveLength(1);
    expect(app.proxy.activity[0]!.command).toBe('flow.replay');
    expect(app.proxy.activity[0]!.seq).toBe(1);
  });

  // The server's `agent.activity` is the whole ring every time. A refresh must REPLACE the log with it, or
  // every side refresh (a scope edit, a PoC run) would stack another copy of the ring on the last.
  it('a second snapshot replaces the first instead of stacking on it', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.ctl.activityWire = [ownKill(1), ownKill(2), ownKill(3)];

    for (let i = 0; i < 2; i++) {
      const refreshed = app.refreshSide();
      await tick(50);
      await refreshed;
    }

    expect(app.proxy.activity.map((e) => (e.args as { id: string }).id)).toEqual(['f_1', 'f_2', 'f_3']);
  });

  it('a snapshot that is not a list changes nothing', async () => {
    const { bus, app } = start();
    await tick(200);
    bus.emit('notifications/aitm/agent', AGENT_LINE);
    bus.ctl.activityWire = { error: 'not a list' } as unknown as unknown[];

    const refreshed = app.refreshSide();
    await tick(50);
    await refreshed;

    expect(app.proxy.activity).toHaveLength(1);
    expect(app.proxy.activity[0]!.command).toBe('flow.replay');
  });

  // Audit lines carry what other clients sent (`args` echoes an agent's tool arguments), so the intake
  // meets arbitrary shapes: none of these may throw, retain a row, or write anywhere else.
  it('malformed audit lines are ignored', async () => {
    const { bus, app } = start();
    await tick(200);

    for (const junk of [null, undefined, 'flow.list', 42, true, [], [AGENT_LINE], {}, { command: 5, origin: 'mcp', result: 'ok' }, { command: 'flow.kill', result: 'ok' }, { command: '', origin: 'mcp' }]) {
      expect(() => bus.emit('notifications/aitm/agent', junk)).not.toThrow();
    }

    expect(app.proxy.activity).toEqual([]);
  });

  it('hostile args are kept as data and pollute nothing', async () => {
    const { bus, app } = start();
    await tick(200);

    bus.emit('notifications/aitm/agent', { ...AGENT_LINE, args: '{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}' });
    bus.emit('notifications/aitm/agent', { ...AGENT_LINE, args: '['.repeat(200_000) }); // far deeper than any parser will take: stays text
    bus.emit('notifications/aitm/agent', { ...AGENT_LINE, args: 'x'.repeat(1_000_000), result: { error: 'y'.repeat(100_000) } });

    expect(app.proxy.activity).toHaveLength(3);
    expect(typeof app.proxy.activity[1]!.args).toBe('string');
    expect(app.proxy.activity[2]!.result).toBe('error');
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(false);
  });
});
