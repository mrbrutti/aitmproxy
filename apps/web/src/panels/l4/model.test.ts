import { describe, expect, it } from 'vitest';
import {
  createOnceLog,
  flowScope,
  flowSubLabel,
  interceptBarModel,
  isKnownKind,
  KNOWN_KINDS,
  L4_ACTIVE_MS,
  L4_IDLE_SLOW_MS,
  L4_IDLE_TICK_MS,
  l4PollPlan,
  l4Row,
  l4SessionState,
  l4Target,
  listCmd,
  parsePacketSpec,
  PENDING_AVAILABILITY,
  placeholderRow,
  protoSubLabel,
  type L4Availability,
  type L4FlowWire,
  type L4ParkedWire,
  type L4PollClock,
  type L4ScopeEntryWire,
} from './model';

const scope = (iface: string): L4ScopeEntryWire => ({
  id: 's1',
  cidr: '127.0.0.1/32',
  ports: '0-65535',
  interface: iface,
  direction: 'outbound',
  capability: 'inject',
  inject_rate: { pps: 100, burst: 100 },
});

const flow = (p: Partial<L4FlowWire> = {}): L4FlowWire => ({
  id: 'l4-1',
  kind: 'capture',
  interface: 'lo0',
  filter: null,
  queue: null,
  packet_count: 0,
  injected_count: 0,
  packets: [],
  ...p,
});

describe('flow-kind model', () => {
  it('knows the three descriptor kinds and their list commands', () => {
    expect([...KNOWN_KINDS].sort()).toEqual(['http', 'l4', 'websocket']);
    expect(isKnownKind('l4')).toBe(true);
    expect(isKnownKind('quic')).toBe(false);
    expect(listCmd('l4')).toBe('l4.flow.list');
    expect(listCmd('http')).toBe('flow.list');
    expect(listCmd('quic')).toBe(null);
  });
});

describe('L4 derivations', () => {
  it('derives the transport sub-label from the innermost layer', () => {
    expect(protoSubLabel(['IPv4', 'UDP'])).toBe('UDP');
    expect(protoSubLabel(['IPv4', 'TCP', 'Raw'])).toBe('TCP');
    expect(protoSubLabel(['IPv6', 'ICMPv6'])).toBe('ICMP');
    expect(protoSubLabel(['Ether', 'Raw'])).toBe(null);
  });

  it('renders the session state and target cells', () => {
    expect(l4SessionState('send_recv')).toBe('send/recv');
    expect(l4SessionState('capture')).toBe('capture');
    expect(l4Target({ interface: 'lo0', filter: 'udp port 9', queue: null })).toBe('lo0 · udp port 9');
    expect(l4Target({ interface: 'eth0', filter: null, queue: 7 })).toBe('eth0 · queue 7');
  });

  it('finds the flow-level sub-label across packets', () => {
    expect(flowSubLabel(flow({ packets: [{ dir: 'inbound', length: 4, injected: false, layers: ['IPv4', 'UDP'] }] }))).toBe('UDP');
    expect(flowSubLabel(flow({ packets: [] }))).toBe(null);
  });
});

describe('scope-as-authorization', () => {
  it('is in scope when an entry covers the interface, out otherwise with a reason', () => {
    expect(flowScope(flow({ interface: 'lo0' }), [scope('lo0')]).inScope).toBe(true);
    const out = flowScope(flow({ interface: 'eth1' }), [scope('lo0')]);
    expect(out.inScope).toBe(false);
    expect(out.reason).toContain('eth1');
    const none = flowScope(flow({ interface: 'lo0' }), []);
    expect(none.inScope).toBe(false);
    expect(none.reason).toContain('no L4 scope is declared');
  });

  it('a wildcard scope interface covers any flow', () => {
    expect(flowScope(flow({ interface: 'eth9' }), [scope('*')]).inScope).toBe(true);
  });
});

describe('union rows', () => {
  it('maps an L4 flow to a row with badge, sub-label, counts, and scope', () => {
    const row = l4Row(
      flow({ kind: 'craft', interface: 'lo0', packet_count: 2, injected_count: 1, packets: [{ dir: 'outbound', length: 9, injected: true, layers: ['IPv4', 'UDP'] }] }),
      [scope('lo0')],
    );
    expect(row.badge).toBe('L4');
    expect(row.subLabel).toBe('UDP');
    expect(row.state).toBe('craft');
    expect(row.packetCount).toBe(2);
    expect(row.injectedCount).toBe(1);
    expect(row.inScope).toBe(true);
    expect(row.known).toBe(true);
  });

  it('a placeholder row is labelled and never empty', () => {
    const row = placeholderRow('x1', 'quic');
    expect(row.known).toBe(false);
    expect(row.badge).toBe('QUIC');
    expect(placeholderRow('x2', '').badge).toBe('??');
  });
});

describe('PacketSpec YAML parser', () => {
  it('parses the default block form into the bus spec shape', () => {
    const r = parsePacketSpec(`layers:\n  - ipv4:\n      dst: 127.0.0.1\n  - udp:\n      dst_port: 9\n  - raw: "probe"\n`);
    expect('spec' in r).toBe(true);
    if ('spec' in r) {
      expect(r.spec.layers).toEqual([
        { ipv4: { dst: '127.0.0.1' } },
        { udp: { dst_port: 9 } },
        { raw: [112, 114, 111, 98, 101] },
      ]);
    }
  });

  it('accepts a raw byte array and strips comments', () => {
    const r = parsePacketSpec(`layers:  # the frame\n  - raw: [1, 2, 255]\n`);
    expect(r).toEqual({ spec: { layers: [{ raw: [1, 2, 255] }] } });
  });

  it('reports a clear error for a missing layers key and a bad raw byte', () => {
    expect('error' in parsePacketSpec('foo: bar')).toBe(true);
    const bad = parsePacketSpec(`layers:\n  - raw: [1, 999]\n`);
    expect('error' in bad).toBe(true);
    if ('error' in bad) expect(bad.error).toContain('0–255');
  });
});

// ---- poll plan (parity spec §7(c) "Polling", AC23) -----------------------------------------------

/** Drive the plan the way `store.refresh()` does: one call per 1.5 s timer tick for a minute. */
function driveMinute(idle: boolean): { ticks: number; slows: number; tickTimes: number[] } {
  const clock: L4PollClock = { lastTickAt: null, lastSlowAt: null };
  let ticks = 0;
  let slows = 0;
  const tickTimes: number[] = [];
  for (let now = 0; now < 60_000; now += L4_ACTIVE_MS) {
    const plan = l4PollPlan(now, clock, idle);
    if (plan.tick) {
      ticks++;
      tickTimes.push(now);
      clock.lastTickAt = now;
    }
    if (plan.slow) {
      slows++;
      clock.lastSlowAt = now;
    }
  }
  return { ticks, slows, tickTimes };
}

describe('L4 poll plan', () => {
  it('has the spec intervals', () => {
    expect(L4_ACTIVE_MS).toBe(1500);
    expect(L4_IDLE_TICK_MS).toBe(10_000);
    expect(L4_IDLE_SLOW_MS).toBe(60_000);
  });

  it('idle: 40 timer calls in a minute fire tick 6 times and slow once (20 l4.* calls, ≤ 30)', () => {
    const { ticks, slows, tickTimes } = driveMinute(true);
    expect(ticks).toBe(6);
    expect(slows).toBe(1);
    expect(tickTimes).toEqual([0, 10_500, 21_000, 31_500, 42_000, 52_500]);
    // tick reads l4.flow.list + l4.capture.status + l4.intercept.status; slow reads
    // l4.scope.list + l4.agent.status.
    const calls = ticks * 3 + slows * 2;
    expect(calls).toBe(20);
    expect(calls).toBeLessThanOrEqual(30);
  });

  it('not idle: every one of the 40 timer calls ticks and slows', () => {
    const { ticks, slows } = driveMinute(false);
    expect(ticks).toBe(40);
    expect(slows).toBe(40);
  });

  it('both fire on the first call and are due exactly at the interval', () => {
    expect(l4PollPlan(5, { lastTickAt: null, lastSlowAt: null }, true)).toEqual({ tick: true, slow: true });
    expect(l4PollPlan(9_999, { lastTickAt: 0, lastSlowAt: 0 }, true)).toEqual({ tick: false, slow: false });
    expect(l4PollPlan(10_000, { lastTickAt: 0, lastSlowAt: 0 }, true)).toEqual({ tick: true, slow: false });
    expect(l4PollPlan(60_000, { lastTickAt: 50_000, lastSlowAt: 0 }, true)).toEqual({ tick: true, slow: true });
  });

  it('is pure: it never mutates the clock', () => {
    const clock: L4PollClock = { lastTickAt: null, lastSlowAt: null };
    l4PollPlan(0, clock, true);
    expect(clock).toEqual({ lastTickAt: null, lastSlowAt: null });
  });
});

describe('createOnceLog', () => {
  it('passes each distinct message to the sink once, and clear() lets it log again', () => {
    const seen: string[] = [];
    const once = createOnceLog((m) => seen.push(m));
    for (const m of ['a', 'a', 'b', 'a']) once.log(m);
    expect(seen).toEqual(['a', 'b']);
    once.clear();
    once.log('a');
    expect(seen).toEqual(['a', 'b', 'a']);
  });
});

// ---- intercept bar model (parity spec §4, AC20; task C5) -------------------------------------------

const parkedWire = (id: string, flow: string): L4ParkedWire => ({
  id,
  flow,
  state: 'parked',
  dir: 'inbound',
  length: 60,
  layers: ['IPv4', 'TCP'],
});

const AVAILABLE: L4Availability = { available: true, code: 'available', reason: null };

describe('interceptBarModel', () => {
  it('unavailable intercept is one documented-limited line carrying the core reason', () => {
    expect(interceptBarModel({ available: false, code: 'unsupported_platform', reason: 'Y' }, [], 'F')).toEqual({ kind: 'limited', reason: 'Y' });
  });

  it('unavailable with a parked list still reports limited (no verdict can succeed)', () => {
    expect(interceptBarModel({ available: false, code: 'needs_privilege', reason: 'Z' }, [parkedWire('P1', 'F')], 'F')).toEqual({
      kind: 'limited',
      reason: 'Z',
    });
  });

  it('pending availability is the shared pending literal as a limited line', () => {
    expect(interceptBarModel(PENDING_AVAILABILITY, [], 'F')).toEqual({ kind: 'limited', reason: 'Reading L4 availability…' });
  });

  it('available with a packet parked for the flow names that parked id (never the flow id)', () => {
    expect(interceptBarModel(AVAILABLE, [parkedWire('P1', 'F')], 'F')).toEqual({ kind: 'parked', id: 'P1' });
    // First listed (oldest) for the flow wins.
    expect(interceptBarModel(AVAILABLE, [parkedWire('P0', 'G'), parkedWire('P1', 'F'), parkedWire('P2', 'F')], 'F')).toEqual({ kind: 'parked', id: 'P1' });
  });

  it('available with nothing parked for the flow is idle', () => {
    expect(interceptBarModel(AVAILABLE, [parkedWire('P1', 'G')], 'F')).toEqual({ kind: 'idle' });
    expect(interceptBarModel(AVAILABLE, [], 'F')).toEqual({ kind: 'idle' });
  });

  it('a null reason while unavailable renders as an empty reason string, not "null"', () => {
    expect(interceptBarModel({ available: false, code: null, reason: null }, [], 'F')).toEqual({ kind: 'limited', reason: '' });
  });
});
