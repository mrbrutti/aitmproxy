import { describe, expect, it } from 'vitest';
import {
  asciiColumn,
  createOnceLog,
  flowGetArgs,
  flowScope,
  flowSubLabel,
  formatPacketTime,
  hexRows,
  httpVerbAllowed,
  interceptBarModel,
  isKnownKind,
  isL4Chip,
  l4ChipMatches,
  KNOWN_KINDS,
  L4_ACTIVE_MS,
  L4_IDLE_SLOW_MS,
  L4_IDLE_TICK_MS,
  l4PollPlan,
  l4Row,
  l4SessionState,
  l4Target,
  listCmd,
  OPERATOR_ONLY_REASON,
  operatorOnlyReason,
  packetHeadline,
  parsePacketSpec,
  PENDING_AVAILABILITY,
  placeholderRow,
  protoSubLabel,
  type L4Availability,
  type L4FlowWire,
  type L4PacketWire,
  type L4ParkedWire,
  type L4PollClock,
  type L4ScopeEntryWire,
} from './model';
import { CHIPS } from '~/shell/chips';

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

  it('takes the flow-level proto first: list rows are read with limit 0 and carry no packets (spec §2)', () => {
    expect(flowSubLabel(flow({ proto: 'UDP', packets: [] }))).toBe('UDP');
    expect(flowSubLabel(flow({ proto: 'TCP', packets: [] }))).toBe('TCP');
    expect(flowSubLabel(flow({ proto: 'ICMP', packets: [] }))).toBe('ICMP');
    expect(flowSubLabel(flow({ proto: 'ICMPv6', packets: [] }))).toBe('ICMP');
    // An unknown or null flow proto falls back to the packet scan.
    expect(flowSubLabel(flow({ proto: null, packets: [{ dir: 'inbound', length: 4, injected: false, layers: ['IPv4', 'TCP'] }] }))).toBe('TCP');
    expect(flowSubLabel(flow({ proto: 'SCTP', packets: [] }))).toBe(null);
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

// ---- packet display (task C6; spec §2, §2.3; AC40) ---------------------------------------------------

describe('packetHeadline (spec §2 addresses)', () => {
  const pkt: L4PacketWire = {
    dir: 'outbound',
    length: 36,
    injected: false,
    layers: ['IPv4', 'UDP'],
    proto: 'UDP',
    src: '127.0.0.1',
    dst: '127.0.0.1',
    src_port: 40000,
    dst_port: 9053,
  };

  it('renders src:port → dst:port · proto · length when the addresses are present', () => {
    expect(packetHeadline(pkt)).toBe('127.0.0.1:40000 → 127.0.0.1:9053 · UDP · 36 B');
  });

  it('falls back to the layer summary when the addresses are null (undecodable or older core)', () => {
    expect(packetHeadline({ ...pkt, src: null, dst: null, src_port: null, dst_port: null })).toBe('IPv4 · UDP · 36 B');
    expect(packetHeadline({ dir: 'inbound', length: 2, injected: false, layers: [] })).toBe('raw · 2 B');
  });

  it('appends ports only when they are non-null (ICMP has addresses but no ports)', () => {
    expect(packetHeadline({ ...pkt, layers: ['IPv4', 'ICMP'], proto: 'ICMP', src_port: null, dst_port: null, length: 84 })).toBe(
      '127.0.0.1 → 127.0.0.1 · ICMP · 84 B',
    );
  });

  it('adds proto to the layer summary only when it is not already the innermost layer', () => {
    expect(packetHeadline({ ...pkt, src: null, dst: null, layers: ['Ether', 'IPv4'], proto: 'TCP' })).toBe('Ether · IPv4 · TCP · 36 B');
  });
});

describe('formatPacketTime (spec §2 timestamp)', () => {
  it('renders local HH:MM:SS.mmm with padded fields', () => {
    const shaped = formatPacketTime(1_761_900_000_007);
    expect(shaped).toMatch(/^\d{2}:\d{2}:\d{2}\.\d{3}$/);
    expect(shaped.endsWith('.007')).toBe(true);
    // The hour/minute/second match what the local clock says for that instant.
    const d = new Date(1_761_900_000_007);
    const hh = String(d.getHours()).padStart(2, '0');
    const mm = String(d.getMinutes()).padStart(2, '0');
    const ss = String(d.getSeconds()).padStart(2, '0');
    expect(shaped).toBe(`${hh}:${mm}:${ss}.007`);
  });
});

describe('inert hex/ASCII renderer (spec §2.3, AC40)', () => {
  const ac40 = Uint8Array.of(0x1b, 0x5b, 0x41, 0x0a, 0x7f, 0x7e, 0x41);

  it('asciiColumn maps every byte outside 0x20–0x7e to "."', () => {
    expect(asciiColumn(ac40)).toBe('.[A..~A');
    expect(asciiColumn(Uint8Array.of(0x20, 0x7e, 0x7f, 0x1f, 0x00, 0xff))).toBe(' ~....');
    expect(asciiColumn(new Uint8Array(0))).toBe('');
  });

  it('hexRows renders one 16-byte row with offset, hex and the ASCII column, with no control character', () => {
    const rows = hexRows(ac40);
    expect(rows).toEqual(['00000000  1b 5b 41 0a 7f 7e 41                              |.[A..~A|']);
    for (const row of rows) for (const ch of row) expect(ch.charCodeAt(0)).toBeGreaterThanOrEqual(0x20);
  });

  it('hexRows splits at 16 bytes with the extra gap after the 8th byte and 8-digit offsets', () => {
    const bytes = new Uint8Array(20);
    for (let i = 0; i < 20; i++) bytes[i] = 0x40 + i;
    const rows = hexRows(bytes);
    expect(rows).toEqual([
      '00000000  40 41 42 43 44 45 46 47  48 49 4a 4b 4c 4d 4e 4f  |@ABCDEFGHIJKLMNO|',
      '00000010  50 51 52 53                                       |PQRS|',
    ]);
    expect(hexRows(new Uint8Array(0))).toEqual([]);
    const all = new Uint8Array(256);
    for (let i = 0; i < 256; i++) all[i] = i;
    for (const row of hexRows(all)) for (const ch of row) expect(ch.charCodeAt(0)).toBeGreaterThanOrEqual(0x20);
  });
});

describe('flowGetArgs offset (load more from next_offset)', () => {
  it('an inspect read may start at next_offset; the C1 defaults are unchanged', () => {
    expect(flowGetArgs('F', 'inspect', true, 69)).toEqual({ id: 'F', offset: 69, limit: 256 });
    expect(flowGetArgs('F', 'inspect', true)).toEqual({ id: 'F', offset: 0, limit: 256 });
    expect(flowGetArgs('F', 'list', true, 69)).toEqual({ id: 'F', limit: 0 });
    expect(flowGetArgs('F', 'inspect', false, 69)).toEqual({ id: 'F' });
  });
});

describe('TCP / UDP / L4 chips (spec §7(c), AC21)', () => {
  it('the bar reads All | HTTP HTTPS WebSocket | TCP UDP L4 | h1 h2, so ⌘5 is TCP', () => {
    expect(CHIPS.map((c) => c.label).slice(0, 9)).toEqual(['All', 'HTTP', 'HTTPS', 'WebSocket', 'TCP', 'UDP', 'L4', 'h1', 'h2']);
    expect(CHIPS[4]!.id).toBe('tcp');
    expect(CHIPS[5]!.id).toBe('udp');
    expect(CHIPS[6]!.id).toBe('l4');
  });

  it('TCP UDP L4 are their own group and h1 keeps its separator', () => {
    expect(CHIPS[4]!.group).toBe(true);
    expect(CHIPS[5]!.group).toBeFalsy();
    expect(CHIPS[6]!.group).toBeFalsy();
    expect(CHIPS[7]!.group).toBe(true);
  });

  it('isL4Chip names exactly tcp, udp and l4', () => {
    expect(isL4Chip('tcp')).toBe(true);
    expect(isL4Chip('udp')).toBe(true);
    expect(isL4Chip('l4')).toBe(true);
    expect(isL4Chip('http')).toBe(false);
    expect(isL4Chip('all')).toBe(false);
  });

  it('l4ChipMatches: l4 matches every L4 row, tcp/udp by sub-label, any other chip never', () => {
    expect(l4ChipMatches('tcp', { subLabel: 'TCP' })).toBe(true);
    expect(l4ChipMatches('udp', { subLabel: 'TCP' })).toBe(false);
    expect(l4ChipMatches('udp', { subLabel: 'UDP' })).toBe(true);
    expect(l4ChipMatches('tcp', { subLabel: 'UDP' })).toBe(false);
    expect(l4ChipMatches('l4', { subLabel: 'UDP' })).toBe(true);
    expect(l4ChipMatches('l4', { subLabel: null })).toBe(true);
    expect(l4ChipMatches('tcp', { subLabel: null })).toBe(false);
    expect(l4ChipMatches('http', { subLabel: 'TCP' })).toBe(false);
    expect(l4ChipMatches('all', { subLabel: 'TCP' })).toBe(false);
  });
});

describe('operatorOnlyReason (spec §7(c) D12, AC24)', () => {
  it('an operator connection has no reason: every Sensitive L4 control stays live', () => {
    expect(operatorOnlyReason('operator')).toBeNull();
  });

  it('an agent connection gets the one operator-only reason, verbatim', () => {
    expect(operatorOnlyReason('agent')).toBe('Operator only: reconnect with the Operator URL the core printed');
  });

  it('an unknown role (no echo yet, or a disconnect) is gated like an agent, not like an operator', () => {
    expect(operatorOnlyReason(null)).toBe('Operator only: reconnect with the Operator URL the core printed');
  });

  it('the exported literal is the reason the components render as title and text', () => {
    expect(OPERATOR_ONLY_REASON).toBe('Operator only: reconnect with the Operator URL the core printed');
    expect(operatorOnlyReason('agent')).toBe(OPERATOR_ONLY_REASON);
  });
});

describe('httpVerbAllowed (spec §7(c) D9 UI, AC33)', () => {
  it('an L4 id gets no HTTP verb: replay, mark, comment, PoC return before any bus call', () => {
    expect(httpVerbAllowed('l4-1', new Set(['l4-1']))).toBe(false);
  });

  it('an HTTP id keeps its verbs even when L4 ids are present', () => {
    expect(httpVerbAllowed('h-1', new Set(['l4-1']))).toBe(true);
  });

  it('with no L4 ids every id is an HTTP id', () => {
    expect(httpVerbAllowed('h-1', new Set())).toBe(true);
  });
});
