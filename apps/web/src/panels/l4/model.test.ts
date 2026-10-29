import { describe, expect, it } from 'vitest';
import {
  flowScope,
  flowSubLabel,
  isKnownKind,
  isNeedsConfirm,
  KNOWN_KINDS,
  l4Row,
  l4SessionState,
  l4Target,
  listCmd,
  parsePacketSpec,
  placeholderRow,
  protoSubLabel,
  type L4FlowWire,
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

describe('operator confirm envelope', () => {
  it('detects the needs_confirmation result and ignores a plain success', () => {
    expect(isNeedsConfirm({ status: 'needs_confirmation', prompt: 'Confirm…', confirm_token: 'abc' })).toBe(true);
    expect(isNeedsConfirm({ flow_id: 'f', sent: 1 })).toBe(false);
    expect(isNeedsConfirm(null)).toBe(false);
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
