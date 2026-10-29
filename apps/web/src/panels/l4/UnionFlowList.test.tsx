import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { UnionFlowList } from './UnionFlowList';
import { l4Row, placeholderRow, summaryRow, type L4FlowWire, type UnionRow } from './model';

afterEach(cleanup);

const l4Flow: L4FlowWire = {
  id: 'l4-1',
  kind: 'craft',
  interface: 'lo0',
  filter: null,
  queue: null,
  packet_count: 3,
  injected_count: 1,
  packets: [{ dir: 'outbound', length: 9, injected: true, layers: ['IPv4', 'UDP'] }],
};

const rows = (): UnionRow[] => [
  summaryRow({ id: 'h1', kind: 'http', method: 'GET', scheme: 'https', authority: 'api.test', path: '/items', status: 200, inScope: true }),
  summaryRow({ id: 'w1', kind: 'websocket', method: 'GET', scheme: 'wss', authority: 'api.test', path: '/ws', status: 101, inScope: true }),
  l4Row(l4Flow, [{ id: 's', cidr: '127.0.0.1/32', ports: '0-65535', interface: 'lo0', direction: 'outbound', capability: 'inject', inject_rate: { pps: 100, burst: 100 } }]),
  placeholderRow('q1', 'quic'),
];

describe('every_kind_renders', () => {
  it('renders an HTTP, a WebSocket, an L4 row and a labelled placeholder for an unknown kind', () => {
    const onSelect = vi.fn();
    const r = render(() => <UnionFlowList rows={rows()} selectedId={null} onSelect={onSelect} />);

    const rowEls = r.container.querySelectorAll('[role="row"][data-id]');
    expect(rowEls.length).toBe(4);
    expect([...rowEls].map((el) => el.getAttribute('data-kind'))).toEqual(['http', 'websocket', 'l4', 'quic']);

    // Each kind carries its badge.
    expect(r.getByText('GET')).toBeTruthy();
    expect(r.getByText('WS')).toBeTruthy();
    expect(r.getByText('L4')).toBeTruthy();
    // L4 sub-label + session state + counts render.
    expect(r.getByText('UDP')).toBeTruthy();
    expect(r.getByText('craft')).toBeTruthy();
    expect(r.container.textContent).toContain('3 pkt');
    expect(r.container.textContent).toContain('1 inj');

    // The unknown kind is a labelled placeholder, never an empty row.
    const placeholder = r.container.querySelector('[data-kind="quic"]')!;
    expect(placeholder.getAttribute('data-known')).toBe('false');
    expect(placeholder.textContent).toContain('QUIC');
    expect(placeholder.textContent).toContain('unsupported kind');
  });

  it('dims an out-of-scope L4 row with the scope reason as its tooltip', () => {
    const outRow = l4Row({ ...l4Flow, interface: 'eth9' }, []);
    const r = render(() => <UnionFlowList rows={[outRow]} selectedId={null} onSelect={() => {}} />);
    const row = r.container.querySelector('[data-kind="l4"]')!;
    expect(row.getAttribute('data-oos')).toBe('true');
    expect(row.getAttribute('title')).toContain('Out of L4 scope');
  });

  it('selects a row on click', () => {
    const onSelect = vi.fn();
    const r = render(() => <UnionFlowList rows={rows()} selectedId={null} onSelect={onSelect} />);
    fireEvent.click(r.container.querySelector('[data-id="l4-1"]')!);
    expect(onSelect).toHaveBeenCalledWith('l4-1');
  });
});
