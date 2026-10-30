import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render } from '@solidjs/testing-library';
import { L4FlowRow } from './L4FlowRow';
import { createColumnState } from './columns';
import { l4Row, placeholderRow, type L4FlowWire, type L4ScopeEntryWire } from '~/panels/l4/model';

afterEach(cleanup);

const scope: L4ScopeEntryWire[] = [
  { id: 's', cidr: '127.0.0.1/32', ports: '0-65535', interface: 'lo0', direction: 'outbound', capability: 'inject', inject_rate: { pps: 100, burst: 100 } },
];

const flow: L4FlowWire = {
  id: 'l4-1',
  kind: 'capture',
  interface: 'lo0',
  filter: 'udp port 9',
  queue: null,
  packet_count: 12,
  injected_count: 2,
  packets: [{ dir: 'outbound', length: 42, injected: false, layers: ['IPv4', 'UDP', 'Raw'] }],
};

describe('L4FlowRow', () => {
  it('renders an L4 session across the shared columns: badge, sub-label, target, state, counts', () => {
    const r = render(() => <L4FlowRow row={l4Row(flow, scope)} seq={3} cols={createColumnState(null)} selected={false} />);
    const row = r.container.querySelector('[role="row"][data-id="l4-1"]')!;
    expect(row.getAttribute('data-kind')).toBe('l4');
    expect(row.getAttribute('data-oos')).toBeNull(); // lo0 is in scope
    // badge + transport sub-label (method column), target (url column), session state (status column)
    expect(r.getByText('L4')).toBeTruthy();
    expect(r.getByText('UDP')).toBeTruthy();
    expect(row.textContent).toContain('lo0 · udp port 9');
    expect(row.textContent).toContain('capture');
    // counts: packets in the request column, injected in the response column
    expect(row.textContent).toContain('12 pkt');
    expect(row.textContent).toContain('2 inj');
    // the # cell shows the passed sequence
    expect(row.textContent).toContain('3');
  });

  it('dims an out-of-scope session and carries the scope reason as its tooltip', () => {
    const r = render(() => <L4FlowRow row={l4Row({ ...flow, interface: 'en0' }, scope)} seq={1} cols={createColumnState(null)} selected={false} />);
    const row = r.container.querySelector('[data-kind="l4"]')!;
    expect(row.getAttribute('data-oos')).toBe('true');
    expect(row.getAttribute('title')).toContain('Out of L4 scope');
  });

  it('renders a labelled placeholder for a session whose detail has not loaded, never an empty row', () => {
    const r = render(() => <L4FlowRow row={placeholderRow('l4-x', 'l4')} seq={1} cols={createColumnState(null)} selected={false} />);
    const row = r.container.querySelector('[data-kind="l4"]')!;
    expect(row.textContent).toContain('this surface has no renderer');
    // no pkt/inj counts for an unknown row — a dash instead
    expect(row.textContent).not.toContain('pkt');
  });
});
