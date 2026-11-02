// Unit (c) fix 3: the L4 inspector mounted under a real `AppProvider` (it reads `useApp().bus.role()`).
// Two findings: (I1, quality) the packet selection must derive from the flow prop, not snapshot it
// at mount — under windowed reads the first flow the inspector sees has `packets: []` and the
// window lands later; (I3, spec) AC24's Inject half: on an agent connection Inject is disabled with
// the operator-only reason beside it, a forced click reaches no `onInject`, and the verdict bar
// receives the same reason. Every input is built here; assertions are on the rendered DOM.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import type { BusClient, BusRole } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { memoryBus } from '~/state/bridgeBus.testkit';
import { L4Inspector, type L4InspectorProps } from './L4Inspector';
import type { L4Caps } from './store';
import { l4Row, OPERATOR_ONLY_REASON, type InterceptBarModel, type L4FlowWire, type L4PacketWire, type L4ScopeEntryWire } from './model';

const CAPS: L4Caps = { craft: true, inject: true, capture: true, intercept: true, scope: true, interfaces: true, agentStatus: true, agentSet: true };

/** One scope entry covering `lo0`, so the flow is in scope and only the role gates Inject. */
const LO0_SCOPE: L4ScopeEntryWire[] = [
  { id: 's1', cidr: '127.0.0.1/32', ports: '9000-9999', interface: 'lo0', direction: 'inbound', capability: 'inject', inject_rate: { pps: 100, burst: 100 } },
];

const pkt = (length: number): L4PacketWire => ({ dir: 'inbound', length, injected: false, layers: ['IPv4', 'UDP'], bytes: 'G1tBCn9+QQ==' });

const flow = (id: string, packets: L4PacketWire[]): L4FlowWire => ({
  id,
  kind: 'capture',
  interface: 'lo0',
  filter: null,
  queue: null,
  packet_count: packets.length,
  injected_count: 0,
  packets,
});

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

/** Mount under a provider whose bus resolved `role`; the flow is a signal so the test can move it like the store does. */
function mount(role: BusRole | null, first: L4FlowWire, over: Partial<L4InspectorProps> = {}) {
  const mem = memoryBus();
  bus = { ...mem, role: () => role };
  const app = createAppStore(bus);
  const [f, setFlow] = createSignal(first);
  const handlers = {
    onBuild: vi.fn(async () => ({ length: 2, bytes: 'AAE=', summary: { layers: ['Raw'], length: 2 } })),
    onInject: vi.fn(),
    onForward: vi.fn(),
    onMutate: vi.fn(),
    onDrop: vi.fn(),
    onRevert: vi.fn(),
    onLoadMore: vi.fn(),
  };
  const model: InterceptBarModel = over.interceptModel ?? { kind: 'idle' };
  const r = render(() => (
    <AppProvider store={app}>
      <L4Inspector flow={f()} row={l4Row(f(), LO0_SCOPE)} caps={over.caps ?? CAPS} interceptModel={model} {...handlers} />
    </AppProvider>
  ));
  const layers = () => r.container.querySelector('[aria-label="Packet layers"]');
  const rows = () => [...r.container.querySelectorAll<HTMLElement>('[aria-label="Packets"] [role="listitem"]')];
  const selectedIndex = () => rows().findIndex((el) => el.getAttribute('aria-selected') === 'true');
  const byId = (id: string) => r.container.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`);
  return { r, setFlow, handlers, layers, rows, selectedIndex, byId };
}

describe('L4Inspector: packet selection derives from the flow (I1; spec §2, plan C6)', () => {
  it('a flow that arrives empty and then gets its window auto-selects packet 0 and renders the layer tree', () => {
    const { setFlow, layers, rows, selectedIndex } = mount('operator', flow('F1', []));
    expect(rows()).toHaveLength(0);
    expect(layers()).toBeNull();
    // The inspect window lands (same flow id, two packets).
    setFlow(flow('F1', [pkt(1), pkt(2)]));
    expect(rows()).toHaveLength(2);
    expect(selectedIndex()).toBe(0);
    expect(layers()).not.toBeNull();
    expect(layers()!.textContent).toContain('Layers · 1 bytes');
  });

  it('a click picks another packet, and moving to another flow resets the highlight to packet 0', () => {
    const { setFlow, rows, selectedIndex, layers } = mount('operator', flow('F1', [pkt(1), pkt(2), pkt(3)]));
    expect(selectedIndex()).toBe(0);
    fireEvent.click(rows()[2]!);
    expect(selectedIndex()).toBe(2);
    expect(layers()!.textContent).toContain('Layers · 3 bytes');
    setFlow(flow('F2', [pkt(7), pkt(8)]));
    expect(rows()).toHaveLength(2);
    expect(selectedIndex()).toBe(0);
    expect(layers()!.textContent).toContain('Layers · 7 bytes');
  });

  it('a picked index past the end of the current packets is clamped, never a highlight on nothing', () => {
    const { setFlow, rows, selectedIndex, layers } = mount('operator', flow('F1', [pkt(1), pkt(2), pkt(3)]));
    fireEvent.click(rows()[2]!);
    expect(selectedIndex()).toBe(2);
    setFlow(flow('F1', [pkt(1)]));
    expect(rows()).toHaveLength(1);
    expect(selectedIndex()).toBe(0);
    expect(layers()!.textContent).toContain('Layers · 1 bytes');
  });
});

describe('L4Inspector: agent role gates Inject and the verdicts (I3; spec §7(c) D12, AC24)', () => {
  it('Inject is disabled with the operator-only line beside it, a forced click calls no onInject, and Forward carries the reason', () => {
    const { byId, handlers } = mount('agent', flow('F1', [pkt(1)]), { interceptModel: { kind: 'parked', id: 'P1' } });
    const inject = byId('l4-inject')!;
    expect(inject).not.toBeNull();
    expect(inject.disabled).toBe(true);
    expect(byId('l4-inject-operator-only')!.textContent).toBe('Inject: Operator only: reconnect with the Operator URL the core printed');
    expect(byId('l4-inject-operator-only')!.getAttribute('data-operator-only')).toBe('true');
    // The strongest push a page can give the handler: the DOM click event straight at the button.
    inject.removeAttribute('disabled');
    fireEvent.click(inject);
    expect(handlers.onInject).not.toHaveBeenCalled();
    const forward = byId('l4-forward')!;
    expect(forward.disabled).toBe(true);
    expect(forward.getAttribute('title')).toBe('Operator only: reconnect with the Operator URL the core printed');
    expect(forward.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
    expect(forward.getAttribute('data-operator-only')).toBe('true');
  });

  it('an operator connection in scope has Inject enabled, no operator-only line, and the verdicts live', () => {
    const { byId, r } = mount('operator', flow('F1', [pkt(1)]), { interceptModel: { kind: 'parked', id: 'P1' } });
    expect(byId('l4-inject')!.disabled).toBe(false);
    expect(byId('l4-inject-operator-only')).toBeNull();
    expect(byId('l4-forward')!.disabled).toBe(false);
    expect(r.container.querySelectorAll('[data-operator-only]')).toHaveLength(0);
  });
});
