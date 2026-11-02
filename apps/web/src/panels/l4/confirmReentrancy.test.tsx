// Tester (unit (c), pass 3): the `busy` re-entrancy guard inside `L4InspectorPanel.confirm` (added by
// fix 4) and `CaptureControls.confirmScopeAdd` (present since C7), driven directly. Through the real
// `ConfirmInject` the guard is unreachable: its Send to wire is `disabled` while busy and Solid's
// delegated `onClick` skips a disabled node, so `L4InspectorPanel.test.tsx` / `CaptureControls.test.tsx`
// can only prove the DOM path is closed. Here the dialog is a stub whose button is never disabled, so a
// second click really re-enters the handler, and the assertion is on what goes to the bus: exactly one
// confirming call per handshake.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@solidjs/testing-library';
import { BusError, type BusClient } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { memoryBus } from '~/state/bridgeBus.testkit';
import { L4InspectorPanel } from './L4InspectorPanel';
import { CaptureControls } from './CaptureControls';
import type { GuardedOutcome } from './inject';
import type { L4Caps, L4Store } from './store';
import { l4Row, type L4FlowWire, type L4ParkedWire, type L4ScopeEntryWire } from './model';

vi.mock('./ConfirmInject', () => ({
  // A dialog whose Send is never disabled (plain DOM, native listener): the only way to re-enter `confirm`.
  ConfirmInject: (props: { prompt: string; busy?: boolean; onConfirm: () => void; onCancel: () => void }) => {
    const root = document.createElement('div');
    root.setAttribute('data-testid', 'stub-dialog');
    const send = document.createElement('button');
    send.setAttribute('data-testid', 'stub-send');
    send.textContent = 'send';
    send.addEventListener('click', () => props.onConfirm());
    root.append(send);
    return root;
  },
}));

const CAPS: L4Caps = { craft: true, inject: true, scope: true, interfaces: true, agentStatus: true, agentSet: true };
const LO0_SCOPE: L4ScopeEntryWire[] = [
  { id: 's1', cidr: '127.0.0.1/32', ports: '9000-9999', interface: 'lo0', direction: 'inbound', capability: 'intercept', inject_rate: { pps: 100, burst: 100 } },
];
const FLOW: L4FlowWire = { id: 'F1', kind: 'intercept', interface: 'lo0', filter: null, queue: 1, packet_count: 0, injected_count: 0, packets: [] };
const PARKED_P1 = { id: 'P1', flow: 'F1', state: 'parked', dir: 'inbound', length: 60, layers: ['IPv4', 'TCP'], bytes: 'AAE=' } as L4ParkedWire;
const ENVELOPE = { status: 'needs_confirmation', prompt: 'Forward parked packet P1 (60 bytes) to the wire', confirm_token: 'TOK-1' };

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

function provider() {
  const mem = memoryBus();
  bus = { ...mem, role: () => 'operator' as const };
  return createAppStore(bus);
}

describe('L4InspectorPanel.confirm: the busy guard (fix 4)', () => {
  it('re-entering confirm while the confirming call is out sends no second `_confirm`; the one answer is applied once', async () => {
    const app = provider();
    let resolveConfirm!: (v: unknown) => void;
    const confirmAnswer = new Promise<unknown>((res) => (resolveConfirm = res));
    const call = vi.fn(async (tool: string, params: Record<string, unknown> = {}) => {
      if (tool !== 'l4.intercept.forward') throw new BusError(`${tool}: not served by the test store`);
      return '_confirm' in params ? confirmAnswer : ENVELOPE;
    });
    const store = {
      selectedFlow: () => FLOW,
      selectedRow: () => l4Row(FLOW, LO0_SCOPE),
      caps: () => CAPS,
      interceptAvailability: () => ({ available: true, code: 'available', reason: null }),
      parked: () => [PARKED_P1],
      call,
      refresh: vi.fn(async () => {}),
      craft: vi.fn(),
      loadMore: vi.fn(),
    } as unknown as L4Store;
    const r = render(() => (
      <AppProvider store={app}>
        <L4InspectorPanel store={store} />
      </AppProvider>
    ));
    const byId = (id: string) => r.container.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    fireEvent.click(byId('l4-forward')!);
    await waitFor(() => expect(byId('stub-dialog')).not.toBeNull());
    fireEvent.click(byId('stub-send')!);
    await waitFor(() => expect(call).toHaveBeenCalledTimes(2));
    expect(call.mock.calls[1]).toEqual(['l4.intercept.forward', { id: 'P1', _confirm: 'TOK-1' }]);
    // Re-enter while busy: the stub's button is live, so these reach `confirm()` itself.
    fireEvent.click(byId('stub-send')!);
    fireEvent.click(byId('stub-send')!);
    await new Promise((res) => setTimeout(res, 10));
    expect(call).toHaveBeenCalledTimes(2);
    resolveConfirm(true);
    await waitFor(() => expect(byId('stub-dialog')).toBeNull());
    expect(call).toHaveBeenCalledTimes(2);
    expect(store.refresh).toHaveBeenCalledTimes(1);
    expect(app.toast()).toEqual({ text: 'Confirm Forward the parked packet — done', kind: 'info' });
  });
});

describe('CaptureControls.confirmScopeAdd: the busy guard', () => {
  it('re-entering the scope-add confirm while it is out calls onConfirmAddScope once; the one answer closes the dialog', async () => {
    const app = provider();
    let answer!: (o: GuardedOutcome) => void;
    const onAddScope = vi.fn(async (): Promise<GuardedOutcome> => ({ kind: 'confirm', prompt: 'P', token: 'T' }));
    const onConfirmAddScope = vi.fn(() => new Promise<GuardedOutcome>((res) => (answer = res)));
    const r = render(() => (
      <AppProvider store={app}>
        <CaptureControls
          capture={{ available: true, code: 'available', reason: null }}
          running={[]}
          canScope={true}
          scope={[]}
          tools={[{ name: 'l4.scope.add', confirmable: true }]}
          onStart={vi.fn()}
          onStop={vi.fn()}
          onAddScope={onAddScope}
          onConfirmAddScope={onConfirmAddScope}
        />
      </AppProvider>
    ));
    const byId = (id: string) => r.container.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    fireEvent.submit(byId('l4-scope-add-form')!);
    await waitFor(() => expect(byId('stub-dialog')).not.toBeNull());
    fireEvent.click(byId('stub-send')!);
    await waitFor(() => expect(onConfirmAddScope).toHaveBeenCalledTimes(1));
    expect(onConfirmAddScope).toHaveBeenCalledWith(expect.objectContaining({ cidr: '127.0.0.1/32' }), 'T');
    fireEvent.click(byId('stub-send')!);
    fireEvent.click(byId('stub-send')!);
    await new Promise((res) => setTimeout(res, 10));
    expect(onConfirmAddScope).toHaveBeenCalledTimes(1);
    answer({ kind: 'done', result: 's9' });
    await waitFor(() => expect(byId('stub-dialog')).toBeNull());
    expect(onConfirmAddScope).toHaveBeenCalledTimes(1);
    expect((byId('l4-scope-add') as HTMLButtonElement).disabled).toBe(false);
  });
});
