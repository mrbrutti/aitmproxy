// Tester (unit (c), pass 2): the inspector panel's confirm path driven through the real
// `L4InspectorPanel` → `L4Inspector` → `L4InterceptBar` tree over a stubbed `L4Store` (the accessors
// the panel reads, and a `call` that answers like the core's confirm-over-the-wire). Two fix-3
// claims the coder covered by inspection only: (1) a dialog the operator dismissed while the
// confirming call was in flight is not re-opened from the stale snapshot when the core's late answer
// lands; (2) while `l4.intercept.status` has not answered, the inspector's bar is exactly the pending
// literal (spec §1), composed through `interceptBarModel` the way the app does it.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@solidjs/testing-library';
import { BusError, type BusClient } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { memoryBus } from '~/state/bridgeBus.testkit';
import { L4InspectorPanel } from './L4InspectorPanel';
import type { L4Caps, L4Store } from './store';
import { l4Row, PENDING_AVAILABILITY, type L4Availability, type L4FlowWire, type L4ParkedWire, type L4ScopeEntryWire } from './model';

const CAPS: L4Caps = { craft: true, inject: true, scope: true, interfaces: true, agentStatus: true, agentSet: true };
const AVAILABLE: L4Availability = { available: true, code: 'available', reason: null };

const LO0_SCOPE: L4ScopeEntryWire[] = [
  { id: 's1', cidr: '127.0.0.1/32', ports: '9000-9999', interface: 'lo0', direction: 'inbound', capability: 'intercept', inject_rate: { pps: 100, burst: 100 } },
];

const FLOW: L4FlowWire = {
  id: 'F1',
  kind: 'intercept',
  interface: 'lo0',
  filter: null,
  queue: 1,
  packet_count: 1,
  injected_count: 0,
  packets: [{ dir: 'inbound', length: 60, injected: false, layers: ['IPv4', 'TCP'], bytes: 'AAE=' }],
};

const PARKED_P1: L4ParkedWire = { id: 'P1', flow: 'F1', state: 'parked', dir: 'inbound', length: 60, layers: ['IPv4', 'TCP'], bytes: 'AAE=' } as L4ParkedWire;

const ENVELOPE = { status: 'needs_confirmation', prompt: 'Forward parked packet P1 (60 bytes) to the wire', confirm_token: 'TOK-1' };

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

/**
 * Mount the panel over a stub store. `call` answers a first-phase verdict with the confirm envelope
 * and hands the confirming call (`_confirm` present) to `answerConfirm`, so the test decides when and
 * how the core answers.
 */
function mount(opts: { intercept?: L4Availability; parked?: L4ParkedWire[] } = {}) {
  const mem = memoryBus();
  bus = { ...mem, role: () => 'operator' as const };
  const app = createAppStore(bus);
  let resolveConfirm!: (v: unknown) => void;
  let rejectConfirm!: (e: Error) => void;
  const confirmAnswer = new Promise<unknown>((res, rej) => {
    resolveConfirm = res;
    rejectConfirm = rej;
  });
  const call = vi.fn(async (tool: string, params: Record<string, unknown> = {}) => {
    if (tool !== 'l4.intercept.forward') throw new BusError(`${tool}: not served by the test store`);
    if (!('_confirm' in params)) return ENVELOPE;
    return confirmAnswer;
  });
  const store = {
    selectedFlow: () => FLOW,
    selectedRow: () => l4Row(FLOW, LO0_SCOPE),
    caps: () => CAPS,
    interceptAvailability: () => opts.intercept ?? AVAILABLE,
    parked: () => opts.parked ?? [PARKED_P1],
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
  const byId = (id: string) => r.container.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`);
  const dialog = () => r.container.querySelector('[role="alertdialog"]');
  const sendToWire = () => [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent === 'Send to wire')!;
  /** Click Forward, wait for the dialog, click Send to wire, wait for the confirming call. */
  async function forwardAndConfirm() {
    fireEvent.click(byId('l4-forward')!);
    await waitFor(() => expect(dialog()).not.toBeNull());
    expect(dialog()!.textContent).toContain(ENVELOPE.prompt);
    fireEvent.click(sendToWire());
    await waitFor(() => expect(call).toHaveBeenCalledTimes(2));
    expect(call.mock.calls[0]).toEqual(['l4.intercept.forward', { id: 'P1' }]);
    expect(call.mock.calls[1]).toEqual(['l4.intercept.forward', { id: 'P1', _confirm: 'TOK-1' }]);
  }
  return { r, app, store, call, byId, dialog, forwardAndConfirm, resolveConfirm, rejectConfirm };
}

describe('L4InspectorPanel.confirm: dialog dismissed while the confirming call is in flight (fix 3)', () => {
  it('a late refusal after the operator dismissed the dialog does not re-open it from the stale snapshot, and shows no refusal', async () => {
    const { r, app, dialog, forwardAndConfirm, rejectConfirm } = mount();
    await forwardAndConfirm();
    // The core has not answered; the operator dismisses the dialog (backdrop click cancels even while busy).
    fireEvent.click(r.container.querySelector('[role="presentation"]')!);
    await waitFor(() => expect(dialog()).toBeNull());
    rejectConfirm(new BusError('late refusal from the core'));
    await new Promise((res) => setTimeout(res, 10));
    expect(dialog()).toBeNull();
    expect(r.container.textContent).not.toContain('late refusal from the core');
    expect(r.container.textContent).not.toContain('Refused by the L4 guard');
    expect(app.toast()).toBeNull();
  });

  it('a late "done" after the dismissal is likewise silent: no toast, no forced refresh from a dialog that is gone', async () => {
    const { r, app, store, dialog, forwardAndConfirm, resolveConfirm } = mount();
    await forwardAndConfirm();
    fireEvent.click(r.container.querySelector('[role="presentation"]')!);
    await waitFor(() => expect(dialog()).toBeNull());
    resolveConfirm(true);
    await new Promise((res) => setTimeout(res, 10));
    expect(dialog()).toBeNull();
    expect(app.toast()).toBeNull();
    expect(store.refresh).not.toHaveBeenCalled();
  });

  it('contrast: a refusal while the dialog is still open is shown verbatim in it, with Send to wire re-enabled', async () => {
    const { r, dialog, forwardAndConfirm, rejectConfirm } = mount();
    await forwardAndConfirm();
    rejectConfirm(new BusError('rate limit exceeded for 127.0.0.1/32'));
    await waitFor(() => expect(r.container.textContent).toContain('Refused by the L4 guard: rate limit exceeded for 127.0.0.1/32'));
    expect(dialog()).not.toBeNull();
    const send = [...dialog()!.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent === 'Send to wire')!;
    expect(send.disabled).toBe(false);
  });

  it('contrast: "done" while the dialog is open closes it, toasts the title, and forces one store refresh', async () => {
    const { app, store, dialog, forwardAndConfirm, resolveConfirm } = mount();
    await forwardAndConfirm();
    resolveConfirm(true);
    await waitFor(() => expect(dialog()).toBeNull());
    expect(app.toast()).toEqual({ text: 'Confirm Forward the parked packet — done', kind: 'info' });
    expect(store.refresh).toHaveBeenCalledWith(true);
  });
});

describe('L4InspectorPanel: the inspector bar while intercept availability is pending (spec §1)', () => {
  it('renders exactly "Reading L4 availability…" as one status line, no limited sentence, no verdict buttons', () => {
    const { r, byId } = mount({ intercept: PENDING_AVAILABILITY, parked: [PARKED_P1] });
    const pending = r.container.querySelectorAll('[data-testid="l4-intercept-pending"]');
    expect(pending).toHaveLength(1);
    expect(pending[0]!.textContent).toBe('Reading L4 availability…');
    expect(r.container.querySelector('[data-testid="l4-intercept-limited"]')).toBeNull();
    expect(r.container.textContent).not.toContain('not available on this core');
    for (const id of ['l4-forward', 'l4-mutate', 'l4-drop', 'l4-revert']) expect(byId(id), id).toBeNull();
  });

  it('once the status answers available with P1 parked, the four verdicts render for P1 and Revert alone is held (unmutated)', () => {
    const { r, byId } = mount({ intercept: AVAILABLE, parked: [PARKED_P1] });
    expect(r.container.querySelector('[data-testid="l4-intercept-pending"]')).toBeNull();
    expect(r.container.querySelector('[data-testid="l4-intercept-parked"]')!.getAttribute('data-parked-id')).toBe('P1');
    expect(byId('l4-forward')!.disabled).toBe(false);
    expect(byId('l4-drop')!.disabled).toBe(false);
    expect(byId('l4-revert')!.disabled).toBe(true);
    expect(byId('l4-revert')!.getAttribute('title')).toBe('Nothing staged to revert');
  });
});
