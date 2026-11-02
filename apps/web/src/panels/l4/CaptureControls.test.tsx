// Tester (unit (c), stage 5): the capture controls and the L4 scope section (tasks C4, C7, C9a;
// spec §1, §3, §7(c); AC18, AC19, AC22, AC24, AC39). The component reads the connection role from
// `useApp().bus.role()`, so it mounts under a real `AppProvider` over the in-memory bus of
// `bridgeBus.testkit`, with the role overridden per case. Every input is built here; the
// assertions are on the rendered DOM and on what the handlers were (not) called with.
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, waitFor } from '@solidjs/testing-library';
import type { BusClient, BusRole } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { memoryBus } from '~/state/bridgeBus.testkit';
import { CaptureControls, type CaptureControlsProps } from './CaptureControls';
import type { GuardedOutcome } from './inject';
import { OPERATOR_ONLY_REASON, PENDING_AVAILABILITY, type L4Availability, type L4ScopeEntryWire } from './model';

const NEEDS_PRIVILEGE: L4Availability = { available: false, code: 'needs_privilege', reason: 'X' };
const AVAILABLE: L4Availability = { available: true, code: 'available', reason: null };
const CONFIRMABLE = [{ name: 'l4.scope.add', confirmable: true }];

const entry = (p: Partial<L4ScopeEntryWire> = {}): L4ScopeEntryWire => ({
  id: 's1',
  cidr: '127.0.0.1/32',
  ports: '9000-9999',
  interface: 'lo0',
  direction: 'inbound',
  capability: 'capture',
  inject_rate: { pps: 100, burst: 100 },
  ...p,
});

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

/** Mount under a provider whose bus resolved `role`; handlers are spies, the add handlers resolve `done` unless overridden. */
function mount(role: BusRole | null, over: Partial<CaptureControlsProps> = {}) {
  const mem = memoryBus();
  bus = { ...mem, role: () => role };
  const app = createAppStore(bus);
  const handlers = {
    onStart: vi.fn(),
    onStop: vi.fn(),
    onAddScope: vi.fn(async (): Promise<GuardedOutcome> => ({ kind: 'done', result: 's2' })),
    onConfirmAddScope: vi.fn(async (): Promise<GuardedOutcome> => ({ kind: 'done', result: 's2' })),
  };
  const props: CaptureControlsProps = {
    capture: AVAILABLE,
    running: [],
    canScope: true,
    scope: [],
    tools: [],
    ...handlers,
    ...over,
  };
  const r = render(() => (
    <AppProvider store={app}>
      <CaptureControls {...props} />
    </AppProvider>
  ));
  const byId = (id: string) => r.container.querySelector<HTMLElement>(`[data-testid="${id}"]`);
  const start = () => byId('l4-capture-start') as HTMLButtonElement | null;
  return { r, handlers, byId, start, app };
}

describe('CaptureControls: Start carries the core reason (AC19, AC33; spec §1)', () => {
  it('unavailable: Start is disabled with the reason as its title and the reason line shows the same text', () => {
    const { start, byId, handlers } = mount('operator', { capture: NEEDS_PRIVILEGE });
    expect(start()).not.toBeNull();
    expect(start()!.disabled).toBe(true);
    expect(start()!.getAttribute('title')).toBe('X');
    expect(byId('l4-capture-reason')!.textContent).toBe('X');
    fireEvent.click(start()!);
    expect(handlers.onStart).not.toHaveBeenCalled();
  });

  it('pending: the shared literal "Reading L4 availability…" is shown and Start is disabled', () => {
    const { start, byId } = mount('operator', { capture: PENDING_AVAILABILITY });
    expect(start()!.disabled).toBe(true);
    expect(byId('l4-capture-reason')!.textContent).toBe('Reading L4 availability…');
    expect(start()!.getAttribute('title')).toBe('Reading L4 availability…');
  });

  it('available: Start is enabled with no reason line, and sends interface + direction from the controls', () => {
    const { r, start, byId, handlers } = mount('operator', { capture: AVAILABLE });
    expect(start()!.disabled).toBe(false);
    expect(start()!.hasAttribute('title')).toBe(false);
    expect(byId('l4-capture-reason')).toBeNull();
    fireEvent.click(start()!);
    expect(handlers.onStart).toHaveBeenCalledWith('lo0', 'inbound');

    const iface = r.container.querySelector<HTMLInputElement>('input[aria-label="Capture interface"]')!;
    fireEvent.input(iface, { target: { value: '  en0 ' } });
    const dir = r.container.querySelector<HTMLSelectElement>('select[aria-label="Capture direction"]')!;
    expect([...dir.options].map((o) => o.value)).toEqual(['inbound', 'outbound']);
    fireEvent.change(dir, { target: { value: 'outbound' } });
    fireEvent.click(start()!);
    expect(handlers.onStart).toHaveBeenLastCalledWith('en0', 'outbound');
    // No free-form BPF filter input anywhere (spec §7(c): the core derives the filter from scope).
    expect(r.container.querySelector('[aria-label*="filter" i]')).toBeNull();
  });

  it('a Stop button per running capture id, each calling onStop with its own id', () => {
    const { r, handlers } = mount('operator', { capture: AVAILABLE, running: ['C1', 'C2'] });
    const stops = [...r.container.querySelectorAll<HTMLButtonElement>('button[aria-label^="Stop capture "]')];
    expect(stops.map((b) => b.getAttribute('aria-label'))).toEqual(['Stop capture C1', 'Stop capture C2']);
    fireEvent.click(stops[1]!);
    expect(handlers.onStop).toHaveBeenCalledTimes(1);
    expect(handlers.onStop).toHaveBeenCalledWith('C2');
    expect(r.container.textContent).toContain('2 active');
  });

  it('with nothing running there is no Stop button and no "active" count', () => {
    const { r } = mount('operator', { capture: AVAILABLE, running: [] });
    expect(r.container.querySelectorAll('button[aria-label^="Stop capture "]')).toHaveLength(0);
    expect(r.container.textContent).not.toContain('active');
  });
});

describe('CaptureControls: scope list and the gated add form (AC22, AC39; spec §3)', () => {
  it('renders each scope entry with its provenance from the core', () => {
    const { r } = mount('operator', { scope: [entry({ id: 'a', source: 'config' }), entry({ id: 'b', ports: '9100-9199', source: 'runtime' })] });
    const rows = [...r.container.querySelectorAll<HTMLElement>('[data-testid="l4-scope-entry"]')];
    expect(rows.map((e) => e.getAttribute('data-source'))).toEqual(['config', 'runtime']);
    expect(rows[0]!.textContent).toContain('lo0 · 127.0.0.1/32:9000-9999 · capture · 100pps');
    expect(rows[0]!.textContent).toContain('config');
    expect(rows[1]!.textContent).toContain('runtime');
  });

  it('says so when l4.scope.list is absent, and when the list is empty', () => {
    const absent = mount('operator', { canScope: false });
    expect(absent.r.container.textContent).toContain('L4 scope is not readable on this core');
    expect(absent.r.container.querySelectorAll('[data-testid="l4-scope-entry"]')).toHaveLength(0);
    cleanup();
    const empty = mount('operator', { canScope: true, scope: [] });
    expect(empty.r.container.textContent).toContain('No L4 scope declared');
  });

  it('no add form when tools/list lacks l4.scope.add, or has it without confirmable: true', () => {
    for (const tools of [[], [{ name: 'l4.scope.add' }], [{ name: 'l4.scope.add', confirmable: false }], [{ name: 'l4.scope.list', confirmable: true }]]) {
      const { byId, r } = mount('operator', { tools });
      expect(byId('l4-scope-add-form'), JSON.stringify(tools)).toBeNull();
      expect(r.container.querySelector('[data-testid="l4-scope-add"]'), JSON.stringify(tools)).toBeNull();
      cleanup();
    }
  });

  it('the add form renders when l4.scope.add is confirmable, and submit sends the draft to onAddScope', async () => {
    const { r, byId, handlers } = mount('operator', { tools: CONFIRMABLE });
    const form = byId('l4-scope-add-form') as HTMLFormElement;
    expect(form).not.toBeNull();
    expect(r.container.querySelectorAll('[data-testid="l4-scope-add-form"]')).toHaveLength(1);
    for (const label of ['Scope CIDR', 'Scope ports', 'Scope interface', 'Scope direction', 'Scope capability']) {
      expect(form.querySelector(`[aria-label="${label}"]`), label).not.toBeNull();
    }
    // Fill the AC5 entry.
    fireEvent.input(form.querySelector('[aria-label="Scope ports"]')!, { target: { value: ' 9100-9199 ' } });
    fireEvent.change(form.querySelector('[aria-label="Scope direction"]')!, { target: { value: 'inbound' } });
    fireEvent.change(form.querySelector('[aria-label="Scope capability"]')!, { target: { value: 'capture' } });
    fireEvent.submit(form);
    await waitFor(() => expect(handlers.onAddScope).toHaveBeenCalledTimes(1));
    expect(handlers.onAddScope).toHaveBeenCalledWith({
      cidr: '127.0.0.1/32',
      ports: '9100-9199',
      interface: 'lo0',
      direction: 'inbound',
      capability: 'capture',
    });
    // A `done` first phase opens no dialog.
    expect(r.container.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it('a needs_confirmation first phase opens the confirm dialog with the core prompt; confirming re-sends the same draft with the token', async () => {
    const { r, byId, handlers } = mount('operator', { tools: CONFIRMABLE });
    handlers.onAddScope.mockResolvedValueOnce({ kind: 'confirm', prompt: 'Add L4 scope 127.0.0.1/32 ports 9100-9199 on lo0 inbound capture', token: 'T-1' });
    const form = byId('l4-scope-add-form') as HTMLFormElement;
    fireEvent.input(form.querySelector('[aria-label="Scope ports"]')!, { target: { value: '9100-9199' } });
    fireEvent.submit(form);
    const dialog = await waitFor(() => {
      const d = r.container.querySelector('[role="alertdialog"]');
      if (!d) throw new Error('no dialog yet');
      return d;
    });
    expect(dialog.textContent).toContain('Confirm L4 scope add');
    expect(dialog.textContent).toContain('Add L4 scope 127.0.0.1/32 ports 9100-9199 on lo0 inbound capture');
    // While pending, the add button is disabled (one handshake at a time).
    expect((byId('l4-scope-add') as HTMLButtonElement).disabled).toBe(true);
    const confirm = [...dialog.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent === 'Send to wire')!;
    expect(confirm).toBeDefined();
    fireEvent.click(confirm);
    await waitFor(() => expect(handlers.onConfirmAddScope).toHaveBeenCalledTimes(1));
    expect(handlers.onConfirmAddScope).toHaveBeenCalledWith(
      { cidr: '127.0.0.1/32', ports: '9100-9199', interface: 'lo0', direction: 'inbound', capability: 'capture' },
      'T-1',
    );
    await waitFor(() => expect(r.container.querySelector('[role="alertdialog"]')).toBeNull());
  });

  it('a refusal from the first phase is shown verbatim as an alert, with no dialog', async () => {
    const { r, byId, handlers } = mount('operator', { tools: CONFIRMABLE });
    handlers.onAddScope.mockResolvedValueOnce({ kind: 'refused', message: 'invalid CIDR: 300.0.0.1/32' });
    fireEvent.submit(byId('l4-scope-add-form')!);
    const alert = await waitFor(() => {
      const a = byId('l4-scope-add-refusal');
      if (!a) throw new Error('no refusal yet');
      return a;
    });
    expect(alert.getAttribute('role')).toBe('alert');
    expect(alert.textContent).toBe('invalid CIDR: 300.0.0.1/32');
    expect(r.container.querySelector('[role="alertdialog"]')).toBeNull();
  });

  it('a refusal on confirm stays in the dialog verbatim and the token is not re-sent silently', async () => {
    const { r, byId, handlers } = mount('operator', { tools: CONFIRMABLE });
    handlers.onAddScope.mockResolvedValueOnce({ kind: 'confirm', prompt: 'P', token: 'T' });
    handlers.onConfirmAddScope.mockResolvedValueOnce({ kind: 'refused', message: 'runtime L4 scope widening is disabled' });
    fireEvent.submit(byId('l4-scope-add-form')!);
    const dialog = await waitFor(() => {
      const d = r.container.querySelector('[role="alertdialog"]');
      if (!d) throw new Error('no dialog yet');
      return d;
    });
    fireEvent.click([...dialog.querySelectorAll<HTMLButtonElement>('button')].find((b) => b.textContent === 'Send to wire')!);
    await waitFor(() => expect(dialog.textContent).toContain('runtime L4 scope widening is disabled'));
    expect(handlers.onConfirmAddScope).toHaveBeenCalledTimes(1);
    expect(r.container.querySelector('[role="alertdialog"]')).not.toBeNull();
  });
});

describe('CaptureControls: agent role (D12, AC24)', () => {
  it('on an agent connection Start is disabled "operator only" even when capture is available, and a forced click sends nothing', () => {
    const { start, byId, handlers } = mount('agent', { capture: AVAILABLE });
    expect(start()!.disabled).toBe(true);
    expect(start()!.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
    expect(start()!.getAttribute('data-operator-only')).toBe('true');
    expect(byId('l4-capture-reason')!.textContent).toBe(OPERATOR_ONLY_REASON);
    fireEvent.click(start()!);
    expect(handlers.onStart).not.toHaveBeenCalled();
  });

  it('Stop and Add L4 scope are disabled "operator only"; a forced submit reaches no handler', async () => {
    const { r, byId, handlers } = mount('agent', { capture: AVAILABLE, running: ['C1'], tools: CONFIRMABLE });
    const stop = r.container.querySelector<HTMLButtonElement>('button[aria-label="Stop capture C1"]')!;
    expect(stop.disabled).toBe(true);
    expect(stop.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
    expect(stop.getAttribute('data-operator-only')).toBe('true');
    fireEvent.click(stop);
    expect(handlers.onStop).not.toHaveBeenCalled();

    const add = byId('l4-scope-add') as HTMLButtonElement;
    expect(add.disabled).toBe(true);
    expect(add.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
    expect(add.getAttribute('data-operator-only')).toBe('true');
    fireEvent.submit(byId('l4-scope-add-form')!);
    await new Promise((res) => setTimeout(res, 10));
    expect(handlers.onAddScope).not.toHaveBeenCalled();
    expect(handlers.onConfirmAddScope).not.toHaveBeenCalled();
  });

  it('an unknown role (no echo) is gated like an agent', () => {
    const { start } = mount(null, { capture: AVAILABLE });
    expect(start()!.disabled).toBe(true);
    expect(start()!.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
  });

  it('the operator-only reason outranks the capture reason on the reason line', () => {
    const { byId } = mount('agent', { capture: NEEDS_PRIVILEGE });
    expect(byId('l4-capture-reason')!.textContent).toBe(OPERATOR_ONLY_REASON);
  });

  it('an operator connection marks nothing operator-only', () => {
    const { r } = mount('operator', { capture: AVAILABLE, running: ['C1'], tools: CONFIRMABLE });
    expect(r.container.querySelectorAll('[data-operator-only]')).toHaveLength(0);
  });
});
