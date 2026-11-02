import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import type { BusClient, BusRole } from '~/bus/types';
import { AppProvider } from '~/state/context';
import { createAppStore } from '~/state/app';
import { memoryBus } from '~/state/bridgeBus.testkit';
import { L4Toggles } from './L4Toggles';
import { OPERATOR_ONLY_REASON, type AgentGates } from '~/panels/l4/model';

let bus: BusClient | null = null;
afterEach(() => {
  cleanup();
  bus?.close();
  bus = null;
});

const gates = (p: Partial<AgentGates> = {}): AgentGates => ({ inject: false, capture: false, intercept: false, widen: false, ...p });

// The switches read the connection role from `useApp().bus.role()`, so every mount is under a real
// `AppProvider` over the in-memory bus (`mountWithRole`, below); these first cases use the operator
// role, where nothing is gated, so they exercise the gate display and the setter only.

describe('toggle_reflects_gate', () => {
  it('each switch reflects the governing l4.allow_agent_* gate', () => {
    const r = mountWithRole('operator', { gates: gates({ capture: true, inject: false }), canSet: true, onSet: () => {} });
    const sw = (cap: string) => r.container.querySelector(`[role="switch"][data-cap="${cap}"]`)!;
    expect(sw('capture').getAttribute('aria-checked')).toBe('true');
    expect(sw('inject').getAttribute('aria-checked')).toBe('false');
    expect(sw('intercept').getAttribute('aria-checked')).toBe('false');
    expect(sw('widen').getAttribute('aria-checked')).toBe('false');
    // All four capabilities are present, in the spec's order.
    expect([...r.container.querySelectorAll('[role="switch"]')].map((s) => s.getAttribute('data-cap'))).toEqual(['capture', 'inject', 'intercept', 'widen']);
  });

  it('toggling a switch sets the opposite of the current gate via l4.agent.set', () => {
    const onSet = vi.fn();
    const r = mountWithRole('operator', { gates: gates({ inject: false }), canSet: true, onSet });
    fireEvent.click(r.container.querySelector('[data-cap="inject"]')!);
    expect(onSet).toHaveBeenCalledWith('inject', true);
  });

  it('is read-only with an honest note when l4.agent.set is absent, and clicking does nothing', () => {
    const onSet = vi.fn();
    const r = mountWithRole('operator', { gates: gates({ inject: true }), canSet: false, onSet });
    const inject = r.container.querySelector('[data-cap="inject"]') as HTMLButtonElement;
    expect(inject.getAttribute('aria-checked')).toBe('true'); // still reflects the real gate
    expect(inject.disabled).toBe(true);
    expect(inject.getAttribute('title')).toContain('config and restart');
    fireEvent.click(inject);
    expect(onSet).not.toHaveBeenCalled();
    expect(r.container.textContent).toContain('config only');
  });

  it('shows an honest unavailable state when the status command is absent', () => {
    const r = mountWithRole('operator', { gates: null, canSet: false, onSet: () => {} });
    expect(r.container.querySelectorAll('[role="switch"]').length).toBe(0);
    expect(r.container.textContent).toContain('does not expose');
  });

  it('always states that an agent cannot flip its own gate', () => {
    const r = mountWithRole('operator', { gates: gates(), canSet: true, onSet: () => {} });
    expect(r.container.textContent).toContain('cannot change its own L4 gates');
  });

  it('requires the provider: a bare mount throws instead of rendering ungated switches (fix 3: no fail-open path)', () => {
    expect(() => render(() => <L4Toggles gates={gates()} canSet onSet={() => {}} />)).toThrow('useApp outside AppProvider');
  });
});

// ---- role gate under a real provider (parity spec §7(c) D12, AC24; task C9a; tester) ----------------
//
// The bus role decides: an `agent` (or unknown) connection must render every switch disabled with
// the one operator-only reason and send nothing, while an `operator` connection keeps the switches
// live.

/** Mount under `AppProvider` over the in-memory bus with its resolved role overridden. */
function mountWithRole(role: BusRole | null, props: { gates: AgentGates | null; canSet: boolean; onSet: (cap: string, allowed: boolean) => void }) {
  const mem = memoryBus();
  bus = { ...mem, role: () => role };
  const app = createAppStore(bus);
  return render(() => (
    <AppProvider store={app}>
      <L4Toggles gates={props.gates} canSet={props.canSet} onSet={props.onSet as never} />
    </AppProvider>
  ));
}

describe('L4Toggles role gate (D12, AC24)', () => {
  it('agent connection: all four switches are disabled "operator only" with the reason as title, and a click sends nothing', () => {
    const onSet = vi.fn();
    const r = mountWithRole('agent', { gates: gates({ capture: true }), canSet: true, onSet });
    const switches = [...r.container.querySelectorAll<HTMLButtonElement>('[role="switch"]')];
    expect(switches.map((s) => s.getAttribute('data-cap'))).toEqual(['capture', 'inject', 'intercept', 'widen']);
    for (const sw of switches) {
      const cap = sw.getAttribute('data-cap')!;
      expect(sw.disabled, cap).toBe(true);
      expect(sw.getAttribute('title'), cap).toBe('Operator only: reconnect with the Operator URL the core printed');
      expect(sw.getAttribute('title'), cap).toBe(OPERATOR_ONLY_REASON);
      expect(sw.getAttribute('data-operator-only'), cap).toBe('true');
      fireEvent.click(sw);
    }
    expect(onSet).not.toHaveBeenCalled();
    // The gate state is still shown truthfully (display is not what is gated).
    expect(switches[0]!.getAttribute('aria-checked')).toBe('true');
    // Each row says why, and the config-only note does not compete with it.
    expect(r.container.querySelectorAll('[role="switch"] ~ label ~ span').length).toBe(4);
    expect(r.container.textContent).toContain('operator only');
    expect(r.container.textContent).not.toContain('config only');
  });

  it('unknown role (no echo yet) is gated like an agent', () => {
    const onSet = vi.fn();
    const r = mountWithRole(null, { gates: gates(), canSet: true, onSet });
    for (const sw of r.container.querySelectorAll<HTMLButtonElement>('[role="switch"]')) {
      expect(sw.disabled).toBe(true);
      expect(sw.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
      fireEvent.click(sw);
    }
    expect(onSet).not.toHaveBeenCalled();
  });

  it('operator connection: the switches are live, carry no operator-only mark, and a click sets the opposite gate', () => {
    const onSet = vi.fn();
    const r = mountWithRole('operator', { gates: gates({ inject: false }), canSet: true, onSet });
    const inject = r.container.querySelector<HTMLButtonElement>('[data-cap="inject"]')!;
    expect(inject.disabled).toBe(false);
    expect(inject.hasAttribute('title')).toBe(false);
    expect(r.container.querySelectorAll('[data-operator-only]')).toHaveLength(0);
    fireEvent.click(inject);
    expect(onSet).toHaveBeenCalledWith('inject', true);
    expect(r.container.textContent).not.toContain('operator only');
  });

  it('operator connection without l4.agent.set keeps the read-only note (the role gate does not hide it)', () => {
    const r = mountWithRole('operator', { gates: gates(), canSet: false, onSet: () => {} });
    const sw = r.container.querySelector<HTMLButtonElement>('[data-cap="widen"]')!;
    expect(sw.disabled).toBe(true);
    expect(sw.getAttribute('title')).toContain('config and restart');
    expect(r.container.textContent).toContain('config only');
  });
});
