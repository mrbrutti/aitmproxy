import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { L4Toggles } from './L4Toggles';
import type { AgentGates } from '~/panels/l4/model';

afterEach(cleanup);

const gates = (p: Partial<AgentGates> = {}): AgentGates => ({ inject: false, capture: false, intercept: false, widen: false, ...p });

describe('toggle_reflects_gate', () => {
  it('each switch reflects the governing l4.allow_agent_* gate', () => {
    const r = render(() => <L4Toggles gates={gates({ capture: true, inject: false })} canSet onSet={() => {}} />);
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
    const r = render(() => <L4Toggles gates={gates({ inject: false })} canSet onSet={onSet} />);
    fireEvent.click(r.container.querySelector('[data-cap="inject"]')!);
    expect(onSet).toHaveBeenCalledWith('inject', true);
  });

  it('is read-only with an honest note when l4.agent.set is absent, and clicking does nothing', () => {
    const onSet = vi.fn();
    const r = render(() => <L4Toggles gates={gates({ inject: true })} canSet={false} onSet={onSet} />);
    const inject = r.container.querySelector('[data-cap="inject"]') as HTMLButtonElement;
    expect(inject.getAttribute('aria-checked')).toBe('true'); // still reflects the real gate
    expect(inject.disabled).toBe(true);
    expect(inject.getAttribute('title')).toContain('config and restart');
    fireEvent.click(inject);
    expect(onSet).not.toHaveBeenCalled();
    expect(r.container.textContent).toContain('config only');
  });

  it('shows an honest unavailable state when the status command is absent', () => {
    const r = render(() => <L4Toggles gates={null} canSet={false} onSet={() => {}} />);
    expect(r.container.querySelectorAll('[role="switch"]').length).toBe(0);
    expect(r.container.textContent).toContain('does not expose');
  });

  it('always states that an agent cannot flip its own gate', () => {
    const r = render(() => <L4Toggles gates={gates()} canSet onSet={() => {}} />);
    expect(r.container.textContent).toContain('cannot change its own L4 gates');
  });
});
