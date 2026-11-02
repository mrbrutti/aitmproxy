// Tester (unit (c), stage 5): the intercept bar renders from `interceptBarModel` (spec §4, AC20)
// and is role-gated (spec §7(c) D12, AC24). The bar has no provider dependency, so it mounts bare
// with the model built here. Every verdict must carry the parked id, never a flow id; the limited
// model must be exactly one line and no verdict button (AC33: nothing that can only fail).
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { L4InterceptBar, InterceptLimitedLine } from './L4InterceptBar';
import { OPERATOR_ONLY_REASON, type InterceptBarModel } from './model';

afterEach(cleanup);

const VERDICTS = ['l4-forward', 'l4-mutate', 'l4-drop', 'l4-revert'] as const;

function mount(model: InterceptBarModel, over: Partial<Parameters<typeof L4InterceptBar>[0]> = {}) {
  const handlers = { onForward: vi.fn(), onMutate: vi.fn(), onDrop: vi.fn(), onRevert: vi.fn() };
  const r = render(() => (
    <L4InterceptBar model={model} inScope scopeReason="out of scope" mutateBlocked={null} operatorOnly={null} {...handlers} {...over} />
  ));
  const byId = (id: string) => r.container.querySelector<HTMLButtonElement>(`[data-testid="${id}"]`);
  return { r, handlers, byId };
}

describe('L4InterceptBar: documented-limited line (AC20, AC33)', () => {
  it('the limited model is exactly one line carrying the core reason and zero verdict buttons', () => {
    const { r, byId } = mount({ kind: 'limited', reason: 'Y' });
    const limited = r.container.querySelectorAll('[data-testid="l4-intercept-limited"]');
    expect(limited).toHaveLength(1);
    expect(limited[0]!.textContent).toBe('In-path intercept is not available on this core: Y');
    expect(limited[0]!.getAttribute('role')).toBe('status');
    for (const id of VERDICTS) expect(byId(id), id).toBeNull();
    expect(r.container.querySelectorAll('button')).toHaveLength(0);
    expect(r.container.querySelector('[data-testid="l4-intercept-parked"]')).toBeNull();
    expect(r.container.querySelector('[data-testid="l4-intercept-idle"]')).toBeNull();
  });

  it('the shared InterceptLimitedLine renders the reason as text (the L4 focus view uses it too)', () => {
    const r = render(() => <InterceptLimitedLine reason="in-path interception is unsupported on macOS" />);
    expect(r.container.textContent).toBe('In-path intercept is not available on this core: in-path interception is unsupported on macOS');
    expect(r.container.querySelector('[data-limited="true"]')).not.toBeNull();
  });

  it('a reason with markup-looking text stays text, never elements (spec §2.3 inert text)', () => {
    const r = render(() => <InterceptLimitedLine reason={'<b>x</b><img src=x onerror=alert(1)>'} />);
    expect(r.container.querySelector('b')).toBeNull();
    expect(r.container.querySelector('img')).toBeNull();
    expect(r.container.textContent).toContain('<b>x</b><img src=x onerror=alert(1)>');
  });

  it('the idle model has no enabled verdict and no verdict testids (nothing can be clicked to fail)', () => {
    const { r, byId } = mount({ kind: 'idle' });
    expect(r.container.querySelector('[data-testid="l4-intercept-idle"]')).not.toBeNull();
    for (const id of VERDICTS) expect(byId(id), id).toBeNull();
    const buttons = [...r.container.querySelectorAll<HTMLButtonElement>('button')];
    expect(buttons.length).toBe(4);
    for (const b of buttons) expect(b.disabled, b.textContent ?? '').toBe(true);
  });
});

describe('L4InterceptBar: parked model sends the parked id (AC20)', () => {
  it('renders the four verdicts and Forward / Drop / Revert call back with the parked id, not the flow id', () => {
    const { r, handlers, byId } = mount({ kind: 'parked', id: 'P1' });
    for (const id of VERDICTS) expect(byId(id), id).not.toBeNull();
    const bar = r.container.querySelector('[data-testid="l4-intercept-parked"]')!;
    expect(bar.getAttribute('data-parked-id')).toBe('P1');
    expect(bar.textContent).toContain('P1');

    fireEvent.click(byId('l4-forward')!);
    expect(handlers.onForward).toHaveBeenCalledTimes(1);
    expect(handlers.onForward).toHaveBeenCalledWith('P1');
    fireEvent.click(byId('l4-drop')!);
    expect(handlers.onDrop).toHaveBeenCalledWith('P1');
    fireEvent.click(byId('l4-revert')!);
    expect(handlers.onRevert).toHaveBeenCalledWith('P1');
    expect(handlers.onMutate).not.toHaveBeenCalled();
  });

  it('a different parked id goes through unchanged (the bar does not hard-code P1)', () => {
    const { handlers, byId } = mount({ kind: 'parked', id: '9f3c-parked' });
    fireEvent.click(byId('l4-forward')!);
    expect(handlers.onForward).toHaveBeenCalledWith('9f3c-parked');
  });

  it('Mutate is disabled with the block reason until a spec is built, then calls back with the parked id', () => {
    const blocked = mount({ kind: 'parked', id: 'P1' }, { mutateBlocked: 'Build a packet in the craft editor first' });
    const mutate = blocked.byId('l4-mutate')!;
    expect(mutate.disabled).toBe(true);
    expect(mutate.getAttribute('title')).toBe('Build a packet in the craft editor first');
    fireEvent.click(mutate);
    expect(blocked.handlers.onMutate).not.toHaveBeenCalled();
    // Forward / Drop / Revert are not blocked by a missing spec.
    expect(blocked.byId('l4-forward')!.disabled).toBe(false);
    cleanup();

    const ready = mount({ kind: 'parked', id: 'P1' }, { mutateBlocked: null });
    expect(ready.byId('l4-mutate')!.disabled).toBe(false);
    fireEvent.click(ready.byId('l4-mutate')!);
    expect(ready.handlers.onMutate).toHaveBeenCalledWith('P1');
  });

  it('out of scope: every verdict is disabled with the scope reason and a forced click calls nothing', () => {
    const { handlers, byId, r } = mount({ kind: 'parked', id: 'P1' }, { inScope: false, scopeReason: 'eth1 is not in L4 scope' });
    for (const id of VERDICTS) {
      const b = byId(id)!;
      expect(b.disabled, id).toBe(true);
      expect(b.getAttribute('title'), id).toBe('eth1 is not in L4 scope');
      fireEvent.click(b);
    }
    expect(r.container.textContent).toContain('eth1 is not in L4 scope');
    for (const h of Object.values(handlers)) expect(h).not.toHaveBeenCalled();
  });
});

describe('L4InterceptBar: agent role (D12, AC24)', () => {
  it('with operatorOnly set every verdict is disabled, titled with the reason, marked operator-only, and a forced click calls nothing', () => {
    const { r, handlers, byId } = mount({ kind: 'parked', id: 'P1' }, { operatorOnly: OPERATOR_ONLY_REASON });
    for (const id of VERDICTS) {
      const b = byId(id)!;
      expect(b.disabled, id).toBe(true);
      expect(b.getAttribute('title'), id).toBe(OPERATOR_ONLY_REASON);
      expect(b.getAttribute('data-operator-only'), id).toBe('true');
      fireEvent.click(b);
    }
    for (const h of Object.values(handlers)) expect(h).not.toHaveBeenCalled();
    expect(r.container.textContent).toContain(OPERATOR_ONLY_REASON);
  });

  it('the operator-only reason outranks the scope reason in the tooltip', () => {
    const { byId } = mount({ kind: 'parked', id: 'P1' }, { operatorOnly: OPERATOR_ONLY_REASON, inScope: false, scopeReason: 'scope' });
    expect(byId('l4-forward')!.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
  });

  it('on an operator connection (operatorOnly null) nothing is marked operator-only', () => {
    const { r } = mount({ kind: 'parked', id: 'P1' });
    expect(r.container.querySelectorAll('[data-operator-only]')).toHaveLength(0);
  });

  it('the idle bar also carries the operator-only reason on its disabled buttons', () => {
    const { r } = mount({ kind: 'idle' }, { operatorOnly: OPERATOR_ONLY_REASON });
    const buttons = [...r.container.querySelectorAll<HTMLButtonElement>('button')];
    expect(buttons).toHaveLength(4);
    for (const b of buttons) {
      expect(b.disabled).toBe(true);
      expect(b.getAttribute('title')).toBe(OPERATOR_ONLY_REASON);
      expect(b.getAttribute('data-operator-only')).toBe('true');
    }
  });
});
