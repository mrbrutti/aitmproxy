import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { CraftEditor } from './CraftEditor';
import type { L4CraftResult } from './model';

afterEach(cleanup);

const CRAFT: L4CraftResult = { length: 2, bytes: 'AAE=', summary: { layers: ['Raw'], length: 2 } };

describe('out_of_scope_inject_disabled', () => {
  it('disables craft and inject with the scope reason as the tooltip when out of L4 scope', () => {
    const onInject = vi.fn();
    const r = render(() => (
      <CraftEditor
        interface="eth9"
        inScope={false}
        scopeReason="Out of L4 scope: no scope entry covers interface eth9."
        canCraft
        canInject
        onBuild={() => Promise.resolve(CRAFT)}
        onInject={onInject}
      />
    ));
    const inject = r.getByTestId('l4-inject') as HTMLButtonElement;
    expect(inject.disabled).toBe(true);
    expect(inject.getAttribute('title')).toContain('Out of L4 scope');
    const build = r.getByText('Build') as HTMLButtonElement;
    expect(build.disabled).toBe(true);
    expect(build.getAttribute('title')).toContain('Out of L4 scope');

    // Clicking the disabled inject never reaches the wire path.
    fireEvent.click(inject);
    expect(onInject).not.toHaveBeenCalled();
    // The scope reason is also shown in place (dimmed session), not only in the tooltip.
    expect(r.container.textContent).toContain('Out of L4 scope');
  });

  it('enables inject in scope and hands the authored target to the guarded path', () => {
    const onInject = vi.fn();
    const r = render(() => (
      <CraftEditor interface="lo0" inScope scopeReason="" canCraft canInject onBuild={() => Promise.resolve(CRAFT)} onInject={onInject} />
    ));
    const inject = r.getByTestId('l4-inject') as HTMLButtonElement;
    expect(inject.disabled).toBe(false);
    fireEvent.click(inject);
    expect(onInject).toHaveBeenCalledTimes(1);
    const arg = onInject.mock.calls[0]![0];
    expect(arg.interface).toBe('lo0');
    expect(arg.dst).toBe('127.0.0.1');
    expect(arg.port).toBe(9);
    expect(arg.spec.layers.length).toBeGreaterThan(0);
  });

  it('disables inject when the core lacks l4.inject, with an honest tooltip', () => {
    const r = render(() => (
      <CraftEditor interface="lo0" inScope scopeReason="" canCraft={false} canInject={false} onBuild={() => Promise.resolve(CRAFT)} onInject={() => {}} />
    ));
    const inject = r.getByTestId('l4-inject') as HTMLButtonElement;
    expect(inject.disabled).toBe(true);
    expect(inject.getAttribute('title')).toContain('l4.inject is not available');
  });
});
