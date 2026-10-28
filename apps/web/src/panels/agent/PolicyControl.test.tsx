import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render } from '@solidjs/testing-library';
import { PolicyControl } from './PolicyControl';

afterEach(cleanup);

describe('PolicyControl', () => {
  it('marks the bound policy and explains it', () => {
    const r = render(() => <PolicyControl value="readonly" onChange={() => {}} />);
    const radios = r.getAllByRole('radio');
    expect(radios.map((b) => b.textContent)).toEqual(['Allow all tools', 'Read-only', 'Paused']);
    expect(radios[1]!.getAttribute('aria-checked')).toBe('true');
    expect(radios[0]!.getAttribute('aria-checked')).toBe('false');
    expect(r.container.textContent).toContain('list/get/status only; mutating calls are refused.');
  });

  it('calls onChange with the clicked policy and not for the current one', () => {
    const onChange = vi.fn();
    const r = render(() => <PolicyControl value="all" onChange={onChange} />);
    fireEvent.click(r.getByText('Paused'));
    expect(onChange).toHaveBeenCalledWith('paused');
    fireEvent.click(r.getByText('Allow all tools'));
    expect(onChange).toHaveBeenCalledTimes(1);
  });

  it('moves with the arrow keys', () => {
    const onChange = vi.fn();
    const r = render(() => <PolicyControl value="all" onChange={onChange} />);
    fireEvent.keyDown(r.getByText('Allow all tools'), { key: 'ArrowRight' });
    expect(onChange).toHaveBeenLastCalledWith('readonly');
    fireEvent.keyDown(r.getByText('Allow all tools'), { key: 'ArrowLeft' });
    expect(onChange).toHaveBeenLastCalledWith('paused');
  });

  it('is disabled with the reason as a tooltip when agent.set is missing', () => {
    const onChange = vi.fn();
    const r = render(() => <PolicyControl value="all" onChange={onChange} disabled disabledReason="agent.set is a core follow-up (F1)" />);
    expect(r.getByRole('radiogroup').getAttribute('title')).toBe('agent.set is a core follow-up (F1)');
    for (const b of r.getAllByRole('radio')) expect((b as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(r.getByText('Paused'));
    expect(onChange).not.toHaveBeenCalled();
  });
});
