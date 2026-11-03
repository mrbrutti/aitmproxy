// The shared view primitives (plan amendment PA8, spec A9): the listbox keyboard contract every T8
// list shares (`Findings.tsx` semantics: ArrowUp/Down/Home/End move, Enter hands focus to the
// detail), and the error block each view shows with the core's text, the last good time and Retry.
import { describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@solidjs/testing-library';
import { afterEach } from 'vitest';
import { ErrorBlock, fmtLastGood, listboxKeys, RECONNECT_NOTE, ReconnectNote } from './primitives';

afterEach(() => cleanup());

/** A handler over `ids` with a recorded selection; `domId` is what each row's `id` attribute reads. */
function harness(ids: string[], selected: string | null = null) {
  const select = vi.fn((id: string) => {
    selected = id;
  });
  const focusDetail = vi.fn();
  const onKeyDown = listboxKeys({
    ids: () => ids,
    selectedId: () => selected,
    select,
    focusDetail,
    domId: (id) => `row-${id}`,
  });
  const key = (k: string) => {
    const e = new KeyboardEvent('keydown', { key: k, cancelable: true });
    onKeyDown(e);
    return e;
  };
  return { key, select, focusDetail, current: () => selected };
}

describe('listboxKeys', () => {
  it('an empty list is a no-op for every key and Enter still hands focus over', () => {
    const h = harness([]);
    for (const k of ['ArrowDown', 'ArrowUp', 'Home', 'End']) h.key(k);
    expect(h.select).not.toHaveBeenCalled();
    h.key('Enter');
    expect(h.focusDetail).toHaveBeenCalledTimes(1);
  });

  it('ArrowDown from nothing selects the first row; ArrowUp from nothing the last', () => {
    const down = harness(['a', 'b', 'c']);
    const e = down.key('ArrowDown');
    expect(down.select).toHaveBeenCalledWith('a');
    expect(e.defaultPrevented).toBe(true);
    const up = harness(['a', 'b', 'c']);
    up.key('ArrowUp');
    expect(up.select).toHaveBeenCalledWith('c');
  });

  it('moves one row at a time, clamps at the ends, Home and End jump', () => {
    const h = harness(['a', 'b', 'c'], 'a');
    h.key('ArrowDown');
    expect(h.current()).toBe('b');
    h.key('ArrowDown');
    h.key('ArrowDown');
    expect(h.current()).toBe('c');
    h.key('Home');
    expect(h.current()).toBe('a');
    h.key('ArrowUp');
    expect(h.current()).toBe('a');
    h.key('End');
    expect(h.current()).toBe('c');
    expect(h.focusDetail).not.toHaveBeenCalled();
  });

  it('a duplicated id never traps the arrow: ArrowDown moves to the next different id', () => {
    const h = harness(['a', 'a', 'b'], 'a');
    h.key('ArrowDown');
    expect(h.current()).toBe('b');
    h.key('ArrowUp');
    expect(h.current()).toBe('a');
    h.key('ArrowUp');
    expect(h.current()).toBe('a');
    expect(h.select).toHaveBeenCalledTimes(3);
  });

  it('Enter calls focusDetail and selects nothing; an unrelated key does nothing', () => {
    const h = harness(['a', 'b'], 'a');
    h.key('Enter');
    expect(h.focusDetail).toHaveBeenCalledTimes(1);
    expect(h.select).not.toHaveBeenCalled();
    const e = h.key('Tab');
    expect(e.defaultPrevented).toBe(false);
    expect(h.select).not.toHaveBeenCalled();
  });

  it('a keyboard selection scrolls the row found by its DOM id, never by a selector', () => {
    const el = document.createElement('div');
    el.id = 'row-we"ird]';
    const scroll = vi.fn();
    (el as unknown as { scrollIntoView: typeof scroll }).scrollIntoView = scroll;
    document.body.appendChild(el);
    try {
      const h = harness(['we"ird]']);
      h.key('ArrowDown');
      expect(scroll).toHaveBeenCalledWith({ block: 'nearest' });
    } finally {
      el.remove();
    }
  });
});

describe('ErrorBlock', () => {
  it('shows the text, the last good time and a Retry that calls back', () => {
    const onRetry = vi.fn();
    const at = new Date(2026, 10, 1, 14, 3, 22).getTime();
    render(() => <ErrorBlock text="bus closed" lastGood={at} onRetry={onRetry} disabled={false} />);
    const block = screen.getByRole('alert');
    expect(block.textContent).toContain('bus closed');
    expect(block.textContent).toContain(`last good: ${fmtLastGood(at)}`);
    expect(fmtLastGood(at)).toContain('14:03:22');
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('a null last good prints the dash; an omitted one prints no line; disabled freezes Retry', () => {
    const onRetry = vi.fn();
    const r = render(() => <ErrorBlock text="x" lastGood={null} onRetry={onRetry} disabled />);
    expect(r.container.textContent).toContain('last good: —');
    const retry = screen.getByRole('button', { name: 'Retry' }) as HTMLButtonElement;
    expect(retry.disabled).toBe(true);
    fireEvent.click(retry);
    expect(onRetry).not.toHaveBeenCalled();
    cleanup();
    const r2 = render(() => <ErrorBlock text="x" onRetry={onRetry} disabled={false} />);
    expect(r2.container.textContent).not.toContain('last good');
  });
});

describe('ReconnectNote', () => {
  it('prints the one sentence every view shares', () => {
    render(() => <ReconnectNote />);
    expect(screen.getByRole('status').textContent).toBe(RECONNECT_NOTE);
    expect(RECONNECT_NOTE).toBe('reconnecting: controls are disabled until the bus is back');
  });

  it('reconnect_note_reads_the_jobs_banner (D15, AC38): with an age it is the Kit banner, with null the ageless one, and without the prop the shared sentence', () => {
    render(() => <ReconnectNote valuesAgeMs={42_000} />);
    const banner = screen.getByRole('status');
    expect(banner.textContent).toBe('Bus disconnected · showing values from 0:42 ago · reconnecting…');
    expect(banner.hasAttribute('data-reconnect')).toBe(true);
    cleanup();
    render(() => <ReconnectNote valuesAgeMs={null} />);
    expect(screen.getByRole('status').textContent).toBe('Bus disconnected · reconnecting…');
    cleanup();
    render(() => <ReconnectNote valuesAgeMs={undefined} />);
    expect(screen.getByRole('status').textContent).toBe(RECONNECT_NOTE);
  });
});
