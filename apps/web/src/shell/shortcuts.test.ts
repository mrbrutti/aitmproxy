import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EVENTS, handleShortcut, installShortcuts, isEditableTarget, type ShortcutStore } from './shortcuts';

type Stub = { [K in keyof ShortcutStore]: ShortcutStore[K] extends (...a: never[]) => unknown ? ReturnType<typeof vi.fn> : ShortcutStore[K] };

const makeStore = (
  over: Partial<{
    armed: boolean;
    selected: ReturnType<ShortcutStore['selected']>;
    paused: ReturnType<ShortcutStore['oldestPaused']>;
    multi: number;
    paletteOpen: boolean;
    /** The raw selected id (L4 or HTTP) and the L4 id set, for the D9 guard; absent means no L4 rows. */
    selectedId: string | null;
    l4Ids: ReadonlySet<string>;
  }> = {},
) => {
  // `selected: null` is a real case (an L4 row is selected by its raw id while the HTTP map has nothing).
  const sel = 'selected' in over ? over.selected! : { id: 'f1', flow: { intercept: 'none', authority: 'api.test', inScope: true } };
  const ids = new Set<string>(['f1']);
  for (let i = 1; i < (over.multi ?? 1); i++) ids.add(`f${i + 1}`);
  const store = {
    proxy: { armed: over.armed ?? false },
    ui: { paletteOpen: over.paletteOpen ?? false, composeOpen: false },
    selected: vi.fn(() => sel),
    selectedIds: vi.fn(() => ids),
    visible: vi.fn(() => [{ id: 'f1' }, { id: 'f2' }, { id: 'f3' }]),
    oldestPaused: vi.fn(() => over.paused ?? null),
    select: vi.fn(),
    moveSelection: vi.fn(),
    arm: vi.fn(),
    replay: vi.fn(),
    resume: vi.fn(),
    kill: vi.fn(),
    openCompose: vi.fn(),
    openPalette: vi.fn(),
    toggleFilters: vi.fn(),
    togglePin: vi.fn(),
    setChip: vi.fn(),
    notice: vi.fn(),
    ...('selectedId' in over ? { selectedId: vi.fn(() => over.selectedId ?? null) } : {}),
    ...('l4Ids' in over ? { l4Ids: vi.fn(() => over.l4Ids ?? new Set<string>()) } : {}),
  };
  return store as unknown as Stub & ShortcutStore;
};

const key = (k: string, init: KeyboardEventInit = {}, target: EventTarget = document.body) => {
  const e = new KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true, ...init });
  Object.defineProperty(e, 'target', { value: target });
  return e;
};

describe('handleShortcut', () => {
  it('maps navigation keys to the store', () => {
    const s = makeStore();
    expect(handleShortcut(key('ArrowDown'), s)).toBe(true);
    expect(s.moveSelection).toHaveBeenCalledWith(1);
    handleShortcut(key('ArrowUp'), s);
    expect(s.moveSelection).toHaveBeenCalledWith(-1);
    handleShortcut(key('Home'), s);
    expect(s.select).toHaveBeenCalledWith('f1');
    handleShortcut(key('End'), s);
    expect(s.select).toHaveBeenCalledWith('f3');
  });

  it('maps the single-key verbs', () => {
    const s = makeStore();
    handleShortcut(key('i'), s);
    expect(s.arm).toHaveBeenCalledWith(true);
    handleShortcut(key('r'), s);
    expect(s.replay).toHaveBeenCalledWith('f1');
    handleShortcut(key('n'), s);
    expect(s.openCompose).toHaveBeenCalledWith(true);
    handleShortcut(key('p'), s);
    expect(s.togglePin).toHaveBeenCalledWith('api.test');
  });

  it('disarms when armed and only kills or edits a paused selection', () => {
    const s = makeStore({ armed: true, selected: { id: 'f9', flow: { intercept: 'paused', authority: 'api.test', inScope: true } } });
    handleShortcut(key('i'), s);
    expect(s.arm).toHaveBeenCalledWith(false);
    handleShortcut(key('d'), s);
    expect(s.kill).toHaveBeenCalledWith('f9');
    const onEdit = vi.fn();
    window.addEventListener(EVENTS.editPaused, onEdit);
    handleShortcut(key('e'), s);
    expect(onEdit).toHaveBeenCalledTimes(1);
    expect((onEdit.mock.calls[0]![0] as CustomEvent).detail).toEqual({ id: 'f9' });
    window.removeEventListener(EVENTS.editPaused, onEdit);

    const idle = makeStore();
    expect(handleShortcut(key('d'), idle)).toBe(false);
    expect(idle.kill).not.toHaveBeenCalled();
  });

  it('refuses mutating verbs on out-of-scope flows with the scope notice', () => {
    const s = makeStore({ selected: { id: 'f2', flow: { intercept: 'paused', authority: 'telemetry.example', inScope: false } } });
    handleShortcut(key('r'), s);
    handleShortcut(key('d'), s);
    expect(s.replay).not.toHaveBeenCalled();
    expect(s.kill).not.toHaveBeenCalled();
    expect(s.notice).toHaveBeenCalledWith('Out of scope — add telemetry.example to scope to act');
  });

  it('dispatches window events for list-geometry and inspector actions', () => {
    const s = makeStore();
    const seen: string[] = [];
    const names = [EVENTS.focusInspector, EVENTS.quickLook, EVENTS.mark, EVENTS.comment, EVENTS.contextMenu, EVENTS.focusFilter, EVENTS.focusSidebarFilter] as const;
    const h = (e: Event) => seen.push(e.type);
    for (const n of names) window.addEventListener(n, h);
    handleShortcut(key('Enter'), s);
    handleShortcut(key(' '), s);
    handleShortcut(key('m'), s);
    handleShortcut(key('c'), s);
    handleShortcut(key('.', { metaKey: true }), s);
    handleShortcut(key('f', { metaKey: true }), s);
    handleShortcut(key('F', { metaKey: true, shiftKey: true }), s);
    for (const n of names) window.removeEventListener(n, h);
    expect(seen).toEqual([...names]);
    expect(s.toggleFilters).toHaveBeenCalledWith(true);
  });

  it('handles the ⌘ chords: K palette, ⏎ resume, \\ kill, 1…9 chips', () => {
    const s = makeStore({ paused: { id: 'p1' } });
    handleShortcut(key('k', { metaKey: true }), s);
    expect(s.openPalette).toHaveBeenCalledWith(true);
    handleShortcut(key('Enter', { ctrlKey: true }), s);
    expect(s.resume).toHaveBeenCalledWith('p1');
    handleShortcut(key('\\', { metaKey: true }), s);
    expect(s.kill).toHaveBeenCalledWith('p1');
    handleShortcut(key('1', { metaKey: true }), s);
    handleShortcut(key('4', { metaKey: true }), s);
    handleShortcut(key('5', { metaKey: true }), s);
    handleShortcut(key('9', { metaKey: true }), s);
    // ⌘1…⌘9 follow the bar order (L4 parity spec §7(c)): ⌘5 is TCP and ⌘9 is h2 now that TCP UDP L4 sit after WebSocket.
    expect(s.setChip.mock.calls.map((c) => c[0])).toEqual(['all', 'ws', 'tcp', 'h2']);
  });

  it('Esc collapses a multi-select to the primary row', () => {
    const s = makeStore({ multi: 3 });
    expect(handleShortcut(key('Escape'), s)).toBe(true);
    expect(s.select).toHaveBeenCalledWith('f1');
    expect(handleShortcut(key('Escape'), makeStore()), 'single selection').toBe(false);
  });

  it('ignores keys typed into inputs, contenteditable and CodeMirror — except ⌘K', () => {
    const s = makeStore();
    const input = document.createElement('input');
    const cm = document.createElement('div');
    cm.className = 'cm-editor';
    const line = document.createElement('div');
    cm.appendChild(line);
    document.body.append(input, cm);
    expect(isEditableTarget(input)).toBe(true);
    expect(isEditableTarget(line)).toBe(true);
    expect(isEditableTarget(document.body)).toBe(false);
    expect(handleShortcut(key('i', {}, input), s)).toBe(false);
    expect(handleShortcut(key('r', {}, line), s)).toBe(false);
    expect(s.arm).not.toHaveBeenCalled();
    expect(handleShortcut(key('k', { metaKey: true }, input), s)).toBe(true);
    input.remove();
    cm.remove();
  });

  it('is quiet while the palette is open', () => {
    const s = makeStore({ paletteOpen: true });
    expect(handleShortcut(key('i'), s)).toBe(false);
    expect(s.arm).not.toHaveBeenCalled();
  });
});

// ---- D9 UI (L4 parity spec §7(c), AC33; task C9b): no HTTP verb on an L4 id -----------------------
//
// An L4 session is selected by its raw id while `selected()` (the HTTP map) is null. Every single-key
// HTTP verb and the ⌘. row menu must end at the notice: handled (true), no store verb, no window
// event. Navigation keys are not verbs and still move the selection.

const ALL_EVENTS = Object.values(EVENTS);

describe('handleShortcut on an L4 id (D9 UI, AC33)', () => {
  const l4Store = () => makeStore({ selected: null, selectedId: 'l4-1', l4Ids: new Set(['l4-1']) });

  it('r m c e d p and ⌘. are handled with the one notice and reach no store verb and no window event', () => {
    const s = l4Store();
    const seen: string[] = [];
    const h = (e: Event) => seen.push(e.type);
    for (const n of ALL_EVENTS) window.addEventListener(n, h);
    try {
      const results = ['r', 'm', 'c', 'e', 'd', 'p'].map((k) => handleShortcut(key(k), s));
      results.push(handleShortcut(key('.', { metaKey: true }), s));
      expect(results).toEqual([true, true, true, true, true, true, true]);
    } finally {
      for (const n of ALL_EVENTS) window.removeEventListener(n, h);
    }
    expect(seen).toEqual([]);
    expect(s.notice).toHaveBeenCalledTimes(7);
    for (const call of s.notice.mock.calls) expect(call[0]).toBe('Not available for L4 flows');
    expect(s.replay).not.toHaveBeenCalled();
    expect(s.kill).not.toHaveBeenCalled();
    expect(s.resume).not.toHaveBeenCalled();
    expect(s.togglePin).not.toHaveBeenCalled();
  });

  it('each refused key is default-prevented, so the browser does nothing with it either', () => {
    const s = l4Store();
    for (const k of ['r', 'm', 'c', 'e', 'd', 'p']) {
      const e = key(k);
      handleShortcut(e, s);
      expect(e.defaultPrevented, `key ${k}`).toBe(true);
    }
    const dot = key('.', { metaKey: true });
    handleShortcut(dot, s);
    expect(dot.defaultPrevented).toBe(true);
  });

  it('navigation still works on an L4 id: ArrowDown / ArrowUp move the selection, Home / End select', () => {
    const s = l4Store();
    expect(handleShortcut(key('ArrowDown'), s)).toBe(true);
    expect(s.moveSelection).toHaveBeenCalledWith(1);
    expect(handleShortcut(key('ArrowUp'), s)).toBe(true);
    expect(s.moveSelection).toHaveBeenCalledWith(-1);
    expect(handleShortcut(key('Home'), s)).toBe(true);
    expect(s.select).toHaveBeenCalledWith('f1');
    expect(s.notice).not.toHaveBeenCalled();
  });

  it('i (arm) and n (compose) are not row verbs and stay live on an L4 id', () => {
    const s = l4Store();
    expect(handleShortcut(key('i'), s)).toBe(true);
    expect(s.arm).toHaveBeenCalledWith(true);
    expect(handleShortcut(key('n'), s)).toBe(true);
    expect(s.openCompose).toHaveBeenCalledWith(true);
    expect(s.notice).not.toHaveBeenCalled();
  });

  it('an HTTP id keeps its verbs while L4 ids exist (the guard is per selected id, not per store)', () => {
    const s = makeStore({ selectedId: 'f1', l4Ids: new Set(['l4-1']) });
    expect(handleShortcut(key('r'), s)).toBe(true);
    expect(s.replay).toHaveBeenCalledWith('f1');
    const onMark = vi.fn();
    window.addEventListener(EVENTS.mark, onMark);
    handleShortcut(key('m'), s);
    window.removeEventListener(EVENTS.mark, onMark);
    expect(onMark).toHaveBeenCalledTimes(1);
    expect(s.notice).not.toHaveBeenCalled();
  });

  it('a store without the L4 accessors (no L4 rows) and a null HTTP selection: verbs fall through as before, no notice', () => {
    const s = makeStore({ selected: null });
    expect(handleShortcut(key('r'), s)).toBe(false);
    expect(handleShortcut(key('m'), s)).toBe(false);
    expect(handleShortcut(key('.', { metaKey: true }), s)).toBe(false);
    expect(s.notice).not.toHaveBeenCalled();
  });
});

describe('installShortcuts', () => {
  let dispose: (() => void) | null = null;
  beforeEach(() => (dispose = null));
  afterEach(() => dispose?.());

  it('listens on the window and stops after dispose', () => {
    const s = makeStore();
    dispose = installShortcuts(s);
    document.body.dispatchEvent(key('ArrowDown'));
    expect(s.moveSelection).toHaveBeenCalledTimes(1);
    dispose();
    dispose = null;
    document.body.dispatchEvent(key('ArrowDown'));
    expect(s.moveSelection).toHaveBeenCalledTimes(1);
  });
});
