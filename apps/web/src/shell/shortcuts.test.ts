import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EVENTS, handleShortcut, installShortcuts, isEditableTarget, type ShortcutStore } from './shortcuts';

type Stub = { [K in keyof ShortcutStore]: ShortcutStore[K] extends (...a: never[]) => unknown ? ReturnType<typeof vi.fn> : ShortcutStore[K] };

const makeStore = (over: Partial<{ armed: boolean; selected: ReturnType<ShortcutStore['selected']>; paused: ReturnType<ShortcutStore['oldestPaused']>; multi: number; paletteOpen: boolean }> = {}) => {
  const sel = over.selected ?? { id: 'f1', flow: { intercept: 'none', authority: 'api.test', inScope: true } };
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
    handleShortcut(key('9', { metaKey: true }), s);
    expect(s.setChip.mock.calls.map((c) => c[0])).toEqual(['all', 'ws', 'xml']);
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
