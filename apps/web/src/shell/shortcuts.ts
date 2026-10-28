// Global keyboard shortcuts (§2.7 "Flow list — Keyboard", §2.8). One window-level handler; it
// ignores keys typed into inputs, textareas, contenteditable and CodeMirror editors. Actions that
// need list geometry (mark menu at the row, comment popover, context menu) or belong to another
// region (inspector focus, quick look, edit paused) are dispatched as window CustomEvents.
import type { FlowId, FlowSummary } from '~/model/flow';
import type { KillMode, Chip } from '~/state/app';
import { CHIPS } from './chips';

export const EVENTS = {
  focusInspector: 'aitm:focus-inspector',
  editPaused: 'aitm:edit-paused',
  quickLook: 'aitm:quick-look',
  mark: 'aitm:mark',
  comment: 'aitm:comment',
  contextMenu: 'aitm:context-menu',
  focusFilter: 'aitm:focus-filter',
  focusSidebarFilter: 'aitm:focus-sidebar-filter',
  composePrefill: 'aitm:compose-prefill',
} as const;

export type ShortcutEvent = (typeof EVENTS)[keyof typeof EVENTS];

export const OUT_OF_SCOPE = (host: string) => `Out of scope — add ${host} to scope to act`;

/** The slice of the app store the shortcuts need; tests pass a stub. */
export interface ShortcutStore {
  proxy: { armed: boolean };
  ui: { paletteOpen: boolean; composeOpen: boolean };
  selected(): { id: FlowId; flow: Pick<FlowSummary, 'intercept' | 'authority' | 'inScope'> } | null;
  selectedIds(): ReadonlySet<FlowId>;
  visible(): { id: FlowId }[];
  oldestPaused(): { id: FlowId } | null;
  select(id: FlowId | null, opts?: { additive?: boolean; range?: boolean }): void;
  moveSelection(delta: number): void;
  arm(enabled: boolean): unknown;
  replay(id: FlowId): unknown;
  resume(id: FlowId): unknown;
  kill(id: FlowId, mode?: KillMode): unknown;
  openCompose(open?: boolean): void;
  openPalette(open?: boolean): void;
  toggleFilters(open?: boolean): void;
  togglePin(host: string): void;
  setChip(c: Chip): void;
  notice(text: string, kind?: 'error' | 'info'): void;
}

export function isEditableTarget(t: EventTarget | null): boolean {
  if (!(t instanceof Element)) return false;
  const tag = t.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true;
  if ((t as HTMLElement).isContentEditable) return true;
  if (t.closest('[contenteditable=""], [contenteditable="true"], .cm-editor')) return true;
  return false;
}

export const emit = (name: ShortcutEvent, detail?: unknown) => window.dispatchEvent(new CustomEvent(name, { detail }));

/** Returns true when the key was handled (and default-prevented). */
export function handleShortcut(e: KeyboardEvent, store: ShortcutStore): boolean {
  if (e.defaultPrevented || e.isComposing) return false;
  const mod = e.metaKey || e.ctrlKey;
  const key = e.key;

  // ⌘K is global, even from inputs.
  if (mod && !e.shiftKey && !e.altKey && (key === 'k' || key === 'K')) {
    store.openPalette(!store.ui.paletteOpen);
    e.preventDefault();
    return true;
  }
  if (isEditableTarget(e.target)) return false;
  if (store.ui.paletteOpen || store.ui.composeOpen) return false;

  const sel = store.selected();
  const guardScope = (): boolean => {
    if (!sel) return false;
    if (!sel.flow.inScope) {
      store.notice(OUT_OF_SCOPE(sel.flow.authority));
      return false;
    }
    return true;
  };

  if (mod && !e.altKey) {
    if (e.shiftKey && (key === 'f' || key === 'F')) {
      emit(EVENTS.focusSidebarFilter);
    } else if (key === 'f' || key === 'F') {
      store.toggleFilters(true);
      emit(EVENTS.focusFilter);
    } else if (key === 'Enter') {
      const p = store.oldestPaused();
      if (p) store.resume(p.id);
      else return false;
    } else if (key === '\\') {
      const p = store.oldestPaused();
      if (p) store.kill(p.id);
      else return false;
    } else if (key === '.') {
      if (!sel) return false;
      emit(EVENTS.contextMenu, { id: sel.id });
    } else if (!e.shiftKey && key >= '1' && key <= '9') {
      const chip = CHIPS[Number(key) - 1];
      if (!chip) return false;
      store.setChip(chip.id);
    } else {
      return false;
    }
    e.preventDefault();
    return true;
  }

  if (mod || e.altKey) return false;

  switch (key) {
    case 'ArrowDown':
      store.moveSelection(1);
      break;
    case 'ArrowUp':
      store.moveSelection(-1);
      break;
    case 'Home': {
      const first = store.visible()[0];
      if (!first) return false;
      store.select(first.id);
      break;
    }
    case 'End': {
      const last = store.visible().at(-1);
      if (!last) return false;
      store.select(last.id);
      break;
    }
    case 'Enter':
      if (!sel) return false;
      emit(EVENTS.focusInspector, { id: sel.id });
      break;
    case ' ':
      if (!sel) return false;
      emit(EVENTS.quickLook, { id: sel.id });
      break;
    case 'Escape':
      if (store.selectedIds().size > 1 && sel) store.select(sel.id);
      else return false;
      break;
    case 'i':
      store.arm(!store.proxy.armed);
      break;
    case 'e':
      if (!sel || sel.flow.intercept !== 'paused') return false;
      if (!guardScope()) return true;
      emit(EVENTS.editPaused, { id: sel.id });
      break;
    case 'r':
      if (!sel) return false;
      if (!guardScope()) return true;
      store.replay(sel.id);
      break;
    case 'n':
      store.openCompose(true);
      break;
    case 'd':
      if (!sel || sel.flow.intercept !== 'paused') return false;
      if (!guardScope()) return true;
      store.kill(sel.id);
      break;
    case 'm':
      if (!sel) return false;
      emit(EVENTS.mark, { id: sel.id });
      break;
    case 'c':
      if (!sel) return false;
      emit(EVENTS.comment, { id: sel.id });
      break;
    case 'p':
      if (!sel) return false;
      store.togglePin(sel.flow.authority);
      break;
    default:
      return false;
  }
  e.preventDefault();
  return true;
}

export function installShortcuts(store: ShortcutStore, target: Window = window): () => void {
  const handler = (e: KeyboardEvent) => void handleShortcut(e, store);
  target.addEventListener('keydown', handler);
  return () => target.removeEventListener('keydown', handler);
}
