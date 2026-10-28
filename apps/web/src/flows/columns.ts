// Flow-list columns (§2.7): the fixed default order, widths (resizable by dragging a header edge),
// visibility (header context menu) and sort — persisted in localStorage. The grid template is one
// CSS custom property on the list, so a resize repaints every row without touching them.
import { createMemo, createSignal } from 'solid-js';
import type { FlowSummary } from '~/model/flow';

export type ColumnId =
  | 'dot'
  | 'seq'
  | 'url'
  | 'client'
  | 'method'
  | 'status'
  | 'time'
  | 'duration'
  | 'req'
  | 'res'
  | 'ssl'
  | 'edited'
  | 'origin'
  | 'mark';

export interface ColumnDef {
  id: ColumnId;
  label: string;
  width: number;
  min: number;
  max: number;
  align: 'left' | 'right' | 'center';
  /** The URL column: `minmax(width, 1fr)`. */
  flex?: boolean;
  hideable: boolean;
  sortable: boolean;
  resizable: boolean;
}

export const COLUMNS: readonly ColumnDef[] = [
  { id: 'dot', label: '', width: 24, min: 24, max: 24, align: 'center', hideable: false, sortable: false, resizable: false },
  { id: 'seq', label: '#', width: 44, min: 36, max: 96, align: 'right', hideable: false, sortable: true, resizable: true },
  { id: 'url', label: 'URL', width: 240, min: 160, max: 2000, align: 'left', flex: true, hideable: false, sortable: true, resizable: true },
  { id: 'client', label: 'Client', width: 104, min: 60, max: 240, align: 'left', hideable: true, sortable: true, resizable: true },
  { id: 'method', label: 'Method', width: 72, min: 56, max: 120, align: 'left', hideable: true, sortable: true, resizable: true },
  { id: 'status', label: 'Status', width: 72, min: 56, max: 120, align: 'left', hideable: true, sortable: true, resizable: true },
  { id: 'time', label: 'Time', width: 112, min: 80, max: 160, align: 'left', hideable: true, sortable: true, resizable: true },
  { id: 'duration', label: 'Duration', width: 72, min: 56, max: 120, align: 'right', hideable: true, sortable: true, resizable: true },
  { id: 'req', label: 'Request', width: 72, min: 56, max: 120, align: 'right', hideable: true, sortable: true, resizable: true },
  { id: 'res', label: 'Response', width: 72, min: 56, max: 120, align: 'right', hideable: true, sortable: true, resizable: true },
  { id: 'ssl', label: 'SSL', width: 40, min: 32, max: 64, align: 'center', hideable: true, sortable: false, resizable: true },
  { id: 'edited', label: 'Edited', width: 52, min: 40, max: 80, align: 'center', hideable: true, sortable: false, resizable: true },
  { id: 'origin', label: 'Origin', width: 60, min: 48, max: 96, align: 'left', hideable: true, sortable: true, resizable: true },
  { id: 'mark', label: '', width: 20, min: 20, max: 20, align: 'center', hideable: true, sortable: false, resizable: false },
];

const DEFS = new Map(COLUMNS.map((c) => [c.id, c]));
export const columnDef = (id: ColumnId): ColumnDef => DEFS.get(id)!;

export interface ColumnState {
  widths: Partial<Record<ColumnId, number>>;
  hidden: ColumnId[];
}

export type SortDir = 'asc' | 'desc';
export interface SortState {
  id: ColumnId;
  dir: SortDir;
}

export const COLUMNS_KEY = 'aitm.columns';

export interface StorageLike {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

export const clampWidth = (id: ColumnId, w: number): number => {
  const d = columnDef(id);
  return Math.round(Math.max(d.min, Math.min(d.max, w)));
};

export const widthOf = (state: ColumnState, id: ColumnId): number => clampWidth(id, state.widths[id] ?? columnDef(id).width);

export function loadColumnState(storage: StorageLike | null): ColumnState {
  const empty: ColumnState = { widths: {}, hidden: [] };
  if (!storage) return empty;
  try {
    const raw = storage.getItem(COLUMNS_KEY);
    if (!raw) return empty;
    const parsed = JSON.parse(raw) as Partial<ColumnState>;
    const widths: ColumnState['widths'] = {};
    for (const [k, v] of Object.entries(parsed.widths ?? {})) {
      if (DEFS.has(k as ColumnId) && typeof v === 'number' && Number.isFinite(v)) widths[k as ColumnId] = clampWidth(k as ColumnId, v);
    }
    const hidden = (parsed.hidden ?? []).filter((id): id is ColumnId => DEFS.has(id) && columnDef(id).hideable);
    return { widths, hidden };
  } catch {
    return empty;
  }
}

export function saveColumnState(storage: StorageLike | null, state: ColumnState): void {
  try {
    storage?.setItem(COLUMNS_KEY, JSON.stringify(state));
  } catch {
    /* private mode */
  }
}

/** Resize `id` by `delta` px from its current width; clamped to the column's [min, max]. */
export function resizeColumn(state: ColumnState, id: ColumnId, delta: number): ColumnState {
  if (!columnDef(id).resizable) return state;
  return { ...state, widths: { ...state.widths, [id]: clampWidth(id, widthOf(state, id) + delta) } };
}

export function toggleColumn(state: ColumnState, id: ColumnId): ColumnState {
  if (!columnDef(id).hideable) return state;
  const hidden = state.hidden.includes(id) ? state.hidden.filter((h) => h !== id) : [...state.hidden, id];
  return { ...state, hidden };
}

export const visibleColumns = (state: ColumnState): ColumnDef[] => COLUMNS.filter((c) => !state.hidden.includes(c.id));

/** `grid-template-columns` for the header and every row. */
export function gridTemplate(state: ColumnState): string {
  return visibleColumns(state)
    .map((c) => {
      const w = widthOf(state, c.id);
      return c.flex ? `minmax(${w}px, 1fr)` : `${w}px`;
    })
    .join(' ');
}

/** Click cycles none → asc → desc → none. */
export function nextSort(cur: SortState | null, id: ColumnId): SortState | null {
  if (!columnDef(id).sortable) return cur;
  if (!cur || cur.id !== id) return { id, dir: 'asc' };
  if (cur.dir === 'asc') return { id, dir: 'desc' };
  return null;
}

const sortKey = (f: FlowSummary, id: ColumnId): string | number => {
  switch (id) {
    case 'seq':
      return f.seq;
    case 'url':
      return `${f.authority}${f.path}`;
    case 'client':
      return f.client.name.toLowerCase();
    case 'method':
      return f.kind === 'websocket' ? 'WS' : f.method;
    case 'status':
      return f.intercept === 'paused' ? 1000 : f.intercept === 'killed' ? 1001 : (f.status ?? 999);
    case 'time':
      return f.startedAt;
    case 'duration':
      return f.durationMs ?? -1;
    case 'req':
      return f.reqSize ?? -1;
    case 'res':
      return f.resSize ?? -1;
    case 'origin':
      return f.origin;
    default:
      return f.seq;
  }
};

export function compareFlows(sort: SortState, a: FlowSummary, b: FlowSummary): number {
  const ka = sortKey(a, sort.id);
  const kb = sortKey(b, sort.id);
  let c = typeof ka === 'number' && typeof kb === 'number' ? ka - kb : String(ka).localeCompare(String(kb));
  if (c === 0) c = a.seq - b.seq;
  return sort.dir === 'asc' ? c : -c;
}

/** Reactive column state for one list. `storage` defaults to localStorage (null in tests). */
export function createColumnState(storage: StorageLike | null = typeof localStorage === 'undefined' ? null : localStorage) {
  const [state, setStateRaw] = createSignal<ColumnState>(loadColumnState(storage));
  const [sort, setSort] = createSignal<SortState | null>(null);
  const setState = (next: ColumnState) => {
    setStateRaw(next);
    saveColumnState(storage, next);
  };
  const template = createMemo(() => gridTemplate(state()));
  const visible = createMemo(() => visibleColumns(state()));
  return {
    state,
    sort,
    template,
    visible,
    width: (id: ColumnId) => widthOf(state(), id),
    isHidden: (id: ColumnId) => state().hidden.includes(id),
    resize: (id: ColumnId, delta: number) => setState(resizeColumn(state(), id, delta)),
    setWidth: (id: ColumnId, w: number) => setState({ ...state(), widths: { ...state().widths, [id]: clampWidth(id, w) } }),
    toggle: (id: ColumnId) => setState(toggleColumn(state(), id)),
    reset: () => setState({ widths: {}, hidden: [] }),
    cycleSort: (id: ColumnId) => setSort(nextSort(sort(), id)),
    clearSort: () => setSort(null),
  };
}

export type ColumnStore = ReturnType<typeof createColumnState>;
