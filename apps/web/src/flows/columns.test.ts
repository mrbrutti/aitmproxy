import { describe, expect, it } from 'vitest';
import {
  COLUMNS,
  COLUMNS_KEY,
  clampWidth,
  compareFlows,
  gridTemplate,
  loadColumnState,
  nextSort,
  resizeColumn,
  saveColumnState,
  toggleColumn,
  visibleColumns,
  type StorageLike,
} from './columns';
import type { FlowSummary } from '~/model/flow';

const memoryStorage = (): StorageLike & { data: Map<string, string> } => {
  const data = new Map<string, string>();
  return { data, getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v) };
};

describe('columns: defaults and template', () => {
  it('keeps the foundation order and default widths', () => {
    expect(COLUMNS.map((c) => c.id)).toEqual(['dot', 'seq', 'url', 'client', 'method', 'status', 'time', 'duration', 'req', 'res', 'ssl', 'edited', 'origin', 'mark']);
    expect(gridTemplate({ widths: {}, hidden: [] })).toBe('24px 44px minmax(240px, 1fr) 104px 72px 72px 112px 72px 72px 72px 40px 52px 60px 20px');
  });

  it('omits hidden columns from the template', () => {
    const state = toggleColumn(toggleColumn({ widths: {}, hidden: [] }, 'client'), 'mark');
    expect(visibleColumns(state).map((c) => c.id)).not.toContain('client');
    expect(gridTemplate(state)).toBe('24px 44px minmax(240px, 1fr) 72px 72px 112px 72px 72px 72px 40px 52px 60px');
    expect(toggleColumn(state, 'client').hidden).toEqual(['mark']);
  });

  it('never hides the dot, # or URL columns', () => {
    const state = toggleColumn(toggleColumn({ widths: {}, hidden: [] }, 'url'), 'dot');
    expect(state.hidden).toEqual([]);
  });
});

describe('columns: resize math', () => {
  it('adds the drag delta and clamps to [min, max]', () => {
    let s = resizeColumn({ widths: {}, hidden: [] }, 'client', 30);
    expect(s.widths.client).toBe(134);
    s = resizeColumn(s, 'client', -500);
    expect(s.widths.client).toBe(60);
    s = resizeColumn(s, 'client', 10_000);
    expect(s.widths.client).toBe(240);
  });

  it('ignores resizes on fixed columns and rounds to whole pixels', () => {
    const base = { widths: {}, hidden: [] };
    expect(resizeColumn(base, 'dot', 20)).toBe(base);
    expect(clampWidth('url', 300.6)).toBe(301);
  });
});

describe('columns: persistence', () => {
  it('round-trips widths and hidden columns through storage', () => {
    const storage = memoryStorage();
    const state = toggleColumn(resizeColumn({ widths: {}, hidden: [] }, 'url', 100), 'ssl');
    saveColumnState(storage, state);
    expect(JSON.parse(storage.data.get(COLUMNS_KEY)!)).toEqual({ widths: { url: 340 }, hidden: ['ssl'] });
    expect(loadColumnState(storage)).toEqual({ widths: { url: 340 }, hidden: ['ssl'] });
  });

  it('drops unknown columns, out-of-range widths and non-hideable ids on load', () => {
    const storage = memoryStorage();
    storage.setItem(COLUMNS_KEY, JSON.stringify({ widths: { url: 5, nope: 50, client: 'x' }, hidden: ['url', 'bogus', 'origin'] }));
    expect(loadColumnState(storage)).toEqual({ widths: { url: 160 }, hidden: ['origin'] });
  });

  it('survives corrupt storage and a missing storage', () => {
    const storage = memoryStorage();
    storage.setItem(COLUMNS_KEY, '{not json');
    expect(loadColumnState(storage)).toEqual({ widths: {}, hidden: [] });
    expect(loadColumnState(null)).toEqual({ widths: {}, hidden: [] });
  });
});

describe('columns: sort', () => {
  const flow = (p: Partial<FlowSummary>): FlowSummary => ({
    id: String(p.seq ?? 1),
    seq: 1,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    authority: 'a.test',
    path: '/',
    query: null,
    status: 200,
    statusText: 'OK',
    startedAt: 0,
    durationMs: 10,
    reqSize: 1,
    resSize: 1,
    client: { id: 'curl', name: 'curl' },
    tls: 'mitm',
    httpVersion: 'HTTP/2',
    intercept: 'none',
    edited: false,
    isReplay: false,
    origin: 'client',
    inScope: true,
    contentType: null,
    mark: null,
    comment: null,
    ...p,
  });

  it('cycles none → asc → desc → none and ignores unsortable columns', () => {
    expect(nextSort(null, 'duration')).toEqual({ id: 'duration', dir: 'asc' });
    expect(nextSort({ id: 'duration', dir: 'asc' }, 'duration')).toEqual({ id: 'duration', dir: 'desc' });
    expect(nextSort({ id: 'duration', dir: 'desc' }, 'duration')).toBeNull();
    expect(nextSort({ id: 'duration', dir: 'desc' }, 'status')).toEqual({ id: 'status', dir: 'asc' });
    expect(nextSort(null, 'ssl')).toBeNull();
  });

  it('orders by the column, with missing values first and capture order as the tie-break', () => {
    const rows = [flow({ seq: 1, durationMs: 300 }), flow({ seq: 2, durationMs: null }), flow({ seq: 3, durationMs: 50 }), flow({ seq: 4, durationMs: 50 })];
    const asc = [...rows].sort((a, b) => compareFlows({ id: 'duration', dir: 'asc' }, a, b)).map((f) => f.seq);
    expect(asc).toEqual([2, 3, 4, 1]);
    const desc = [...rows].sort((a, b) => compareFlows({ id: 'duration', dir: 'desc' }, a, b)).map((f) => f.seq);
    expect(desc).toEqual([1, 4, 3, 2]);
  });

  it('sorts paused and killed after every status code', () => {
    const rows = [flow({ seq: 1, status: null, intercept: 'paused' }), flow({ seq: 2, status: 503 }), flow({ seq: 3, status: null, intercept: 'killed' }), flow({ seq: 4, status: 200 })];
    const asc = [...rows].sort((a, b) => compareFlows({ id: 'status', dir: 'asc' }, a, b)).map((f) => f.seq);
    expect(asc).toEqual([4, 2, 1, 3]);
  });
});
