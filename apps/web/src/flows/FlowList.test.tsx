import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, cleanup } from '@solidjs/testing-library';
import { createSignal } from 'solid-js';
import { createStore } from 'solid-js/store';
import { AppProvider } from '~/state/context';
import type { AppStore, FlowEntry } from '~/state/app';
import type { FlowSummary } from '~/model/flow';
import { FlowList } from './FlowList';
import { createColumnState } from './columns';
import { isAtBottom, newSince, windowRange } from './scroll';

const flow = (seq: number, p: Partial<FlowSummary> = {}): FlowSummary => ({
  id: `f${seq}`,
  seq,
  kind: 'http',
  method: 'GET',
  scheme: 'https',
  authority: 'api.shop-staging.test',
  path: `/api/items/${seq}`,
  query: null,
  status: 200,
  statusText: 'OK',
  startedAt: 1_700_000_000_000 + seq,
  durationMs: 40,
  reqSize: 120,
  resSize: 2048,
  client: { id: 'curl', name: 'curl' },
  tls: 'mitm',
  httpVersion: 'HTTP/2',
  intercept: 'none',
  edited: false,
  isReplay: false,
  origin: 'client',
  inScope: true,
  contentType: 'application/json',
  mark: null,
  comment: null,
  ...p,
});

function stubApp(n: number) {
  const entries: FlowEntry[] = [];
  for (let i = 1; i <= n; i++) {
    const [store, set] = createStore<FlowSummary>(flow(i));
    entries.push({ id: `f${i}`, flow: store, raw: flow(i), set });
  }
  const [selectedId, setSelectedId] = createSignal<string | null>(null);
  const [selectedIds, setSelectedIds] = createSignal<ReadonlySet<string>>(new Set());
  const byId = new Map(entries.map((e) => [e.id, e]));
  const app = {
    ui: { density: 'dense', autoSelect: false, pinned: [] as string[] },
    proxy: { address: '127.0.0.1:8080', pausedIds: [] as string[] },
    visible: () => entries,
    total: () => entries.length,
    byId,
    details: {},
    selectedId,
    selectedIds,
    select: vi.fn((id: string | null) => {
      setSelectedId(id);
      setSelectedIds(new Set(id ? [id] : []));
    }),
    setChip: vi.fn(),
    setFilters: vi.fn(),
    setQuickFilter: vi.fn(),
    setSidebar: vi.fn(),
    notice: vi.fn(),
  };
  return { app: app as unknown as AppStore, entries };
}

const VIEWPORT = 280; // px → 10 rows of 28 + 12 overscan
const tick = () => new Promise((r) => setTimeout(r, 30));

describe('FlowList rendering', () => {
  // jsdom has no layout: the virtualizer measures the scroll element with clientWidth/Height,
  // so give every element a 1200×280 box.
  const proto = HTMLElement.prototype;
  const original = { w: Object.getOwnPropertyDescriptor(proto, 'clientWidth'), h: Object.getOwnPropertyDescriptor(proto, 'clientHeight') };
  beforeEach(() => {
    Object.defineProperty(proto, 'clientWidth', { configurable: true, get: () => 1200 });
    Object.defineProperty(proto, 'clientHeight', { configurable: true, get: () => VIEWPORT });
  });
  afterEach(() => {
    if (original.w) Object.defineProperty(proto, 'clientWidth', original.w);
    else delete (proto as unknown as Record<string, unknown>).clientWidth;
    if (original.h) Object.defineProperty(proto, 'clientHeight', original.h);
    else delete (proto as unknown as Record<string, unknown>).clientHeight;
    cleanup();
  });

  it('renders only the visible window plus overscan for a tall list', async () => {
    const { app } = stubApp(500);
    const r = render(() => (
      <AppProvider store={app}>
        <FlowList columns={createColumnState(null)} />
      </AppProvider>
    ));
    await tick();
    const rows = r.container.querySelectorAll('[role="row"][data-id]');
    // viewport 280 / 28 = 10 rows visible, + 12 overscan below (nothing above at offset 0)
    expect(rows.length).toBeGreaterThanOrEqual(10);
    expect(rows.length).toBeLessThanOrEqual(10 + 12 + 1);
    expect(rows.length).toBeLessThan(500);
    expect(r.container.querySelector('[role="rowgroup"]')).toHaveProperty('style.height', `${500 * 28}px`);
  });

  it('renders every row of a short list and the right cells', async () => {
    const { app } = stubApp(5);
    const r = render(() => (
      <AppProvider store={app}>
        <FlowList columns={createColumnState(null)} />
      </AppProvider>
    ));
    await tick();
    const rows = r.container.querySelectorAll('[role="row"][data-id]');
    expect(rows.length).toBe(5);
    expect(rows[0]!.textContent).toContain('https://api.shop-staging.test');
    expect(rows[0]!.textContent).toContain('/api/items/1');
    expect(rows[0]!.textContent).toContain('GET');
    expect(rows[0]!.textContent).toContain('2.0 KB');
    const headers = [...r.container.querySelectorAll('[role="columnheader"]')].map((h) => h.textContent);
    expect(headers).toEqual(['', '#', 'URL', 'Client', 'Method', 'Status', 'Time', 'Duration', 'Request', 'Response', 'SSL', 'Edited', 'Origin', '']);
  });

  it('shows the §2.8 empty state when there are no flows', () => {
    const { app } = stubApp(0);
    const r = render(() => (
      <AppProvider store={app}>
        <FlowList columns={createColumnState(null)} />
      </AppProvider>
    ));
    expect(r.container.textContent).toContain('No flows yet — point a client at 127.0.0.1:8080 or open the browser.');
  });

  it('selects on click and marks paused / agent / killed rows', async () => {
    const { app, entries } = stubApp(3);
    entries[0]!.set({ intercept: 'paused', status: null });
    entries[1]!.set({ origin: 'agent' });
    entries[2]!.set({ intercept: 'killed', status: null });
    const r = render(() => (
      <AppProvider store={app}>
        <FlowList columns={createColumnState(null)} />
      </AppProvider>
    ));
    await tick();
    const rows = r.container.querySelectorAll<HTMLElement>('[role="row"][data-id]');
    expect(rows[0]!.dataset.paused).toBe('true');
    expect(rows[0]!.textContent).toContain('Paused');
    expect(rows[1]!.dataset.agent).toBe('true');
    expect(rows[1]!.textContent).toContain('agent');
    expect(rows[2]!.dataset.killed).toBe('true');
    expect(rows[2]!.textContent).toContain('killed');
    rows[1]!.firstElementChild!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    expect(app.select).toHaveBeenCalledWith('f2', { additive: false, range: false });
    await tick();
    expect(rows[1]!.getAttribute('aria-selected')).toBe('true');
  });
});

describe('virtual window math', () => {
  it('computes the rendered index range for a viewport', () => {
    expect(windowRange(0, 280, 28, 500, 12)).toEqual({ start: 0, end: 21 });
    expect(windowRange(2800, 280, 28, 500, 12)).toEqual({ start: 88, end: 121 });
    expect(windowRange(0, 280, 28, 5, 12)).toEqual({ start: 0, end: 4 });
    expect(windowRange(0, 280, 28, 0, 12)).toEqual({ start: 0, end: -1 });
  });

  it('detects the bottom within one row and counts new rows since leaving it', () => {
    expect(isAtBottom(3664, 367, 4032, 28)).toBe(true);
    expect(isAtBottom(3000, 367, 4032, 28)).toBe(false);
    expect(isAtBottom(0, 500, 200, 28)).toBe(true);
    expect(newSince(120, 100)).toBe(20);
    expect(newSince(90, 100)).toBe(0);
  });
});
