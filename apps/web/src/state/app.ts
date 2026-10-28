// The app store. One instance per page, provided through AppContext.
//
// Performance shape (the §2.10(b) bar: 50 appends/s, no jank):
//  - every flow is its own Solid store, so a response arriving updates one row in place;
//  - list membership is a plain array plus a `version` signal bumped once per animation frame,
//    so the virtualizer re-reads the visible slice at most 60×/s regardless of arrival rate;
//  - filters run over untracked raw snapshots, never through store proxies.

import { batch, createMemo, createRoot, createSignal, untrack, type Accessor } from 'solid-js';
import { createStore, produce, reconcile, type SetStoreFunction } from 'solid-js/store';
import type { BusClient, AgentNotification, FlowNotification, StateNotification, ToolDef } from '~/bus/types';
import { toDetail, toSummary } from '~/bus/normalize';
import type { PocRun } from '~/bus/mock';
import {
  contentFamily,
  type ContentFamily,
  type FlowDetail,
  type FlowId,
  type FlowSummary,
  type MarkColor,
} from '~/model/flow';

export type Chip = 'all' | 'http' | 'https' | 'ws' | 'h1' | 'h2' | ContentFamily;

export type SidebarItem =
  | { kind: 'all' }
  | { kind: 'pinned'; key: string }
  | { kind: 'app'; key: string }
  | { kind: 'domain'; key: string }
  | { kind: 'scope' }
  | { kind: 'findings' }
  | { kind: 'browser' }
  | { kind: 'scripts' }
  | { kind: 'agent' };

export type FilterField =
  | 'url'
  | 'host'
  | 'path'
  | 'query'
  | 'method'
  | 'status'
  | 'req-header'
  | 'res-header'
  | 'req-body'
  | 'res-body'
  | 'content-type'
  | 'client'
  | 'duration'
  | 'size'
  | 'comment'
  | 'origin'
  | 'scope';
export type FilterOp = 'contains' | 'equals' | 'wildcard' | 'regex' | 'not-contains' | 'gt' | 'lt';
export interface FilterRow {
  id: number;
  field: FilterField;
  op: FilterOp;
  value: string;
}

export type Layout = 'horizontal' | 'vertical';
export type Theme = 'system' | 'light' | 'dark';
export type Density = 'dense' | 'default' | 'comfortable';
export type AgentPolicy = StateNotification['agent'];
export type KillMode = 'reset' | '429' | '503';
export type Panel = 'inspector' | 'findings' | 'browser' | 'scope' | 'agent' | 'scripts';

export interface FlowEntry {
  readonly id: FlowId;
  /** Reactive view for rows and the inspector. */
  readonly flow: FlowSummary;
  /** Plain snapshot for filtering/sorting; kept in step with `flow`. */
  raw: FlowSummary;
  set: SetStoreFunction<FlowSummary>;
}

export interface ActivityEntry extends AgentNotification {
  seq: number;
}

interface UiState {
  chip: Chip;
  sidebar: SidebarItem;
  filters: FilterRow[];
  filtersOpen: boolean;
  filterMode: 'and' | 'or';
  quickFilter: string;
  pinned: string[];
  autoSelect: boolean;
  layout: Layout;
  theme: Theme;
  density: Density;
  sidebarOpen: boolean;
  paletteOpen: boolean;
  composeOpen: boolean;
  panel: Panel;
  requestTab: string;
  responseTab: string;
  /** Flow ids picked for the Diff viewer (left, right). */
  diff: [FlowId | null, FlowId | null];
}

interface ProxyState {
  listening: boolean;
  address: string;
  protocol: string;
  armed: boolean;
  pausedIds: FlowId[];
  agent: AgentPolicy;
  agentActionsLastMinute: number;
  throughput: { up: number; down: number };
  memoryBytes: number | null;
  scope: { host: string; rate_limit?: unknown; backoff?: unknown }[];
  findings: PocRun[];
  activity: ActivityEntry[];
  tools: ToolDef[];
  /** Live bus has no push until F4: the store polls `flow.list`. */
  polling: boolean;
  version: string;
}

const STORAGE = {
  pinned: 'aitm.pinned',
  theme: 'aitm.theme',
  density: 'aitm.density',
  layout: 'aitm.layout',
  autoSelect: 'aitm.autoSelect',
  sidebar: 'aitm.sidebarOpen',
} as const;

const read = <T,>(key: string, fallback: T): T => {
  try {
    const v = localStorage.getItem(key);
    return v == null ? fallback : (JSON.parse(v) as T);
  } catch {
    return fallback;
  }
};
const write = (key: string, v: unknown) => {
  try {
    localStorage.setItem(key, JSON.stringify(v));
  } catch {
    /* private mode */
  }
};

export function createAppStore(bus: BusClient) {
  return createRoot(() => {
    // ---- flows ------------------------------------------------------------
    const entries: FlowEntry[] = [];
    const byId = new Map<FlowId, FlowEntry>();
    const [version, setVersion] = createSignal(0);
    let bumpScheduled = false;
    const bump = () => {
      if (bumpScheduled) return;
      bumpScheduled = true;
      requestAnimationFrame(() => {
        bumpScheduled = false;
        setVersion((v) => v + 1);
      });
    };

    const [details, setDetails] = createStore<Record<FlowId, FlowDetail>>({});
    const [detailLoading, setDetailLoading] = createSignal<FlowId | null>(null);
    const [detailError, setDetailError] = createSignal<string | null>(null);

    const [selectedId, setSelectedIdRaw] = createSignal<FlowId | null>(null);
    const [selectedIds, setSelectedIds] = createSignal<ReadonlySet<FlowId>>(new Set<FlowId>());

    const [ui, setUi] = createStore<UiState>({
      chip: 'all',
      sidebar: { kind: 'all' },
      filters: [],
      filtersOpen: false,
      filterMode: 'and',
      quickFilter: '',
      pinned: read<string[]>(STORAGE.pinned, []),
      autoSelect: read(STORAGE.autoSelect, false),
      layout: read<Layout>(STORAGE.layout, 'horizontal'),
      theme: read<Theme>(STORAGE.theme, 'system'),
      density: read<Density>(STORAGE.density, 'dense'),
      sidebarOpen: read(STORAGE.sidebar, true),
      paletteOpen: false,
      composeOpen: false,
      panel: 'inspector',
      requestTab: 'headers',
      responseTab: 'body',
      diff: [null, null],
    });

    const [proxy, setProxy] = createStore<ProxyState>({
      listening: true,
      address: '',
      protocol: '',
      armed: false,
      pausedIds: [],
      agent: 'all',
      agentActionsLastMinute: 0,
      throughput: { up: 0, down: 0 },
      memoryBytes: null,
      scope: [],
      findings: [],
      activity: [],
      tools: [],
      polling: false,
      version: '0.3.0',
    });
    let activitySeq = 0;

    const [toast, setToast] = createSignal<{ text: string; kind: 'error' | 'info' } | null>(null);
    let toastTimer: ReturnType<typeof setTimeout> | null = null;
    const notice = (text: string, kind: 'error' | 'info' = 'info') => {
      setToast({ text, kind });
      if (toastTimer) clearTimeout(toastTimer);
      toastTimer = setTimeout(() => setToast(null), kind === 'error' ? 6000 : 2500);
    };

    // ---- flow ingestion -----------------------------------------------------
    function upsert(summary: FlowSummary): FlowEntry {
      const existing = byId.get(summary.id);
      if (existing) {
        existing.set(reconcile(summary, { key: 'id', merge: true }));
        existing.raw = summary;
        bump();
        return existing;
      }
      const [flow, set] = createStore<FlowSummary>(summary);
      const entry: FlowEntry = { id: summary.id, flow, raw: summary, set };
      entries.push(entry);
      byId.set(summary.id, entry);
      bump();
      if (untrack(() => ui.autoSelect)) setSelectedIdRaw(summary.id);
      return entry;
    }

    function patch(id: FlowId, p: Partial<FlowSummary>) {
      const e = byId.get(id);
      if (!e) return;
      e.set(p as FlowSummary);
      e.raw = { ...e.raw, ...p };
      bump();
    }

    function clearFlows() {
      entries.length = 0;
      byId.clear();
      setDetails(reconcile({}));
      setSelectedIdRaw(null);
      setSelectedIds(new Set<FlowId>());
      setProxy('pausedIds', []);
      bump();
    }

    function recomputePaused() {
      const ids: FlowId[] = [];
      for (const e of entries) if (e.raw.intercept === 'paused') ids.push(e.id);
      setProxy('pausedIds', ids);
    }

    function onFlowEvent(n: FlowNotification) {
      if (n.event === 'cleared') {
        clearFlows();
        return;
      }
      if (!n.summary) return;
      const s = toSummary(n.summary, entries.length + 1);
      upsert(s);
      if (n.event === 'response' || n.event === 'mutated' || n.event === 'meta' || n.event === 'released' || n.event === 'killed') {
        // Detail is stale once anything changed; the inspector refetches on demand.
        if (details[s.id]) setDetails(produce((d) => delete d[s.id]));
        if (untrack(selectedId) === s.id) void loadDetail(s.id, true);
      }
      if (n.event === 'intercepted' || n.event === 'released' || n.event === 'killed') recomputePaused();
    }

    function onState(s: StateNotification) {
      batch(() => {
        setProxy({
          listening: s.listening,
          address: s.address ?? proxy.address,
          protocol: s.protocol ?? proxy.protocol,
          armed: s.intercept_armed,
          agent: s.agent,
          agentActionsLastMinute: s.agent_actions_last_minute ?? 0,
          throughput: s.throughput ?? { up: 0, down: 0 },
          memoryBytes: s.memory_bytes ?? null,
        });
      });
    }

    function onAgent(a: AgentNotification) {
      setProxy('activity', (list) => {
        const next = [...list, { ...a, seq: ++activitySeq }];
        return next.length > 500 ? next.slice(-500) : next;
      });
    }

    bus.onNotification((method, params) => {
      switch (method) {
        case 'notifications/aitm/flow':
          onFlowEvent(params as FlowNotification);
          break;
        case 'notifications/aitm/state':
          onState(params as StateNotification);
          break;
        case 'notifications/aitm/agent':
          onAgent(params as AgentNotification);
          break;
      }
    });

    // ---- polling fallback (bus without F4) --------------------------------
    let pollTimer: ReturnType<typeof setTimeout> | null = null;
    async function pollOnce() {
      try {
        const ids = await bus.call<string[]>('flow.list');
        const fresh = ids.filter((id) => !byId.has(id));
        const pending = ids.filter((id) => {
          const e = byId.get(id);
          return e && e.raw.status == null && e.raw.intercept !== 'killed';
        });
        const want = [...fresh, ...pending.slice(0, 50)];
        const got = await Promise.all(want.map((id) => bus.call('flow.get', { id }).catch(() => null)));
        batch(() => {
          got.forEach((raw, i) => {
            if (raw) upsert(toSummary(raw, ids.indexOf(want[i]!) + 1));
          });
          recomputePaused();
        });
      } catch {
        /* reconnecting; next tick */
      }
    }
    function startPolling() {
      if (pollTimer) return;
      setProxy('polling', true);
      const tick = async () => {
        await pollOnce();
        pollTimer = setTimeout(tick, 500);
      };
      void tick();
    }

    // ---- bootstrap ----------------------------------------------------------
    async function refreshSide() {
      const has = (n: string) => proxy.tools.some((t) => t.name === n);
      const jobs: Promise<unknown>[] = [];
      if (has('scope.list'))
        jobs.push(
          bus
            .call<unknown>('scope.list')
            // The bus returns an array of host strings; fixtures add rate-limit/back-off objects.
            .then((s) => setProxy('scope', Array.isArray(s) ? s.map((e) => (typeof e === 'string' ? { host: e } : (e as ProxyState['scope'][number]))) : []))
            .catch(() => {}),
        );
      if (has('poc.list')) jobs.push(bus.call<PocRun[]>('poc.list').then((p) => setProxy('findings', p)).catch(() => {}));
      if (has('agent.status'))
        jobs.push(
          bus
            .call<{ policy: AgentPolicy; actions_last_minute: number; log?: AgentNotification[] }>('agent.status')
            .then((a) => {
              setProxy({ agent: a.policy, agentActionsLastMinute: a.actions_last_minute });
              // The activity log rides on agent.status as `log` (no agent.activity command on the bus).
              if (Array.isArray(a.log) && !has('agent.activity')) setProxy('activity', a.log.map((e) => ({ ...e, seq: ++activitySeq })));
            })
            .catch(() => {}),
        );
      if (has('agent.activity'))
        jobs.push(
          bus
            .call<AgentNotification[]>('agent.activity')
            .then((list) => setProxy('activity', list.map((a) => ({ ...a, seq: ++activitySeq }))))
            .catch(() => {}),
        );
      // No read for the intercept state exists: `flow.intercept {}` ARMS (enabled defaults to
      // true), so the armed flag comes only from notifications/aitm/state and our own calls.
      if (has('proxy.status'))
        jobs.push(
          bus
            .call<{ listening?: boolean | string | null; address?: string | null; capturing?: boolean; paused?: number | boolean; protocol?: string }>('proxy.status')
            .then((s) =>
              setProxy({
                // Landed shape: `listening` is the bound address (string|null) — the core is
                // moving to `listening: bool` + `address`; `capturing` is the record toggle;
                // `paused` is a COUNT of intercepted flows. The store's `listening` flag is the
                // capture state.
                listening: s.capturing ?? (typeof s.paused === 'boolean' ? !s.paused : proxy.listening),
                address: (typeof s.listening === 'string' ? s.listening : s.address) ?? proxy.address,
                protocol: s.protocol ?? proxy.protocol,
              }),
            )
            .catch(() => {}),
        );
      await Promise.all(jobs);
    }

    async function bootstrap() {
      bus.connect();
      try {
        const tools = await bus.tools();
        setProxy('tools', tools);
        await refreshSide();
        if (!tools.some((t) => t.name === 'flow.subscribe') && bus.address !== 'fixtures') startPolling();
        else await pollOnce();
      } catch (e) {
        notice((e as Error).message, 'error');
      }
    }
    void bootstrap();

    // ---- derived --------------------------------------------------------------
    const pinnedSet = createMemo(() => new Set(ui.pinned));

    function matchesChip(f: FlowSummary, chip: Chip): boolean {
      switch (chip) {
        case 'all':
          return true;
        case 'http':
          return f.scheme === 'http';
        case 'https':
          return f.scheme === 'https';
        case 'ws':
          return f.kind === 'websocket';
        case 'h1':
          return f.httpVersion === 'HTTP/1.1';
        case 'h2':
          return f.httpVersion === 'HTTP/2';
        default:
          return f.kind === 'http' && contentFamily(f) === chip;
      }
    }

    function matchesSidebar(f: FlowSummary, s: SidebarItem): boolean {
      switch (s.kind) {
        case 'app':
          return f.client.id === s.key;
        case 'domain':
        case 'pinned':
          return f.authority === s.key;
        case 'scope':
          return f.inScope;
        default:
          return true;
      }
    }

    const regexCache = new Map<string, RegExp | null>();
    const regexOf = (v: string, wildcard: boolean) => {
      const key = (wildcard ? 'w:' : 'r:') + v;
      let r = regexCache.get(key);
      if (r === undefined) {
        try {
          r = wildcard ? new RegExp('^' + v.split('*').map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$', 'i') : new RegExp(v, 'i');
        } catch {
          r = null;
        }
        regexCache.set(key, r);
      }
      return r;
    };

    function fieldValue(f: FlowSummary, field: FilterField): string | number | null {
      switch (field) {
        case 'url':
          return `${f.scheme}://${f.authority}${f.path}${f.query ? '?' + f.query : ''}`;
        case 'host':
          return f.authority;
        case 'path':
          return f.path;
        case 'query':
          return f.query;
        case 'method':
          return f.kind === 'websocket' ? 'WS' : f.method;
        case 'status':
          return f.intercept === 'paused' ? 'paused' : f.intercept === 'killed' ? 'killed' : f.status;
        case 'content-type':
          return f.contentType;
        case 'client':
          return f.client.name;
        case 'duration':
          return f.durationMs;
        case 'size':
          return (f.reqSize ?? 0) + (f.resSize ?? 0);
        case 'comment':
          return f.comment;
        case 'origin':
          return f.origin;
        case 'scope':
          return f.inScope ? 'in' : 'out';
        case 'req-header':
        case 'res-header':
        case 'req-body':
        case 'res-body': {
          const d = untrack(() => details[f.id]);
          if (!d) return null;
          if (field === 'req-header') return d.request.headers.map((h) => `${h.name}: ${h.value}`).join('\n');
          if (field === 'res-header') return d.response?.headers.map((h) => `${h.name}: ${h.value}`).join('\n') ?? null;
          if (field === 'req-body') return d.request.body.text;
          return d.response?.body.text ?? null;
        }
      }
    }

    function matchesRow(f: FlowSummary, row: FilterRow): boolean {
      if (!row.value) return true;
      const v = fieldValue(f, row.field);
      if (row.op === 'gt' || row.op === 'lt') {
        const n = typeof v === 'number' ? v : Number(v);
        const t = Number(row.value);
        if (!Number.isFinite(n) || !Number.isFinite(t)) return false;
        return row.op === 'gt' ? n > t : n < t;
      }
      const s = v == null ? '' : String(v);
      switch (row.op) {
        case 'contains':
          return s.toLowerCase().includes(row.value.toLowerCase());
        case 'not-contains':
          return !s.toLowerCase().includes(row.value.toLowerCase());
        case 'equals':
          return s.toLowerCase() === row.value.toLowerCase();
        case 'wildcard':
          return regexOf(row.value, true)?.test(s) ?? false;
        case 'regex':
          return regexOf(row.value, false)?.test(s) ?? false;
      }
    }

    /** The rows the list shows, in capture order (newest at the bottom, §3.1). */
    const visible = createMemo<FlowEntry[]>(() => {
      version();
      const chip = ui.chip;
      const side = ui.sidebar;
      const rows = ui.filters.filter((r) => r.value);
      const mode = ui.filterMode;
      const quick = ui.quickFilter.trim().toLowerCase();
      const out: FlowEntry[] = [];
      for (const e of entries) {
        const f = e.raw;
        if (!matchesChip(f, chip) || !matchesSidebar(f, side)) continue;
        if (quick && !`${f.authority}${f.path}${f.query ?? ''} ${f.method} ${f.status ?? ''} ${f.client.name}`.toLowerCase().includes(quick)) continue;
        if (rows.length) {
          const ok = mode === 'and' ? rows.every((r) => matchesRow(f, r)) : rows.some((r) => matchesRow(f, r));
          if (!ok) continue;
        }
        out.push(e);
      }
      return out;
    });

    const total = createMemo(() => (version(), entries.length));

    /** Sidebar counts: apps and domains with flow counts, pinned first. */
    const groups = createMemo(() => {
      version();
      const apps = new Map<string, { name: string; count: number }>();
      const domains = new Map<string, number>();
      let inScope = 0;
      for (const e of entries) {
        const f = e.raw;
        const a = apps.get(f.client.id);
        if (a) a.count++;
        else apps.set(f.client.id, { name: f.client.name, count: 1 });
        domains.set(f.authority, (domains.get(f.authority) ?? 0) + 1);
        if (f.inScope) inScope++;
      }
      return {
        apps: [...apps.entries()].map(([id, v]) => ({ id, ...v })).sort((x, y) => y.count - x.count),
        domains: [...domains.entries()].map(([host, count]) => ({ host, count })).sort((x, y) => y.count - x.count),
        inScope,
      };
    });

    const selected = createMemo<FlowEntry | null>(() => {
      version();
      const id = selectedId();
      return id ? (byId.get(id) ?? null) : null;
    });

    const selectedDetail = createMemo<FlowDetail | null>(() => {
      const id = selectedId();
      return id ? (details[id] ?? null) : null;
    });

    const oldestPaused = createMemo<FlowEntry | null>(() => {
      const sel = selected();
      if (sel && sel.flow.intercept === 'paused') return sel;
      const id = proxy.pausedIds[0];
      return id ? (byId.get(id) ?? null) : null;
    });

    // ---- actions ------------------------------------------------------------------
    async function loadDetail(id: FlowId, force = false): Promise<FlowDetail | null> {
      if (!force && details[id]) return details[id]!;
      const has = (n: string) => proxy.tools.some((t) => t.name === n);
      setDetailLoading(id);
      setDetailError(null);
      try {
        const e = byId.get(id);
        const raw = has('flow.detail') ? await bus.call('flow.detail', { id }) : await bus.call('flow.get', { id });
        const d = toDetail(raw, e?.raw.seq ?? 0);
        if (!has('flow.detail')) {
          // Today's bus has no bodies/headers (F5): keep what the summary knows.
          d.request = { headers: [], body: { text: null, contentType: null, size: 0, truncated: false } };
          d.response = null;
        }
        setDetails(id, d);
        if (e) upsert({ ...e.raw, ...toSummary(raw, e.raw.seq) });
        return d;
      } catch (err) {
        setDetailError((err as Error).message);
        return null;
      } finally {
        if (detailLoading() === id) setDetailLoading(null);
      }
    }

    function select(id: FlowId | null, opts: { additive?: boolean; range?: boolean } = {}) {
      batch(() => {
        if (id && opts.additive) {
          const next = new Set(selectedIds());
          if (next.has(id)) next.delete(id);
          else next.add(id);
          setSelectedIds(next);
          setSelectedIdRaw(id);
        } else if (id && opts.range && selectedId()) {
          const list = visible();
          const a = list.findIndex((e) => e.id === selectedId());
          const b = list.findIndex((e) => e.id === id);
          if (a >= 0 && b >= 0) {
            const [lo, hi] = a < b ? [a, b] : [b, a];
            setSelectedIds(new Set(list.slice(lo, hi + 1).map((e) => e.id)));
          }
          setSelectedIdRaw(id);
        } else {
          setSelectedIds(id ? new Set<FlowId>([id]) : new Set<FlowId>());
          setSelectedIdRaw(id);
        }
        if (id) {
          setUi('panel', 'inspector');
          void loadDetail(id);
        }
      });
    }

    /** Replace the multi-selection wholesale (e.g. a shift-range computed in the list's sort order). */
    function setSelection(ids: readonly FlowId[], anchor: FlowId | null = ids[ids.length - 1] ?? null) {
      batch(() => {
        setSelectedIds(new Set<FlowId>(ids));
        setSelectedIdRaw(anchor);
        if (anchor) {
          setUi('panel', 'inspector');
          void loadDetail(anchor);
        }
      });
    }

    function moveSelection(delta: number) {
      const list = visible();
      if (!list.length) return;
      const cur = selectedId();
      const i = cur ? list.findIndex((e) => e.id === cur) : -1;
      const next = Math.max(0, Math.min(list.length - 1, i < 0 ? (delta > 0 ? 0 : list.length - 1) : i + delta));
      select(list[next]!.id);
    }

    const guarded = async <T,>(label: string, fn: () => Promise<T>): Promise<T | null> => {
      try {
        return await fn();
      } catch (e) {
        notice(`${label}: ${(e as Error).message}`, 'error');
        return null;
      }
    };

    const actions = {
      select,
      setSelection,
      moveSelection,
      loadDetail,
      notice,
      clearToast: () => setToast(null),

      setChip: (c: Chip) => setUi('chip', c),
      setSidebar: (s: SidebarItem) => batch(() => {
        setUi('sidebar', s);
        const panel: Panel =
          s.kind === 'findings' ? 'findings' : s.kind === 'browser' ? 'browser' : s.kind === 'scope' ? 'scope' : s.kind === 'agent' ? 'agent' : s.kind === 'scripts' ? 'scripts' : 'inspector';
        setUi('panel', panel);
      }),
      setPanel: (p: Panel) => setUi('panel', p),
      setQuickFilter: (q: string) => setUi('quickFilter', q),
      setFilters: (rows: FilterRow[]) => setUi('filters', rows),
      setFilterMode: (m: 'and' | 'or') => setUi('filterMode', m),
      toggleFilters: (open?: boolean) => setUi('filtersOpen', open ?? !ui.filtersOpen),
      setRequestTab: (t: string) => setUi('requestTab', t),
      setResponseTab: (t: string) => setUi('responseTab', t),
      setDiff: (left: FlowId | null, right: FlowId | null) => setUi('diff', [left, right]),
      togglePin: (host: string) => {
        const next = ui.pinned.includes(host) ? ui.pinned.filter((h) => h !== host) : [...ui.pinned, host];
        setUi('pinned', next);
        write(STORAGE.pinned, next);
      },
      setAutoSelect: (v: boolean) => {
        setUi('autoSelect', v);
        write(STORAGE.autoSelect, v);
      },
      setLayout: (l: Layout) => {
        setUi('layout', l);
        write(STORAGE.layout, l);
      },
      setTheme: (t: Theme) => {
        setUi('theme', t);
        write(STORAGE.theme, t);
        if (t === 'system') document.documentElement.removeAttribute('data-theme');
        else document.documentElement.setAttribute('data-theme', t);
        try {
          if (t === 'system') localStorage.removeItem('aitm.theme');
          else localStorage.setItem('aitm.theme', t);
        } catch {
          /* ignore */
        }
      },
      setDensity: (d: Density) => {
        setUi('density', d);
        write(STORAGE.density, d);
        document.documentElement.setAttribute('data-density', d);
        try {
          localStorage.setItem('aitm.density', d);
        } catch {
          /* ignore */
        }
      },
      toggleSidebar: () => {
        setUi('sidebarOpen', !ui.sidebarOpen);
        write(STORAGE.sidebar, ui.sidebarOpen);
      },
      openPalette: (open = true) => setUi('paletteOpen', open),
      openCompose: (open = true) => setUi('composeOpen', open),

      // --- bus-backed ---
      arm: (enabled: boolean) =>
        guarded('intercept', async () => {
          const r = await bus.call<boolean>('flow.intercept', { enabled });
          setProxy('armed', typeof r === 'boolean' ? r : enabled);
        }),
      resume: (id: FlowId) =>
        guarded('resume', async () => {
          await bus.call('flow.resume', { id });
          patch(id, { intercept: 'resumed' });
          recomputePaused();
        }),
      resumeAll: () =>
        guarded('resume all', async () => {
          for (const id of [...proxy.pausedIds]) {
            await bus.call('flow.resume', { id });
            patch(id, { intercept: 'resumed' });
          }
          recomputePaused();
        }),
      kill: (id: FlowId, mode: KillMode = 'reset') =>
        guarded('kill', async () => {
          await bus.call('flow.kill', mode === 'reset' ? { id } : { id, mode });
          patch(id, { intercept: 'killed', status: null, durationMs: null });
          recomputePaused();
        }),
      mutate: (id: FlowId, edits: { method?: string; path?: string; headers?: Record<string, string> | { name: string; value: string }[]; body?: string }) =>
        guarded('edit', async () => {
          await bus.call('flow.mutate', { id, edits });
          patch(id, { edited: true });
          await loadDetail(id, true);
        }),
      replay: (id: FlowId) =>
        guarded('replay', async () => {
          const newId = await bus.call<string>('flow.replay', { id });
          notice(`Replayed as a new flow`);
          return newId;
        }),
      compose: (req: { method: string; url: string; headers: Record<string, string>; body: string }) =>
        guarded('send', async () => {
          const id = await bus.call<string>('request.send', req);
          setUi('composeOpen', false);
          return id;
        }),
      addScope: (host: string) =>
        guarded('scope', async () => {
          await bus.call('scope.add', { host });
          await refreshSide();
          for (const e of entries) if (!e.raw.inScope && e.raw.authority === host) patch(e.id, { inScope: true });
        }),
      removeScope: (host: string) =>
        guarded('scope', async () => {
          await bus.call('scope.remove', { host });
          await refreshSide();
        }),
      setAgentPolicy: (policy: AgentPolicy) =>
        guarded('agent', async () => {
          await bus.call('agent.set', { policy });
          setProxy('agent', policy);
        }),
      toggleCapture: () =>
        guarded('capture', async () => {
          await bus.call(proxy.listening ? 'proxy.pause' : 'proxy.resume');
          setProxy('listening', !proxy.listening);
        }),
      clear: () =>
        guarded('clear', async () => {
          await bus.call('flow.clear');
          clearFlows();
        }),
      mark: (id: FlowId, mark: MarkColor | null) =>
        guarded('mark', async () => {
          // The bus takes `marks: [str]` and replaces the set; the UI keeps one mark per flow.
          await bus.call('flow.mark', { id, marks: mark ? [mark] : [] });
          patch(id, { mark });
        }),
      comment: (id: FlowId, text: string) =>
        guarded('comment', async () => {
          await bus.call('flow.comment', { id, text });
          patch(id, { comment: text || null });
        }),
      buildPoc: (flowId: FlowId, name: string, param?: string) =>
        guarded('build PoC', async () => {
          // poc.build returns the YAML text. Until poc.list (F13) exists the panel cannot show
          // it, so the text is also put on the clipboard.
          const r = await bus.call<string | { yaml?: string }>('poc.build', param ? { flow_id: flowId, name, param } : { flow_id: flowId, name });
          const yaml = typeof r === 'string' ? r : (r?.yaml ?? null);
          await refreshSide();
          const listed = proxy.tools.some((t) => t.name === 'poc.list');
          if (listed) setUi('panel', 'findings');
          if (yaml && !listed) {
            try {
              await navigator.clipboard.writeText(yaml);
              notice(`PoC "${name}" built — YAML copied (poc.list will show it here once the core lists runs)`);
            } catch {
              notice(`PoC "${name}" built`);
            }
          }
          return yaml;
        }),
      runPoc: (pocPath: string, target?: string, vars?: Record<string, string>) =>
        guarded('run PoC', async () => {
          const r = await bus.call<PocRun>('poc.run', { poc_path: pocPath, ...(target ? { target } : {}), ...(vars ? { vars } : {}) });
          await refreshSide();
          return r;
        }),
      refreshSide,
      call: <T,>(tool: string, args?: Record<string, unknown>) => bus.call<T>(tool, args),
    };

    return {
      bus,
      ui,
      proxy,
      version,
      entries,
      byId,
      visible,
      total,
      groups,
      pinnedSet,
      selectedId,
      selectedIds,
      selected,
      selectedDetail,
      detailLoading,
      detailError,
      oldestPaused,
      details,
      toast,
      ...actions,
    };
  });
}

export type AppStore = ReturnType<typeof createAppStore>;
export type { Accessor };
