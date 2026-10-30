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
  | { kind: 'scan' }
  | { kind: 'browser' }
  | { kind: 'scripts' }
  | { kind: 'l4' }
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
export type Panel = 'inspector' | 'findings' | 'scan' | 'browser' | 'scope' | 'agent' | 'scripts';

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
  /** True while the poll loop is the live source (no push notifications arriving); false on push or on the static fixtures bus. */
  polling: boolean;
  /** The core's version, from `proxy.status`; empty until it answers (never a made-up number). */
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

    // L4 flows are not HTTP `FlowEntry`s — they live in the lifted L4 store and come from
    // `l4.flow.list`. The store registers their ids here so selection routes to the L4 inspector
    // (not the HTTP `flow.detail` path) and the unified list knows which ids are L4.
    const [l4Ids, setL4IdsSig] = createSignal<ReadonlySet<FlowId>>(new Set<FlowId>());

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
      version: '',
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

    // When the last flow/state notification landed. The poll loop backs off only while push is
    // demonstrably flowing — never because the core merely *advertises* `flow.subscribe`.
    let lastPushAt = Number.NEGATIVE_INFINITY;

    bus.onNotification((method, params) => {
      switch (method) {
        case 'notifications/aitm/flow':
          lastPushAt = Date.now();
          onFlowEvent(params as FlowNotification);
          break;
        case 'notifications/aitm/state':
          lastPushAt = Date.now();
          onState(params as StateNotification);
          break;
        case 'notifications/aitm/agent':
          onAgent(params as AgentNotification);
          break;
      }
    });

    // ---- live updates: poll unless push is demonstrably flowing -------------
    // Every real bus is polled. `flow.subscribe` being advertised proves nothing — nothing here calls
    // it, and the /bus bridge pushes no notifications — so the loop runs regardless, and only skips
    // its work while a flow/state notification arrived within PUSH_FRESH_MS. Even then a heartbeat
    // poll runs every PUSH_FRESH_MS, so a push that dies quietly (or carries only state) cannot freeze
    // the list. The static `fixtures` bus is a snapshot and is never polled.
    const POLL_MS = 500;
    const STATUS_EVERY_TICKS = 4; // ~2 s while polling
    const PUSH_FRESH_MS = 10_000;
    let pollTimer: ReturnType<typeof setTimeout> | null = null;
    let pollLoopOn = false;
    let pollTicks = 0;
    let lastPollAt = Number.NEGATIVE_INFINITY;
    async function pollOnce() {
      lastPollAt = Date.now();
      try {
        const ids = await bus.call<string[]>('flow.list');
        const fresh = ids.filter((id) => !byId.has(id));
        const pending = ids.filter((id) => {
          const e = byId.get(id);
          return e && e.raw.status == null && e.raw.intercept !== 'killed';
        });
        const want = [...fresh, ...pending.slice(0, 50)];
        // `flow.detail {body: none}` is a summary with headers, sizes, times and the connection
        // — everything a row shows — at the cost of one call per flow, like `flow.get`.
        const rich = proxy.tools.some((t) => t.name === 'flow.detail');
        const got = await Promise.all(
          want.map((id) => (rich ? bus.call('flow.detail', { id, body: 'none' }) : bus.call('flow.get', { id })).catch(() => null)),
        );
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
    async function pollStatus() {
      if (!proxy.tools.some((t) => t.name === 'proxy.status')) return;
      try {
        const s = await bus.call<{ capturing?: boolean; intercept_armed?: boolean; address?: string | null; paused?: number; version?: unknown }>('proxy.status');
        setProxy({
          listening: s.capturing ?? proxy.listening,
          armed: typeof s.intercept_armed === 'boolean' ? s.intercept_armed : proxy.armed,
          address: s.address ?? proxy.address,
          version: typeof s.version === 'string' ? s.version : proxy.version,
        });
      } catch {
        /* next tick */
      }
    }
    function startPolling() {
      if (pollLoopOn) return;
      pollLoopOn = true;
      const tick = async () => {
        pollTimer = null;
        // A closed bus ends the loop (nothing is rescheduled), so no timer outlives it.
        if (bus.state() === 'closed') {
          pollLoopOn = false;
          setProxy('polling', false);
          return;
        }
        const now = Date.now();
        const sincePush = now - lastPushAt;
        const pushLive = sincePush >= 0 && sincePush < PUSH_FRESH_MS;
        setProxy('polling', !pushLive);
        if (!pushLive || now - lastPollAt >= PUSH_FRESH_MS) {
          await pollOnce();
          // The listener/intercept state is polled too: every ~2 s on the loop, on each heartbeat under push.
          if (pushLive || ++pollTicks % STATUS_EVERY_TICKS === 0) await pollStatus();
        }
        pollTimer = setTimeout(tick, POLL_MS);
      };
      pollTimer = setTimeout(tick, POLL_MS);
    }

    // ---- PoC session state ----------------------------------------------------
    // The core's poc.list returns library summaries ({id, title, severity, poc_path}) and keeps
    // no run history, and poc.build returns YAML text without writing a file. The session keeps
    // what the operator would otherwise lose: built-but-unsaved PoCs, fetched sources, and the
    // last run result per path, merged into one list for the Findings panel.
    const pocSources = new Map<string, string>();
    const pocRuns = new Map<string, Partial<PocRun>>();
    const [localPocs, setLocalPocs] = createSignal<PocRun[]>([]);
    let lastBusPocs: unknown[] = [];

    function mergeFindings(list: unknown[]): PocRun[] {
      lastBusPocs = list;
      const fromBus = list.map((raw): PocRun => {
        const r = (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
        const pocPath = typeof r.poc_path === 'string' ? r.poc_path : '';
        const run = pocRuns.get(pocPath) ?? {};
        const sev = typeof r.severity === 'string' ? r.severity : 'medium';
        return {
          id: typeof r.id === 'string' ? r.id : pocPath,
          title: typeof r.title === 'string' && r.title ? r.title : (pocPath.split('/').pop() ?? 'PoC'),
          severity: (['critical', 'high', 'medium', 'low', 'info'].includes(sev) ? sev : 'medium') as PocRun['severity'],
          target: typeof r.target === 'string' ? r.target : '',
          passed: typeof r.passed === 'boolean' ? r.passed : (run.passed ?? false),
          at: typeof r.at === 'number' ? r.at : (run.at ?? 0),
          origin: r.origin === 'agent' ? 'agent' : 'human',
          poc_path: pocPath,
          yaml: typeof r.yaml === 'string' ? r.yaml : (pocSources.get(pocPath) ?? ''),
          finding_capture: typeof r.finding_capture === 'string' ? r.finding_capture : (run.finding_capture ?? ''),
          screenshot_path: typeof r.screenshot_path === 'string' && r.screenshot_path ? r.screenshot_path : (run.screenshot_path ?? null),
          evaluated: Array.isArray(r.evaluated) ? (r.evaluated as PocRun['evaluated']) : (run.evaluated ?? []),
          ...(typeof r.description === 'string' ? { description: r.description } : {}),
          ...(pocRuns.has(pocPath) ? { ran: true } : {}),
        };
      });
      const listedPaths = new Set(fromBus.map((p) => p.poc_path));
      return [...localPocs().filter((p) => !listedPaths.has(p.poc_path)), ...fromBus];
    }

    /** Loads a PoC's YAML through poc.get once and patches it into the list. */
    async function ensurePocSource(pocPath: string): Promise<string | null> {
      if (!pocPath) return null;
      const cached = pocSources.get(pocPath);
      if (cached) return cached;
      if (!proxy.tools.some((t) => t.name === 'poc.get')) return null;
      try {
        const r = await bus.call<{ yaml?: string; source?: string; description?: string }>('poc.get', { poc_path: pocPath });
        const yaml = r.yaml ?? r.source ?? '';
        if (yaml) pocSources.set(pocPath, yaml);
        setProxy('findings', mergeFindings(lastBusPocs));
        return yaml || null;
      } catch (e) {
        notice(`poc.get: ${(e as Error).message}`, 'error');
        return null;
      }
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
      if (has('poc.list'))
        jobs.push(bus.call<unknown[]>('poc.list').then((p) => setProxy('findings', mergeFindings(Array.isArray(p) ? p : []))).catch(() => {}));
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
            .call<{
              listening?: boolean | string | null;
              address?: string | null;
              capturing?: boolean;
              paused?: number | boolean;
              intercept_armed?: boolean;
              protocol?: string;
              version?: unknown;
            }>('proxy.status')
            .then((s) =>
              setProxy({
                // Live shape: `listening: bool` + `address` (an older build sent the address as
                // `listening`); `capturing` is the record toggle; `paused` is a COUNT of
                // intercepted flows; `intercept_armed` is the only read of the armed state.
                // The store's `listening` flag is the capture state.
                listening: s.capturing ?? (typeof s.paused === 'boolean' ? !s.paused : proxy.listening),
                address: (typeof s.listening === 'string' ? s.listening : s.address) ?? proxy.address,
                protocol: s.protocol ?? proxy.protocol,
                armed: typeof s.intercept_armed === 'boolean' ? s.intercept_armed : proxy.armed,
                // The binary's version; a core older than the field sends none, and nothing is better than a guess.
                version: typeof s.version === 'string' ? s.version : proxy.version,
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
        await pollOnce(); // the snapshot of what was captured before this page connected
      } catch (e) {
        notice((e as Error).message, 'error');
      }
      // Outside the try on purpose: a failed bootstrap (tools/list rejected, say) must not leave the
      // list frozen. The loop keeps trying every tick, and `flow.list` needs no catalogue.
      if (bus.address !== 'fixtures') startPolling();
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
        case 'l4':
          // The L4 focus view: hide HTTP/WebSocket so only L4 session rows show (the list appends
          // them). L4 rows are not FlowEntries, so they are never excluded by this HTTP predicate.
          return false;
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

    /** True when the selected id is an L4 session — the lower region shows the L4 inspector. */
    const selectedIsL4 = createMemo<boolean>(() => {
      const id = selectedId();
      return !!id && l4Ids().has(id);
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
        // An L4 session: single-select, open the L4 inspector, and skip the HTTP detail fetch
        // (L4 detail is `l4.flow.get`, held by the L4 store, not `flow.detail`).
        if (id && l4Ids().has(id)) {
          setSelectedIds(new Set<FlowId>([id]));
          setSelectedIdRaw(id);
          setUi('panel', 'inspector');
          return;
        }
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
        // `l4` is a FILTER over the one unified list (like `scope`), not a panel: it stays on the
        // inspector so the lower region shows the HTTP or L4 inspector by the selected flow's kind.
        const panel: Panel =
          s.kind === 'findings' ? 'findings' : s.kind === 'scan' ? 'scan' : s.kind === 'browser' ? 'browser' : s.kind === 'scope' ? 'scope' : s.kind === 'agent' ? 'agent' : s.kind === 'scripts' ? 'scripts' : 'inspector';
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
          // Abort modes are F3; today's flow.kill rejects unknown parameters, so send `mode`
          // only when the schema declares it.
          const hasMode = !!proxy.tools.find((t) => t.name === 'flow.kill')?.inputSchema.properties?.mode;
          await bus.call('flow.kill', mode === 'reset' || !hasMode ? { id } : { id, mode });
          patch(id, { intercept: 'killed', status: null, durationMs: null });
          recomputePaused();
          // Trust but verify: the core has been seen to resume a killed flow. Re-read the state
          // and say so rather than leaving a row that lies.
          if (proxy.tools.some((t) => t.name === 'flow.detail')) {
            setTimeout(() => {
              void bus
                .call('flow.detail', { id, body: 'none' })
                .then((raw) => {
                  const s = toSummary(raw, byId.get(id)?.raw.seq ?? 0);
                  if (s.intercept !== 'killed') {
                    upsert(s);
                    notice(`flow.kill reported success but the core ${s.intercept === 'resumed' ? 'resumed' : 'kept'} the flow — it reached upstream (core bug)`, 'error');
                  }
                })
                .catch(() => {});
            }, 400);
          }
        }),
      mutate: (id: FlowId, edits: { method?: string; path?: string; headers?: Record<string, string> | { name: string; value: string }[]; body?: string }) =>
        guarded('edit', async () => {
          // The bus takes `headers` as a name→value object (each replaces that header). A header
          // the operator deleted cannot be expressed yet — flow.mutate has no removal form.
          const wire: Record<string, unknown> = { ...edits };
          let removed: string[] = [];
          if (Array.isArray(edits.headers)) {
            const kept = new Set(edits.headers.map((h) => h.name.trim().toLowerCase()).filter(Boolean));
            removed = (details[id]?.request.headers ?? []).map((h) => h.name).filter((n) => !kept.has(n.toLowerCase()));
            wire.headers = Object.fromEntries(edits.headers.filter((h) => h.name.trim()).map((h) => [h.name.trim(), h.value]));
          }
          await bus.call('flow.mutate', { id, edits: wire });
          if (removed.length)
            notice(`${removed.length} removed header${removed.length === 1 ? '' : 's'} (${removed.join(', ')}) stay on the wire — flow.mutate cannot delete headers yet`, 'error');
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
          // request.send takes the parts, not a URL: {scheme, authority, path (with query), method, headers, body}.
          const u = new URL(req.url);
          const args: Record<string, unknown> = {
            scheme: u.protocol.replace(/:$/, ''),
            authority: u.host,
            path: `${u.pathname}${u.search}`,
            method: req.method,
            headers: req.headers,
          };
          if (req.body) args.body = req.body;
          const id = await bus.call<string>('request.send', args);
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
          // poc.build returns the YAML text and writes no file, so the result would be lost: it
          // is kept as a session-local finding (Export saves it; drop the file into poc.dir to run
          // it) and copied to the clipboard.
          const r = await bus.call<string | { yaml?: string; poc_path?: string }>('poc.build', param ? { flow_id: flowId, name, param } : { flow_id: flowId, name });
          const yaml = typeof r === 'string' ? r : (r?.yaml ?? null);
          await refreshSide();
          const savedPath = typeof r === 'object' && r && typeof r.poc_path === 'string' ? r.poc_path : null;
          const listed = savedPath ? proxy.findings.some((p) => p.poc_path === savedPath) : false;
          if (yaml && !listed) {
            const flow = byId.get(flowId)?.raw;
            const entry: PocRun = {
              id: `local:${name}:${Date.now()}`,
              title: name,
              severity: 'medium',
              target: flow ? `${flow.scheme}://${flow.authority}` : '',
              passed: false,
              at: Date.now(),
              origin: 'human',
              poc_path: '',
              yaml,
              finding_capture: flowId,
              screenshot_path: null,
              evaluated: [],
              local: true,
            };
            setLocalPocs((l) => [entry, ...l]);
            setProxy('findings', mergeFindings(lastBusPocs));
            try {
              await navigator.clipboard.writeText(yaml);
              notice(`PoC "${name}" built — kept in Findings and copied; save the YAML into poc.dir to run it`);
            } catch {
              notice(`PoC "${name}" built — kept in Findings; export the YAML into poc.dir to run it`);
            }
          }
          setUi('panel', 'findings');
          return yaml;
        }),
      runPoc: (pocPath: string, target?: string, vars?: Record<string, string>) =>
        guarded('run PoC', async () => {
          const r = await bus.call<Partial<PocRun> & { passed?: boolean }>('poc.run', { poc_path: pocPath, ...(target ? { target } : {}), ...(vars ? { vars } : {}) });
          // The core keeps no run history: remember this run for the Findings detail.
          pocRuns.set(pocPath, {
            passed: r.passed ?? false,
            at: Date.now(),
            ...(typeof r.finding_capture === 'string' ? { finding_capture: r.finding_capture } : {}),
            screenshot_path: typeof r.screenshot_path === 'string' && r.screenshot_path ? r.screenshot_path : null,
            evaluated: Array.isArray(r.evaluated) ? r.evaluated : [],
          });
          await refreshSide();
          setProxy('findings', mergeFindings(lastBusPocs));
          notice(`PoC ${r.passed ? 'passed' : 'did not pass'}${Array.isArray(r.evaluated) ? ` — ${r.evaluated.filter((e) => e.matched).length} of ${r.evaluated.length} assertions matched` : ''}`);
          return r as PocRun;
        }),
      // The scanner's scope-bound discovery launch (Stage 1). The Scan view binds `target` to an
      // in-scope host, so the call is deny-by-default at the UI; the core re-gates it anyway.
      scanDiscover: (args: Record<string, unknown>) => guarded('scan', () => bus.call<unknown>('scan.discover', args)),
      ensurePocSource,
      refreshSide,
      /** The lifted L4 store calls this on each refresh so selection/list routing knows L4 ids. */
      setL4Ids: (ids: readonly FlowId[]) => setL4IdsSig(new Set<FlowId>(ids)),
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
      selectedIsL4,
      l4Ids,
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
