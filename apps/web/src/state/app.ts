// The app store. One instance per page, provided through AppContext.
//
// Performance shape (the §2.10(b) bar: 50 appends/s, no jank):
//  - every flow is its own Solid store, so a response arriving updates one row in place;
//  - list membership is a plain array plus a `version` signal bumped once per animation frame,
//    so the virtualizer re-reads the visible slice at most 60×/s regardless of arrival rate;
//  - filters run over untracked raw snapshots, never through store proxies.

import { batch, createEffect, createMemo, createRoot, createSignal, on, untrack, type Accessor } from 'solid-js';
import { createStore, produce, reconcile, type SetStoreFunction } from 'solid-js/store';
import type { BusClient, AgentNotification, CAStatusWire, FlowEventKind, FlowNotification, PocRun, StateNotification, SystemProxyStatus, ToolDef } from '~/bus/types';
import { toAgentEntry, toDetail, toSummary } from '~/bus/normalize';
import { isUiPollNoise, ownOriginOf } from '~/bus/noise';
import { parseCATrust, type CATrustStatus } from './caTrust';
import { mergeSystemProxy, parseSystemProxy } from './systemProxy';
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
  /** True while the poll loop is the live source (no push notifications arriving); false while push notifications are fresh. */
  polling: boolean;
  /** The core's version, from `proxy.status`; empty until it answers (never a made-up number). */
  version: string;
  /**
   * `proxy.status.system_proxy` (spec D6), parsed on every status read; null until the core answers
   * or when it is older than the field. The toolbar pill word and menu derive from it (D15).
   */
  systemProxy: SystemProxyStatus | null;
  /** This client's own `proxy.system.set` / `unset` is in flight (another client's is `systemProxy.setting`). */
  systemProxySetting: boolean;
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
    // What lives here: the push coalescer's queue, timer and flags, the row-fetch tickets and the clear
    // epoch, and the single-flight poll slot. It is declared ahead of `clearFlows` (just below), which
    // drops the pending set and bumps the epoch long before the coalescer and the loop are defined.
    // The push clocks (`lastFlowPushAt`, `lastStatePushAt`) sit just above the notification handler;
    // `failedAt`, `backlog`, `toolsLoaded`, `lastPollAt`, `lastStatusAt` and `pollLoopOn` come with
    // the loop.
    /** Ids a flow push named that the coalescer has not fetched yet, in first-notification (capture) order. */
    const pushPending = new Set<FlowId>();
    /** The armed coalescing timer, if any (`armPush`). */
    let pushTimer: ReturnType<typeof setTimeout> | null = null;
    /** A flush is applying; one runs at a time. */
    let flushing = false;
    /** A queued event was `intercepted|released|killed`: the next flush recomputes `pausedIds` after it applies. */
    let pausedIdsStale = false;
    /** Per id, the ticket of the newest row fetch issued for it; an older reply is dropped. */
    const fetchTicket = new Map<FlowId, number>();
    let fetchSeq = 0;
    /** Bumped by `clearFlows`: a fetch issued under an older epoch applies nothing (no ghost row after `flow.clear`). */
    let clearEpoch = 0;
    /** The poll in progress, if any: `pollOnce` joins it rather than overlapping it. */
    let pollRunning: Promise<void> | null = null;
    /** A resync was requested while a poll was running: exactly one more runs when it finishes. */
    let pollTrailing = false;
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
      systemProxy: null,
      systemProxySetting: false,
    });
    let activitySeq = 0;

    // CA trust (§D17.12): the last `ca.status` reading, and whether a `ca.install` / `ca.uninstall`
    // run is in flight. The word always comes from the read-back, never from the install's reply.
    const [caStatus, setCaStatus] = createSignal<CATrustStatus | null>(null);
    const [caInstalling, setCAInstalling] = createSignal(false);

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
      dropPending();
      clearEpoch++;
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

    /** Events after which a flow's cached detail is stale. */
    const changesDetail = (e: FlowEventKind) => e === 'response' || e === 'mutated' || e === 'meta' || e === 'released' || e === 'killed';
    /** Events after which `pausedIds` has to be recomputed from the rows. */
    const changesPause = (e: FlowEventKind) => e === 'intercepted' || e === 'released' || e === 'killed';
    /** Detail is stale once anything changed: drop the cache, and reload it now if the inspector shows this flow. */
    function invalidateDetail(id: FlowId) {
      if (details[id]) setDetails(produce((d) => delete d[id]));
      if (untrack(selectedId) === id) void loadDetail(id, true);
    }

    /**
     * A real bus: the push is a trigger, never data. The server's summary is the full `flow.get`
     * object (same keys, `kind:"websocket"`), but it is still not applied: refetching by id keeps
     * one fetch path for push and poll, a deliberate choice rather than a workaround for a sparse
     * summary (applying it is follow-up F4). The id is queued and the coalescer refetches it
     * through the same helper the poll uses.
     */
    function onFlowTrigger(n: FlowNotification) {
      if (n.event === 'cleared') {
        clearFlows();
        return;
      }
      if (!n.id) return;
      // A chatty WebSocket would refetch an O(messages) detail many times a second; live message
      // counters are a non-goal, so a message on a known flow changes nothing. On an unknown id it
      // is the first we hear of the flow.
      if (n.event === 'ws_message' && byId.has(n.id)) return;
      if (changesDetail(n.event)) invalidateDetail(n.id);
      if (changesPause(n.event)) pausedIdsStale = true;
      queuePush(n.id);
    }

    /**
     * Only a complete payload is state. The `lagged` marker and any partial push would otherwise
     * delete `listening`, `armed` and `agent` from the store (a Solid store drops a key set to
     * undefined) and zero throughput and memory; they write nothing and advance no clock.
     */
    const isCompleteState = (p: unknown): p is StateNotification => {
      const s = p as Partial<StateNotification> | null | undefined;
      return typeof s?.listening === 'boolean' && typeof s?.intercept_armed === 'boolean';
    };

    /** Applies a state payload; false when it was not a complete state, in which case nothing was written. */
    function onState(p: unknown): boolean {
      if (!isCompleteState(p)) return false;
      const s = p;
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
      return true;
    }

    /** Newest lines kept, after the noise filter, on both paths. */
    const ACTIVITY_CAP = 500;
    /**
     * The one intake behind the live push (`append`) and the `agent.activity` snapshot (`replace`)
     * (push spec D6, D7). Each line is normalized from the server's wire shape (`toAgentEntry`; an
     * `approval_requested` line is not an audit entry and is skipped), this UI's own successful
     * background reads are dropped, what is kept is numbered, and the newest ACTIVITY_CAP stay. The
     * filter runs on BOTH paths: the web server echoes every call made over `/bus` back to us, and
     * since PR #145 it shares the primary's audit ring (`tui::with_shared_governance`), so the
     * snapshot holds this UI's own polling too, up to the ring's 4096 lines; own-ness is inferred from
     * this connection's role because the bridge labels nothing (D7, fifth amendment). A batch that
     * keeps nothing changes nothing, in either mode: a snapshot that is empty (a fresh core) or all
     * our own polling must not replace the push-fed log with nothing on every side refresh (scope.add,
     * poc.run, the catalogue heal).
     */
    function intakeActivity(raw: readonly unknown[], mode: 'append' | 'replace') {
      const own = { origin: ownOriginOf(untrack(bus.role)) };
      const kept: ActivityEntry[] = [];
      for (const item of raw) {
        const e = toAgentEntry(item);
        if (!e || isUiPollNoise(e, own)) continue;
        kept.push({ ...e, seq: ++activitySeq });
      }
      commitActivity(kept, mode);
    }
    /** Append to (or replace) the log with already-numbered rows and keep the newest ACTIVITY_CAP; nothing kept, nothing changed. */
    function commitActivity(kept: ActivityEntry[], mode: 'append' | 'replace') {
      if (!kept.length) return;
      setProxy('activity', (list) => {
        const next = mode === 'replace' ? kept : [...list, ...kept];
        return next.length > ACTIVITY_CAP ? next.slice(-ACTIVITY_CAP) : next;
      });
    }
    /**
     * Why audit lines can be missing from the push-fed log (push spec D7, fourth amendment): the server
     * dropped notifications for this connection (`lagged`), or the bus reconnected and whatever was pushed
     * during the outage is gone. The sentence goes in `args` so the table shows it, and in `detail` for
     * the result tooltip.
     */
    const GAP_NOTE = {
      lagged: 'audit lines may be missing: the push stream lagged',
      reconnected: 'audit lines may be missing: the bus reconnected',
    } as const;
    interface GapArgs {
      note: string;
      count: number;
    }
    /** The `seq` of the gap row this store appended last; a new gap folds into it only while it is still the newest row. */
    let lastGapSeq = 0;
    /**
     * Make a gap visible as one synthetic error row (an `audit-log` line of our own, not an audit entry,
     * so it never meets the noise rule, and never a real line: the fold matches the row by the seq this
     * store gave it, not by its shape). Consecutive gaps FOLD into the newest row (`count` and `at`
     * move, the first reason's sentence stays), so a sustained lag cannot evict the 500-row history
     * with notices; a real row in between starts a new gap row. The fold updates the row in place
     * (`<For>` keys by object identity, so the rendered row is not rebuilt) but gives it a fresh `seq`:
     * `seq` is the Clear-view watermark (`filterActivity`, `clearedThrough`), and a fold that kept the
     * old number would stay hidden behind a Clear made after the first gap. The lost lines themselves
     * cannot be recovered over `aitm web`.
     */
    function noteAuditGap(why: keyof typeof GAP_NOTE) {
      const at = new Date().toISOString();
      const list = untrack(() => proxy.activity);
      const last = list[list.length - 1];
      if (last && last.seq === lastGapSeq) {
        const prev = last.args as GapArgs;
        lastGapSeq = ++activitySeq;
        setProxy('activity', list.length - 1, { seq: lastGapSeq, at, args: { note: prev.note, count: prev.count + 1 } });
        return;
      }
      lastGapSeq = ++activitySeq;
      const args: GapArgs = { note: GAP_NOTE[why], count: 1 };
      commitActivity([{ seq: lastGapSeq, origin: 'operator', command: 'audit-log', result: 'error', at, args, detail: GAP_NOTE[why] }], 'append');
    }

    function onAgent(a: unknown) {
      intakeActivity([a], 'append');
    }

    // When the last flow / complete state notification landed. The poll loop backs off only while the
    // matching stream is demonstrably flowing — never because the core merely *advertises*
    // `flow.subscribe`, and never for the list because only the state stream (throughput ticks) is
    // alive. Only `notifications/aitm/flow` advances the flow clock (an audit line, a state line or
    // the `lagged` marker says nothing about flows); only a complete state payload advances the state
    // clock. Both are reset when the bus (re)opens, and the flow clock by `lagged`.
    let lastFlowPushAt = Number.NEGATIVE_INFINITY;
    let lastStatePushAt = Number.NEGATIVE_INFINITY;

    /** A flow event is an object with a string `event` and a string `id`; anything else is not a flow push at all. */
    const isFlowNotification = (p: unknown): p is FlowNotification => {
      const n = p as Partial<FlowNotification> | null | undefined;
      return typeof n?.event === 'string' && typeof n?.id === 'string';
    };

    bus.onNotification((method, params) => {
      switch (method) {
        case 'notifications/aitm/flow':
          // Validated before the clock moves: a malformed line proves nothing about the stream.
          if (!isFlowNotification(params)) break;
          lastFlowPushAt = Date.now();
          onFlowTrigger(params);
          break;
        case 'notifications/aitm/state':
          if ((params as { lagged?: unknown } | null | undefined)?.lagged === true) {
            // The server's lane for this connection overflowed and dropped notifications. The marker
            // is not state and proves nothing about the flow stream: push is distrusted until the next
            // flow notification, and the list is resynced now, not on the next tick. The server pushes
            // no state, so nothing in the status was lost and that clock is left alone. Audit lines
            // were lost too and cannot be re-read: the log gets one row that says so.
            lastFlowPushAt = Number.NEGATIVE_INFINITY;
            requestPollNow();
            noteAuditGap('lagged');
            break;
          }
          // Only a complete payload is a state push: the clock moves only when one was applied.
          if (onState(params)) lastStatePushAt = Date.now();
          break;
        case 'notifications/aitm/agent':
          onAgent(params);
          break;
      }
    });

    // ---- live updates: push as a trigger, poll unless push is demonstrably flowing -------------
    // The bus client subscribes (`flow.subscribe`, in ws.ts) on every open, and a flow notification
    // is treated as a trigger: the id is queued and refetched (`onFlowTrigger`, `flushPush`), never
    // applied from the push's summary (`onFlowTrigger` says why). The outcome of the subscribe is not
    // surfaced, and a confirmed subscription cannot be told from a dispatcher that is not fed until a
    // push arrives, so every real bus is still polled. The loop skips the flow poll only while a FLOW
    // notification arrived within PUSH_FRESH_MS, and the status poll only while a STATE one did (a
    // bridge that pushes just throughput ticks must not slow the list down). Even then a heartbeat
    // runs every PUSH_FRESH_MS, so a push that dies quietly or loses events cannot freeze either. When
    // the bus (re)opens both clocks are reset and the pending set dropped, so the first tick after an
    // outage takes a fresh snapshot; a `lagged` marker resyncs at once (`requestPollNow`), single-flight
    // with the tick's own poll. The loop touches the bus only while it is `open` (a call into a bus
    // that is reconnecting can wait on it indefinitely), and heals a bootstrap that never got the tool
    // catalogue.
    const POLL_MS = 500;
    const STATUS_EVERY_MS = 2000; // while the state stream is not pushing
    const PUSH_FRESH_MS = 10_000;
    /** At most this many unseen flows are fetched per poll, so a core holding tens of thousands cannot be hit with that many concurrent `flow.detail` calls. */
    const MAX_FRESH_PER_POLL = 200;
    /**
     * A flow whose `flow.detail` / `flow.get` failed is left alone this long before it is tried again.
     * Without the pause a run of unreadable flows (at least a window's worth) is the head of every
     * capped fetch, fails every time, and starves the healthy flows behind it while keeping `backlog`
     * (and so the 500 ms cadence) on for good.
     */
    const FAILED_RETRY_MS = 5000;
    /** A throttle, not a debounce: the first queued id arms one timer, traffic never re-arms it, so push latency is bounded. */
    const PUSH_COALESCE_MS = 100;
    /** `flow.detail` calls in flight per flush wave: the bridge runs at most this many frames concurrently. */
    const PUSH_FETCH_WAVE = 16;
    /** Distinct ids the coalescer holds; past it the surplus is left to the poll (`backlog`), so memory stays bounded. */
    const PUSH_MAX_PENDING = 256;
    const failedAt = new Map<FlowId, number>();
    let pollLoopOn = false;
    let toolsLoaded = false;
    /** The last poll left unseen flows behind (the per-poll cap): keep polling until they are all in, push or not. */
    let backlog = false;
    let lastPollAt = Number.NEGATIVE_INFINITY;
    let lastStatusAt = Number.NEGATIVE_INFINITY;
    const isFresh = (at: number, now: number) => {
      const age = now - at;
      return age >= 0 && age < PUSH_FRESH_MS;
    };
    /** True while `id` is paused for a recent read failure (shared by the poll and the push flush). */
    function isHeld(id: FlowId, now: number): boolean {
      const at = failedAt.get(id);
      return at !== undefined && now - at >= 0 && now - at < FAILED_RETRY_MS;
    }
    /** A `flow.detail` / `flow.get` reply is the row for `id` only if it says so itself. */
    const isRowFor = (raw: unknown, id: FlowId): boolean => !!raw && typeof raw === 'object' && (raw as { id?: unknown }).id === id;
    /**
     * The one fetcher behind the poll and the push flush. `flow.detail {body: none}` is a summary
     * with headers, sizes, times and the connection — everything a row shows — at the cost of one
     * call per flow, like `flow.get` (used when the catalogue lacks `flow.detail`). `wave` calls are
     * in flight at a time; each wave is applied in one batch, in id order, with `seqOf(id)` read at
     * apply time. A good read clears `failedAt`, a failed one sets it. A reply is dropped when the
     * list was cleared since the fetch was issued (epoch) or a newer fetch for that id was issued
     * since (ticket), so two fetchers (the heartbeat poll and a flush) cannot land out of order.
     */
    async function fetchRows(ids: readonly FlowId[], seqOf: (id: FlowId) => number, wave: number): Promise<void> {
      const rich = proxy.tools.some((t) => t.name === 'flow.detail');
      // One epoch for the whole call: a clear during any wave ends the call, or the later waves would
      // run under the new epoch and put back rows the operator just cleared.
      const epoch = clearEpoch;
      for (let i = 0; i < ids.length; i += wave) {
        if (epoch !== clearEpoch) return;
        const slice = ids.slice(i, i + wave);
        const tickets = slice.map((id) => {
          const t = ++fetchSeq;
          fetchTicket.set(id, t);
          return t;
        });
        const got = await Promise.all(
          slice.map((id) => (rich ? bus.call('flow.detail', { id, body: 'none' }) : bus.call('flow.get', { id })).catch(() => null)),
        );
        const failedNow = Date.now();
        batch(() => {
          got.forEach((raw, j) => {
            const id = slice[j]!;
            // Stale when a newer fetch owns the id (it will tidy the ticket) or the list was cleared since.
            const newest = fetchTicket.get(id) === tickets[j];
            if (newest) fetchTicket.delete(id);
            if (!newest || epoch !== clearEpoch) return;
            // Keyed by the id that was asked for: a reply naming another flow, or none, would make a
            // ghost row (`''`) or overwrite that other row. It is a failed read like any other.
            if (isRowFor(raw, id)) {
              failedAt.delete(id);
              upsert(toSummary(raw, seqOf(id)));
            } else failedAt.set(id, failedNow);
          });
        });
      }
    }
    /** Single-flight: the running poll's promise when one is running, else a new one. */
    function pollOnce(): Promise<void> {
      if (pollRunning) return pollRunning;
      pollRunning = runPoll().finally(() => {
        pollRunning = null;
        if (pollTrailing) {
          pollTrailing = false;
          void pollOnce();
        }
      });
      return pollRunning;
    }
    /** Resync now, not on the next tick: start a poll, or fold into one trailing poll if one is running. */
    function requestPollNow(): void {
      // Only an open bus is called (the marker can land during a handshake): a poll parked on `ready`
      // would hold the single-flight slot and stall the loop's own polls behind it.
      if (bus.state() !== 'open') return;
      if (pollRunning) pollTrailing = true;
      else void pollOnce();
    }
    async function runPoll() {
      lastPollAt = Date.now();
      try {
        const ids = await bus.call<string[]>('flow.list');
        const now = Date.now();
        // Forget pauses that ended and flows that are gone (flow.clear), so the map stays small.
        if (failedAt.size) {
          const listed = new Set(ids);
          for (const id of failedAt.keys()) if (!isHeld(id, now) || !listed.has(id)) failedAt.delete(id);
        }
        // Oldest first, so the list stays in capture order while the backlog drains. Only flows not
        // paused for a recent failure are eligible, and the backlog is measured over those alone.
        const unseen = ids.filter((id) => !byId.has(id) && !isHeld(id, now));
        const fresh = unseen.slice(0, MAX_FRESH_PER_POLL);
        backlog = unseen.length > fresh.length;
        const pending = ids.filter((id) => {
          const e = byId.get(id);
          return e && e.raw.status == null && e.raw.intercept !== 'killed' && !isHeld(id, now);
        });
        const want = [...fresh, ...pending.slice(0, 50)];
        // One wave: the poll's fan-out is bounded by MAX_FRESH_PER_POLL, and its seq is the core's position.
        await fetchRows(want, (id) => ids.indexOf(id) + 1, Math.max(1, want.length));
        recomputePaused();
      } catch {
        // `flow.list` itself failed. The loop only calls an open bus, so this is a call that errored on
        // a live connection: it is retried on the next tick. A core that keeps erroring leaves the list
        // as it was (stale), and nothing says so: no toast, and the status bar only reflects whether
        // the bus connection is up. (Individual unreadable flows are handled by `failedAt`.)
      }
    }
    // ---- the push coalescer (its state is declared with the flows, above) ----------------------
    function armPush() {
      if (pushTimer !== null) return;
      pushTimer = setTimeout(() => {
        pushTimer = null;
        void flushPush();
      }, PUSH_COALESCE_MS);
    }
    /** Forget every queued id and disarm the timer: the list was cleared, or the connection is new. */
    function dropPending() {
      pushPending.clear();
      pausedIdsStale = false;
      if (pushTimer !== null) {
        clearTimeout(pushTimer);
        pushTimer = null;
      }
    }
    /** Queue an id a flow push named; one flush runs at a time, and the next timer is armed when it finishes. */
    function queuePush(id: FlowId) {
      if (!pushPending.has(id)) {
        if (pushPending.size >= PUSH_MAX_PENDING) {
          // The surplus is dropped; the poll (capped, oldest first) reconciles it on the 500 ms cadence.
          backlog = true;
          return;
        }
        pushPending.add(id);
      }
      if (!flushing) armPush();
    }
    async function flushPush(): Promise<void> {
      if (flushing) return;
      if (bus.state() !== 'open') {
        // Nothing is sent into a bus that is not open: the queue and its pause mark are dropped, and
        // the resync on reconnect takes a fresh snapshot.
        dropPending();
        return;
      }
      if (!toolsLoaded) {
        // Without the catalogue the fetch would fall back to `flow.get`, a thinner row than the
        // poll's `flow.detail`; wait for the loop to heal it.
        armPush();
        return;
      }
      flushing = true;
      try {
        const now = Date.now();
        // Taken and removed now, so an event that arrives while these are in flight re-queues its id
        // and it is refetched after this flush. Ids paused for a recent failure wait for the poll.
        const ids = [...pushPending].filter((id) => !isHeld(id, now));
        pushPending.clear();
        const stale = pausedIdsStale;
        pausedIdsStale = false;
        // A new id takes the next position at apply time (inside the batch, so consecutive new ids
        // get consecutive numbers whatever order the replies came back in); a known id keeps its seq.
        if (ids.length) await fetchRows(ids, (id) => byId.get(id)?.raw.seq ?? entries.length + 1, PUSH_FETCH_WAVE);
        if (stale) recomputePaused();
      } catch {
        // Applying a wave threw (the fetch itself never rejects). The ids taken above are not
        // re-queued: the poll re-reads what is missing, at the heartbeat at the latest, as it does
        // for any failed read. This runs from a timer, so the error must not escape as an unhandled
        // rejection, and `flushing` must be released below.
      } finally {
        flushing = false;
        if (pushPending.size) armPush();
      }
    }
    async function pollStatus() {
      if (!proxy.tools.some((t) => t.name === 'proxy.status')) return;
      lastStatusAt = Date.now();
      try {
        const s = await bus.call<{ capturing?: boolean; intercept_armed?: boolean; address?: string | null; paused?: number; version?: unknown; system_proxy?: unknown }>('proxy.status');
        setProxy({
          listening: s.capturing ?? proxy.listening,
          armed: typeof s.intercept_armed === 'boolean' ? s.intercept_armed : proxy.armed,
          address: s.address ?? proxy.address,
          version: typeof s.version === 'string' ? s.version : proxy.version,
          // Always null, never undefined, when absent: a Solid store drops a key set to undefined.
          // The compact object has no guidance/remedy: the last full read's survive it (spec D15).
          systemProxy: mergeSystemProxy(proxy.systemProxy, parseSystemProxy(s.system_proxy)),
        });
      } catch {
        /* next tick */
      }
    }
    // Every (re)connection is a new stream: nothing pushed before an outage says anything about what
    // was captured during it. Both clocks are reset so the next tick takes a fresh snapshot even if a
    // push was fresh seconds ago, held failures are retried, and ids queued for the socket that is
    // gone are dropped (the snapshot covers them). The flows are covered that way; the audit lines
    // pushed during the outage are not, so every open after the first notes a gap in the Activity log
    // (the first open missed nothing). Deferred: the state at creation is not a transition, which is
    // why `hasBeenOpen` is seeded from it (a bus handed over already open has had its first open).
    let hasBeenOpen = untrack(bus.state) === 'open';
    createEffect(
      on(
        bus.state,
        (s) => {
          if (s !== 'open') return;
          if (hasBeenOpen) noteAuditGap('reconnected');
          hasBeenOpen = true;
          lastFlowPushAt = Number.NEGATIVE_INFINITY;
          lastStatePushAt = Number.NEGATIVE_INFINITY;
          failedAt.clear();
          dropPending();
        },
        { defer: true },
      ),
    );
    /** `polling` means the loop is the live source: the bus is open and no flow notifications are arriving. */
    const syncPollingFlag = () => setProxy('polling', bus.state() === 'open' && !isFresh(lastFlowPushAt, Date.now()));
    function startPolling() {
      if (pollLoopOn) return;
      pollLoopOn = true;
      syncPollingFlag();
      const tick = async () => {
        // A closed bus ends the loop: nothing is rescheduled, so at most one more tick runs after close.
        if (bus.state() === 'closed') {
          pollLoopOn = false;
          setProxy('polling', false);
          return;
        }
        try {
          syncPollingFlag();
          // Only an open bus is called. Anything else (connecting, reconnecting) is waited out: a call
          // issued into it can stay pending, and since the loop never overlaps itself that would stall it.
          if (bus.state() === 'open') {
            if (!toolsLoaded) {
              // A bootstrap that never got the tool catalogue heals here, then re-reads the side data.
              try {
                await loadCatalogue();
              } catch {
                /* next tick */
              }
            }
            const now = Date.now();
            if (backlog || !isFresh(lastFlowPushAt, now) || now - lastPollAt >= PUSH_FRESH_MS) await pollOnce();
            const later = Date.now();
            // State/armed/version: every ~2 s unless state is pushed, and on the heartbeat even then.
            const statusEvery = isFresh(lastStatePushAt, later) ? PUSH_FRESH_MS : STATUS_EVERY_MS;
            if (later - lastStatusAt >= statusEvery) await pollStatus();
          }
        } finally {
          setTimeout(tick, POLL_MS);
        }
      };
      setTimeout(tick, POLL_MS);
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
            // The bus returns an array of host strings; an object entry with `host` is also accepted.
            .then((s) => setProxy('scope', Array.isArray(s) ? s.map((e) => (typeof e === 'string' ? { host: e } : (e as ProxyState['scope'][number]))) : []))
            .catch(() => {}),
        );
      if (has('poc.list'))
        jobs.push(bus.call<unknown[]>('poc.list').then((p) => setProxy('findings', mergeFindings(Array.isArray(p) ? p : []))).catch(() => {}));
      if (has('agent.status'))
        jobs.push(
          bus
            .call<{ policy: AgentPolicy; actions_last_minute: number; log?: unknown[] }>('agent.status')
            .then((a) => {
              setProxy({ agent: a.policy, agentActionsLastMinute: a.actions_last_minute });
              // On a bus without agent.activity the log rides on agent.status as `log` (the real core sends none).
              if (Array.isArray(a.log) && !has('agent.activity')) intakeActivity(a.log, 'replace');
            })
            .catch(() => {}),
        );
      if (has('agent.activity'))
        jobs.push(
          bus
            .call<unknown>('agent.activity')
            // No `limit`: the ring is the snapshot, and the intake filters and caps it. Over `aitm web`
            // the ring was empty before PR #145 (the web server's own ring was not the one agent.activity
            // read); since then it is the primary's, shared, and holds this UI's own polling.
            .then((list) => {
              if (Array.isArray(list)) intakeActivity(list, 'replace');
            })
            .catch(() => {}),
        );
      // No read for the intercept state exists: `flow.intercept {}` ARMS (enabled defaults to
      // true), so the armed flag comes only from notifications/aitm/state and our own calls.
      if (has('proxy.status')) {
        lastStatusAt = Date.now();
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
              system_proxy?: unknown;
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
                systemProxy: mergeSystemProxy(proxy.systemProxy, parseSystemProxy(s.system_proxy)),
              }),
            )
            .catch(() => {}),
        );
      }
      await Promise.all(jobs);
    }

    /**
     * Re-read `ca.status` into `ca` (D17.5); true when the read-back landed. A missing tool leaves
     * the reading untouched and a failed read keeps the last one, both false, so the caller that
     * just changed the trust store can say the word may be stale. Each read costs the core one
     * trust evaluation per store, so it runs only at bootstrap and after a `ca.install` /
     * `ca.uninstall` run, not on every side refresh.
     */
    async function refreshCA(): Promise<boolean> {
      if (!proxy.tools.some((t) => t.name === 'ca.status')) return false;
      try {
        setCaStatus(parseCATrust(await bus.call<CAStatusWire>('ca.status')));
        return true;
      } catch {
        return false;
      }
    }

    /** The tool catalogue, then everything read through it. Shared by bootstrap and the loop's heal. */
    async function loadCatalogue() {
      const tools = await bus.tools();
      setProxy('tools', tools);
      toolsLoaded = true;
      await Promise.all([refreshSide(), refreshCA()]);
    }

    async function bootstrap() {
      bus.connect();
      try {
        await loadCatalogue();
        await pollOnce(); // the snapshot of what was captured before this page connected
      } catch (e) {
        notice((e as Error).message, 'error');
      }
      // Outside the try on purpose: a failed bootstrap (tools/list rejected, say) must not leave the
      // list frozen. The loop keeps trying every tick, and `flow.list` needs no catalogue.
      startPolling();
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

    /** One system-proxy change: flag it in flight for the pill, store the reply's status, clear the flag even on error. */
    async function systemProxyChange(tool: 'proxy.system.set' | 'proxy.system.unset', args?: Record<string, unknown>): Promise<void> {
      setProxy('systemProxySetting', true);
      try {
        const result = await bus.call<unknown>(tool, args);
        setProxy('systemProxy', parseSystemProxy(result));
      } finally {
        setProxy('systemProxySetting', false);
      }
    }

    /**
     * The full status read the pill menu asks for when it opens (spec D15, amended 2026-11-01): the
     * compact `proxy.status` sub-object has no `guidance`/`remedy`, so "Copy env line" and the
     * privilege remedy come only from here. Gated on the tool being offered. A reply that is not a
     * status object keeps what the poll already stored rather than wiping the pill. Skipped while this
     * client's own set/unset is in flight: the change's reply stores the status, and a concurrent full
     * read could race it with a stale object.
     */
    async function refreshSystemProxy(): Promise<void> {
      if (proxy.systemProxySetting) return;
      if (!proxy.tools.some((t) => t.name === 'proxy.system.status')) return;
      const full = parseSystemProxy(await bus.call<unknown>('proxy.system.status'));
      if (full) setProxy('systemProxy', full);
    }

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
      // The system-proxy pill menu (spec D15): `proxy.system.set {}` / `proxy.system.unset` return the
      // full D6 status object, which replaces the compact one from `proxy.status`. The in-flight flag
      // is this client's own; a refusal reaches the status bar through `guarded`'s notice. No per-call
      // timeout here: `ws.ts` has none and a set can take a couple of seconds of `networksetup`.
      setSystemProxy: () => guarded('system proxy', () => systemProxyChange('proxy.system.set', {})),
      unsetSystemProxy: () => guarded('system proxy', () => systemProxyChange('proxy.system.unset')),
      refreshSystemProxy: () => guarded('system proxy', refreshSystemProxy),
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
      refreshCA,
      /** Set by the palette for the duration of a `ca.install` / `ca.uninstall` run and its re-read. */
      setCAInstalling: (on: boolean) => setCAInstalling(on),
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
      /** The last `ca.status` reading; null before the first read, without the tool, or when no store reports. */
      get ca(): CATrustStatus | null {
        return caStatus();
      },
      get caInstalling(): boolean {
        return caInstalling();
      },
      ...actions,
    };
  });
}

export type AppStore = ReturnType<typeof createAppStore>;
export type { Accessor };
