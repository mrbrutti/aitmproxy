// The L4 session store: feature-detects `l4.*` from `tools/list` and reads the live bus through the
// kind's `list_cmd`/`detail_cmd` indirection (`l4.flow.list` / `l4.flow.get`), never `flow.detail`.
// It never assumes a capability is present — each is gated on its own command, so the surface
// degrades honestly where privilege or a command is absent (ui-ext §3.2, L4OPS Task 12). It holds
// no wire path of its own: inject goes through `panels/l4/inject` → `l4.inject` only.
//
// Parity (plan 2026-10-31-l4-parity-fixes, task C3): `refresh()` runs on the `l4PollPlan` back-off
// (spec §7(c), AC23), availability comes from the status replies on every slow poll and is never
// cached for the session (spec §1), list rows are read with `limit: 0` and only the inspector asks
// for a packet window (spec §2), `l4.intercept.list` is read only while intercept is available, and
// every argument-taking verb goes through a `model.ts` builder (`args.test.ts` tripwire).
import { batch, createEffect, createMemo, createSignal, on, untrack } from 'solid-js';
import { createStore } from 'solid-js/store';
import type { AppStore } from '~/state/app';
import { beginGuarded, confirmGuarded, type GuardedOutcome } from './inject';
import {
  availabilityFromError,
  availabilityFromReply,
  captureStartArgs,
  captureStopArgs,
  createOnceLog,
  flowGetArgs,
  l4PollPlan,
  l4Row,
  mutateArgs,
  PENDING_AVAILABILITY,
  placeholderRow,
  revertArgs,
  scopeAddArgs,
  statusIds,
  supportsFlowWindow,
  verdictArgs,
  type AgentGates,
  type L4Availability,
  type L4CraftResult,
  type L4Direction,
  type L4FlowWire,
  type L4ParkedWire,
  type L4PollClock,
  type L4ScopeDraft,
  type L4ScopeEntryWire,
  type PacketSpec,
  type UnionRow,
} from './model';

export interface L4Caps {
  craft: boolean;
  inject: boolean;
  scope: boolean;
  interfaces: boolean;
  agentStatus: boolean;
  agentSet: boolean;
}

export function createL4Store(app: AppStore) {
  // Tolerate a partial app (unit-test stubs that mount a bare AppProvider): no tools → no L4.
  /** The app's `tools/list`, for the feature detects (`supportsFlowWindow`, `supportsOperatorScopeAdd`). */
  const tools = () => app.proxy?.tools ?? [];
  const has = (n: string) => tools().some((t) => t.name === n);
  /** The L4 flow kind is live iff its list command is advertised (ui-ext §3.1 feature-detect). */
  const present = createMemo(() => has('l4.flow.list'));
  const caps = createMemo<L4Caps>(() => ({
    craft: has('l4.craft'),
    inject: has('l4.inject'),
    scope: has('l4.scope.list'),
    interfaces: has('l4.interfaces'),
    agentStatus: has('l4.agent.status'),
    agentSet: has('l4.agent.set'),
  }));
  /** Whether `l4.flow.get` takes the §2 window on this core (older cores get `{id}` only). */
  const windowed = () => supportsFlowWindow(tools());

  const [flowsById, setFlowsById] = createStore<Record<string, L4FlowWire>>({});
  const [ids, setIds] = createSignal<string[]>([]);
  const [scope, setScope] = createSignal<L4ScopeEntryWire[]>([]);
  const [gates, setGates] = createSignal<AgentGates | null>(null);
  const [captureIds, setCaptureIds] = createSignal<string[]>([]);
  const [captureAvailability, setCaptureAvailability] = createSignal<L4Availability>(PENDING_AVAILABILITY);
  const [interceptAvailability, setInterceptAvailability] = createSignal<L4Availability>(PENDING_AVAILABILITY);
  /** `l4.intercept.list`, arrival order (spec §4); empty while intercept is unavailable. */
  const [parked, setParked] = createSignal<L4ParkedWire[]>([]);
  /** The selected flow with its first packet window (`flowGetArgs(id, 'inspect', …)`). */
  const [inspected, setInspected] = createSignal<L4FlowWire | null>(null);
  /** The last read failure of the current pass; null once a pass completes clean. */
  const [error, setError] = createSignal<string | null>(null);

  // ---- reads: once-per-message failure log, poll plan ------------------------------------------

  // Every read failure goes through this one log: a failing verb repeats on every poll, the activity
  // log carries each distinct message once (spec §7(c)). Recovery is per call identity (`key`), not
  // per verb: when the same read succeeds again its last message is forgotten, so a recurrence after
  // recovery is logged again — while another read of the same verb (flow B's `l4.flow.get` beside
  // flow A's) succeeding, or a pass that ran only the slow group, cannot un-suppress a read still
  // failing. The logged text keeps the verb `label`.
  const readFailures = createOnceLog((msg) => app.notice(msg, 'error'));
  /** The last logged message per read key, forgotten when that same read succeeds. */
  const lastFailure = new Map<string, string>();
  const clock: L4PollClock = { lastTickAt: null, lastSlowAt: null };
  let failedThisPass = false;
  let inFlight = false;
  /** A `refresh(true)` arrived while a pass was in flight: run one more pass when it ends. */
  let forcePending = false;

  function failed(label: string, key: string, e: unknown): void {
    const message = `${label}: ${(e as Error).message}`;
    failedThisPass = true;
    setError(message);
    lastFailure.set(key, message);
    readFailures.log(message);
  }

  /** The read under `key` succeeded: its last failure, if any, may be logged again if it recurs. */
  function recovered(key: string): void {
    const message = lastFailure.get(key);
    if (message === undefined) return;
    lastFailure.delete(key);
    readFailures.forget(message);
  }

  /**
   * One bus read; a failure is logged once (as `label: <message>`) and yields `undefined`. `key`
   * identifies the read for recovery; it is the label unless one verb is read several ways.
   */
  async function read<T>(label: string, pending: Promise<T>, key = label): Promise<T | undefined> {
    try {
      const value = await pending;
      recovered(key);
      return value;
    } catch (e) {
      failed(label, key, e);
      return undefined;
    }
  }

  /**
   * A status verb (spec §1): the reply maps through `availabilityFromReply`; an older core's refusal
   * (`… L4 unavailable: <reason>`) is itself an availability answer; any other error is a read
   * failure and leaves the previous availability in place.
   */
  async function readAvailability(label: string, pending: Promise<unknown>): Promise<{ avail: L4Availability; reply: unknown } | null> {
    try {
      const reply = await pending;
      recovered(label);
      return { avail: availabilityFromReply(reply), reply };
    } catch (e) {
      const avail = availabilityFromError((e as Error).message);
      if (avail) {
        recovered(label);
        return { avail, reply: null };
      }
      failed(label, label, e);
      return null;
    }
  }

  /** Whether `id` is a known L4 flow id (the app's selection is shared with HTTP/WS rows). */
  const isL4Id = (id: string | null | undefined): id is string => !!id && untrack(ids).includes(id);

  /** The fast group: list + rows (`limit: 0`), capture status, intercept status and — only when available — the parked list. */
  async function tick(): Promise<void> {
    const list = await read<string[]>('l4.flow.list', app.call<string[]>('l4.flow.list'));
    if (list !== undefined) {
      const next = Array.isArray(list) ? list : [];
      setIds(next);
      // Register with the app so the unified list and selection route L4 ids to the L4 inspector.
      app.setL4Ids?.(next);
      const got = await Promise.all(
        next.map((id) => read<L4FlowWire>('l4.flow.get', app.call<L4FlowWire>('l4.flow.get', flowGetArgs(id, 'list', windowed())), `l4.flow.get ${id}`)),
      );
      batch(() => {
        for (const f of got) if (f && typeof f.id === 'string') setFlowsById(f.id, f);
      });
    }
    if (has('l4.capture.status')) {
      const s = await readAvailability('l4.capture.status', app.call('l4.capture.status'));
      if (s) {
        setCaptureAvailability(s.avail);
        setCaptureIds(statusIds(s.reply, 'captures'));
      }
    }
    if (has('l4.intercept.status')) {
      const s = await readAvailability('l4.intercept.status', app.call('l4.intercept.status'));
      if (s) setInterceptAvailability(s.avail);
    }
    // Spec §4: an unavailable intercept is one documented-limited line and the list is not polled.
    if (interceptAvailability().available) {
      const list = await read<L4ParkedWire[]>('l4.intercept.list', app.call<L4ParkedWire[]>('l4.intercept.list'));
      if (list !== undefined) setParked(Array.isArray(list) ? list : []);
    } else if (parked().length) setParked([]);
    // Keep the inspector's window current while its flow grows (one extra read only when the row changed).
    const sel = app.selectedId?.() ?? null;
    if (isL4Id(sel)) {
      const row = flowsById[sel];
      const shown = inspected();
      if (!row || shown?.id !== sel || shown.packet_count !== row.packet_count) await inspect(sel);
    }
  }

  /** The slow group: scope and the agent gates (availability is re-read by every tick, never cached). */
  async function slow(): Promise<void> {
    if (caps().scope) {
      const s = await read<L4ScopeEntryWire[]>('l4.scope.list', app.call<L4ScopeEntryWire[]>('l4.scope.list'));
      if (s !== undefined) setScope(Array.isArray(s) ? s : []);
    }
    if (caps().agentStatus) {
      const g = await read<AgentGates | null>('l4.agent.status', app.call<AgentGates>('l4.agent.status'));
      if (g !== undefined) setGates(g ?? null);
    }
  }

  /**
   * One timer call (`state/context.tsx`, every 1.5 s). The poll plan decides what is due: while the
   * lane is idle (capture unavailable, no flows) the fast group runs every 10 s and the slow group
   * every 60 s (AC23); otherwise both run on every call. `force` (after an action) runs both now —
   * or, when a pass is already in flight, once more as soon as it ends (an ordinary timer call that
   * lands mid-pass is simply dropped; the next one comes in 1.5 s).
   */
  async function refresh(force = false): Promise<void> {
    if (!present()) {
      setIds([]);
      app.setL4Ids?.([]);
      return;
    }
    if (inFlight) {
      if (force) forcePending = true;
      return;
    }
    const now = Date.now();
    const idle = !force && !captureAvailability().available && ids().length === 0;
    const plan = l4PollPlan(now, clock, idle);
    if (!plan.tick && !plan.slow) return;
    inFlight = true;
    failedThisPass = false;
    try {
      if (plan.tick) {
        clock.lastTickAt = now;
        await tick();
      }
      if (plan.slow) {
        clock.lastSlowAt = now;
        await slow();
      }
      if (!failedThisPass) setError(null);
    } finally {
      inFlight = false;
    }
    if (forcePending) {
      forcePending = false;
      await refresh(true);
    }
  }

  /** Fetch the selected flow's first packet window (spec §2) for the inspector. */
  async function inspect(id: string): Promise<void> {
    const flow = await read<L4FlowWire>('l4.flow.get', app.call<L4FlowWire>('l4.flow.get', flowGetArgs(id, 'inspect', windowed())), 'l4.flow.get inspect');
    if (!flow || flow.id !== id) return;
    // A flow's packet log is append-only, so a window already extended by `loadMore()` is a longer
    // prefix of the same log: keep it (and its continuation point) rather than shrink back to the
    // first window when the tick re-reads a grown flow.
    const shown = inspected();
    if (shown && shown.id === id && (flow.offset ?? 0) === 0 && shown.packets.length > flow.packets.length) {
      setInspected({ ...flow, packets: shown.packets, truncated: shown.truncated ?? false, next_offset: shown.next_offset ?? null });
      return;
    }
    setInspected(flow);
  }

  /**
   * After a `truncated` window (spec §2 byte budget): read the next window from the reply's
   * `next_offset` and append its packets to the inspected flow; `truncated` / `next_offset` then
   * come from the new reply. A no-op when nothing is inspected or the window is complete.
   */
  /**
   * The windows `loadMore()` reads are in flight for, as `<flow id>:<next_offset>`: a second click for
   * the same window of the same flow is ignored; a click on another flow (whose first `next_offset`
   * is the same inspect limit) is not.
   */
  const loading = new Set<string>();
  async function loadMore(): Promise<void> {
    const shown = inspected();
    if (!shown || shown.truncated !== true || typeof shown.next_offset !== 'number') return;
    const windowKey = `${shown.id}:${shown.next_offset}`;
    if (loading.has(windowKey)) return;
    loading.add(windowKey);
    const id = shown.id;
    try {
      const more = await read<L4FlowWire>(
        'l4.flow.get',
        app.call<L4FlowWire>('l4.flow.get', flowGetArgs(id, 'inspect', windowed(), shown.next_offset)),
        'l4.flow.get inspect',
      );
      if (!more || more.id !== id) return;
      const current = inspected();
      // The selection moved while the read was in flight: the reply belongs to a flow no longer shown.
      if (!current || current.id !== id) return;
      setInspected({ ...more, offset: current.offset ?? 0, packets: [...current.packets, ...more.packets] });
    } finally {
      loading.delete(windowKey);
    }
  }

  // Selection is the app's single `selectedId`; an L4 id gets its window, anything else clears it.
  createEffect(
    on(
      () => app.selectedId?.() ?? null,
      (id) => {
        if (isL4Id(id)) void inspect(id);
        else setInspected(null);
      },
    ),
  );

  // ---- derived ---------------------------------------------------------------------------------

  /** The L4 rows for the union list; a flow whose detail failed to load is a labelled placeholder. */
  const rows = createMemo<UnionRow[]>(() => ids().map((id) => (flowsById[id] ? l4Row(flowsById[id]!, scope()) : placeholderRow(id, 'l4'))));
  // The L4 inspector shows the selection when it is an L4 flow: the windowed read when it has
  // landed, else the list row's flow (packets empty under `limit: 0` until the window arrives).
  const selectedFlow = createMemo<L4FlowWire | null>(() => {
    const id = app.selectedId?.();
    if (!id) return null;
    const shown = inspected();
    if (shown && shown.id === id) return shown;
    return flowsById[id] ?? null;
  });
  const selectedRow = createMemo<UnionRow | null>(() => {
    const f = selectedFlow();
    return f ? l4Row(f, scope()) : null;
  });

  // ---- actions (every argument through a `model.ts` builder) -----------------------------------

  const craft = (spec: PacketSpec) => app.call<L4CraftResult>('l4.craft', { spec });

  async function startCapture(iface: string, direction: L4Direction): Promise<void> {
    try {
      await app.call('l4.capture.start', captureStartArgs(iface, direction));
      app.notice(`Capture started on ${iface} (${direction})`);
      await refresh(true);
    } catch (e) {
      app.notice(`l4.capture.start: ${(e as Error).message}`, 'error');
    }
  }

  async function stopCapture(id: string): Promise<void> {
    try {
      await app.call('l4.capture.stop', captureStopArgs(id));
      app.notice(`Capture ${id} stopped`);
      await refresh(true);
    } catch (e) {
      app.notice(`l4.capture.stop: ${(e as Error).message}`, 'error');
    }
  }

  // The parked-packet verbs (spec §4) take the parked id, never the flow id. Each is the first
  // phase of the confirm-over-the-wire path; a `confirm` outcome is completed by the caller with
  // `confirmGuarded(call, tool, <the same builder args>, token)` (the panel's existing dialog).
  const forward = (parkedId: string): Promise<GuardedOutcome> => beginGuarded(app.call, 'l4.intercept.forward', verdictArgs(parkedId));
  const drop = (parkedId: string): Promise<GuardedOutcome> => beginGuarded(app.call, 'l4.intercept.drop', verdictArgs(parkedId));
  const mutate = (parkedId: string, spec: PacketSpec): Promise<GuardedOutcome> =>
    beginGuarded(app.call, 'l4.intercept.mutate', mutateArgs(parkedId, spec));
  const revert = (parkedId: string): Promise<GuardedOutcome> => beginGuarded(app.call, 'l4.intercept.revert', revertArgs(parkedId));

  // Operator L4 scope add (spec §3, AC22): the ONLY path to `l4.scope.add` in this store, and it is
  // the same confirm-over-the-wire handshake as inject. `addScope` is the first phase; a `confirm`
  // outcome is completed by `confirmAddScope` with the same draft and the core's token. The core
  // validates the entry and writes the prompt; nothing here fabricates either. After a `done` the
  // slow group re-reads `l4.scope.list`, so the new entry shows with its `runtime` provenance.
  async function addScope(draft: L4ScopeDraft): Promise<GuardedOutcome> {
    const outcome = await beginGuarded(app.call, 'l4.scope.add', scopeAddArgs(draft));
    if (outcome.kind === 'done') await slow();
    return outcome;
  }

  async function confirmAddScope(draft: L4ScopeDraft, token: string): Promise<GuardedOutcome> {
    const outcome = await confirmGuarded(app.call, 'l4.scope.add', scopeAddArgs(draft), token);
    if (outcome.kind === 'done') await slow();
    return outcome;
  }

  async function setGate(capability: string, allowed: boolean): Promise<void> {
    try {
      const next = await app.call<AgentGates>('l4.agent.set', { capability, allowed });
      setGates(next ?? null);
    } catch (e) {
      app.notice(`l4.agent.set: ${(e as Error).message}`, 'error');
    }
  }

  return {
    present,
    caps,
    tools,
    rows,
    ids,
    scope,
    gates,
    captureIds,
    captureAvailability,
    interceptAvailability,
    parked,
    inspected,
    selectedFlow,
    selectedRow,
    refresh,
    inspect,
    loadMore,
    craft,
    startCapture,
    stopCapture,
    forward,
    drop,
    mutate,
    revert,
    addScope,
    confirmAddScope,
    setGate,
    error,
    call: app.call,
  };
}

export type L4Store = ReturnType<typeof createL4Store>;
