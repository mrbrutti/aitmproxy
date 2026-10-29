// The L4 session store: feature-detects `l4.*` from `tools/list` and reads the live bus through the
// kind's `list_cmd`/`detail_cmd` indirection (`l4.flow.list` / `l4.flow.get`), never `flow.detail`.
// It never assumes a capability is present — each is gated on its own command, so the surface
// degrades honestly where privilege or a command is absent (ui-ext §3.2, L4OPS Task 12). It holds
// no wire path of its own: inject goes through `panels/l4/inject` → `l4.inject` only.
import { batch, createMemo, createSignal } from 'solid-js';
import { createStore } from 'solid-js/store';
import type { AppStore } from '~/state/app';
import {
  l4Row,
  placeholderRow,
  type AgentGates,
  type L4CraftResult,
  type L4FlowWire,
  type L4ScopeEntryWire,
  type PacketSpec,
  type UnionRow,
} from './model';

export interface L4Caps {
  craft: boolean;
  inject: boolean;
  capture: boolean;
  intercept: boolean;
  scope: boolean;
  interfaces: boolean;
  agentStatus: boolean;
  agentSet: boolean;
}

export function createL4Store(app: AppStore) {
  // Tolerate a partial app (unit-test stubs that mount a bare AppProvider): no tools → no L4.
  const has = (n: string) => (app.proxy?.tools ?? []).some((t) => t.name === n);
  /** The L4 flow kind is live iff its list command is advertised (ui-ext §3.1 feature-detect). */
  const present = createMemo(() => has('l4.flow.list'));
  const caps = createMemo<L4Caps>(() => ({
    craft: has('l4.craft'),
    inject: has('l4.inject'),
    capture: has('l4.capture.start'),
    intercept: has('l4.intercept.status') || has('l4.intercept.start'),
    scope: has('l4.scope.list'),
    interfaces: has('l4.interfaces'),
    agentStatus: has('l4.agent.status'),
    agentSet: has('l4.agent.set'),
  }));

  const [flowsById, setFlowsById] = createStore<Record<string, L4FlowWire>>({});
  const [ids, setIds] = createSignal<string[]>([]);
  const [scope, setScope] = createSignal<L4ScopeEntryWire[]>([]);
  const [gates, setGates] = createSignal<AgentGates | null>(null);
  const [captureIds, setCaptureIds] = createSignal<string[]>([]);
  const [interceptParked, setInterceptParked] = createSignal(0);
  const [firstParkedId, setFirstParkedId] = createSignal<string | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  async function refresh(): Promise<void> {
    if (!present()) {
      setIds([]);
      app.setL4Ids?.([]);
      return;
    }
    try {
      const list = await app.call<string[]>('l4.flow.list');
      const ids = Array.isArray(list) ? list : [];
      setIds(ids);
      // Register with the app so the unified list and selection route L4 ids to the L4 inspector.
      app.setL4Ids?.(ids);
      const got = await Promise.all(ids.map((id) => app.call<L4FlowWire>('l4.flow.get', { id }).catch(() => null)));
      batch(() => {
        for (const f of got) if (f && typeof f.id === 'string') setFlowsById(f.id, f);
      });
      if (caps().scope) setScope((await app.call<L4ScopeEntryWire[]>('l4.scope.list').catch(() => [])) ?? []);
      if (caps().capture) setCaptureIds((await app.call<string[]>('l4.capture.status').catch(() => [])) ?? []);
      if (caps().agentStatus) setGates((await app.call<AgentGates>('l4.agent.status').catch(() => null)) ?? null);
      if (caps().intercept) {
        const sessions = (await app.call<{ parked?: number }[]>('l4.intercept.status').catch(() => [])) ?? [];
        setInterceptParked(sessions.reduce((n, s) => n + (typeof s.parked === 'number' ? s.parked : 0), 0));
        const parked = (await app.call<{ id?: string }[]>('l4.intercept.list').catch(() => [])) ?? [];
        setFirstParkedId(parked[0]?.id ?? null);
      }
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  /** The L4 rows for the union list; a flow whose detail failed to load is a labelled placeholder. */
  const rows = createMemo<UnionRow[]>(() => ids().map((id) => (flowsById[id] ? l4Row(flowsById[id]!, scope()) : placeholderRow(id, 'l4'))));
  // Selection is the app's single `selectedId`; the L4 inspector shows it when it is an L4 flow.
  const selectedFlow = createMemo<L4FlowWire | null>(() => {
    const id = app.selectedId?.();
    return id ? (flowsById[id] ?? null) : null;
  });
  const selectedRow = createMemo<UnionRow | null>(() => {
    const f = selectedFlow();
    return f ? l4Row(f, scope()) : null;
  });

  const craft = (spec: PacketSpec) => app.call<L4CraftResult>('l4.craft', { spec });

  async function startCapture(iface: string, filter: string | null): Promise<void> {
    try {
      await app.call('l4.capture.start', filter ? { interface: iface, filter } : { interface: iface });
      app.notice(`Capture started on ${iface}`);
      await refresh();
    } catch (e) {
      app.notice(`l4.capture.start: ${(e as Error).message}`, 'error');
    }
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
    rows,
    ids,
    scope,
    gates,
    captureIds,
    interceptParked,
    firstParkedId,
    selectedFlow,
    selectedRow,
    refresh,
    craft,
    startCapture,
    setGate,
    error,
    call: app.call,
  };
}

export type L4Store = ReturnType<typeof createL4Store>;
