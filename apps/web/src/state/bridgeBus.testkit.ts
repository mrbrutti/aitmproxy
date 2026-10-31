// The shared test double for the store's live-list suites (`app.polling.test.ts`, `app.push.test.ts`,
// and the resync / activity suites that follow): a bus that looks like the /bus bridge, not like the
// `fixtures` mock. The file name is not `*.test.ts`, so vitest does not collect it; `tsc` still checks
// it and `vite build` never bundles it (nothing under the app imports it).

import { createSignal } from 'solid-js';
import { createMockBus, type MockControls } from '~/bus/mock';
import { generateRequest, generateResponse, mulberry32 } from '~/bus/fixtures';
import { BusError, type BusClient, type BusState, type NotificationHandler, type ToolDef } from '~/bus/types';

export const SUBSCRIBE: ToolDef = {
  name: 'flow.subscribe',
  description: 'Stream flow events (streaming MCP connections only).',
  inputSchema: { type: 'object', properties: {} },
};

export type TestBus = BusClient &
  MockControls & {
    /** Every tool called through the store, in order (`tools/list` included). */
    calls: string[];
    count(tool: string): number;
    /** The arguments of every call to `tool`, in order. */
    callArgs(tool: string): Record<string, unknown>[];
    /** The most `flow.detail` calls that were ever in flight at once. */
    peak: { detail: number };
    /** Deliver a server notification to the store, as a streaming bus would. */
    emit(method: string, params: unknown): void;
    /**
     * Failure / latency injection: `flow.list` fails or is held, the next `tools/list` rejects, and
     * the next `failStatus` `proxy.status` calls throw (set these BEFORE `start()` to fail bootstrap);
     * `setState` moves the bus through open / reconnecting / closed, and `failDetail` lists flow ids
     * whose `flow.detail` / `flow.get` always error (a flow the core cannot render). `holdReply`
     * holds one `flow.detail` reply per id: the reply is computed when the mock answers (its few ms
     * of latency) but delivered only when the promise settles; the entry is used once and removed.
     * `hideTools` names tools removed from the catalogue (set before `start()`). `activityWire`,
     * when set, is what `agent.activity` returns instead of the mock's own log: the server's wire
     * shape (epoch ms, `client_label`, `args` as JSON text), un-normalized and un-filtered.
     * `stripSeq`, when true, removes `seq` from every `flow.detail` / `flow.get` reply, as the real
     * core's reply carries none (`aitm-plugins/src/detail.rs`): the fixture flows do, and `toSummary`
     * prefers a reply's own `seq` to the store's position, so without this a test cannot tell the
     * store's numbering from the fixture's.
     */
    ctl: {
      failDetail: Set<string>;
      failFlowList: boolean;
      holdFlowList: Promise<void> | null;
      holdReply: Map<string, Promise<void>>;
      hideTools: Set<string>;
      failToolsOnce: boolean;
      failStatus: number;
      activityWire: unknown[] | null;
      stripSeq: boolean;
      setState(s: BusState): void;
    };
  };

/**
 * A real-looking bus (not the `fixtures` one): the mock command set, an address that is not
 * `fixtures`, `flow.subscribe` advertised, and NO notifications of its own — like the /bus bridge.
 * It starts `open`; `ctl.setState` plays out an outage.
 */
export function bridgeBus(address = '127.0.0.1:8082'): TestBus {
  const mock = createMockBus({ initial: 0, rate: 0, agentActive: false });
  const handlers = new Set<NotificationHandler>();
  const calls: string[] = [];
  const log: { tool: string; args: Record<string, unknown> }[] = [];
  const peak = { detail: 0 };
  let detailInFlight = 0;
  const [state, setState] = createSignal<BusState>('open');
  const ctl: TestBus['ctl'] = {
    failDetail: new Set(),
    failFlowList: false,
    holdFlowList: null,
    holdReply: new Map(),
    hideTools: new Set(),
    failToolsOnce: false,
    failStatus: 0,
    activityWire: null,
    stripSeq: false,
    setState,
  };
  return {
    ...mock,
    address,
    state,
    close() {
      mock.close();
      setState('closed');
    },
    calls,
    peak,
    ctl,
    count: (tool) => calls.filter((c) => c === tool).length,
    callArgs: (tool) => log.filter((c) => c.tool === tool).map((c) => c.args),
    async tools() {
      calls.push('tools/list');
      if (ctl.failToolsOnce) {
        ctl.failToolsOnce = false;
        throw new BusError('tools/list: bus closed (1006)');
      }
      return [...(await mock.tools()), SUBSCRIBE].filter((t) => !ctl.hideTools.has(t.name));
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      const reply = await answer<T>(tool, args);
      return ctl.stripSeq && (tool === 'flow.detail' || tool === 'flow.get') ? (withoutSeq(reply) as T) : reply;
    },
    onNotification(h) {
      handlers.add(h);
      return () => handlers.delete(h);
    },
    emit(method, params) {
      for (const h of handlers) h(method, params);
    },
  };

  async function answer<T>(tool: string, args: Record<string, unknown>): Promise<T> {
    calls.push(tool);
    log.push({ tool, args });
    if (tool === 'flow.list') {
      if (ctl.holdFlowList) await ctl.holdFlowList;
      if (ctl.failFlowList) throw new BusError('bus unreachable');
    }
    if (tool === 'proxy.status' && ctl.failStatus > 0) {
      ctl.failStatus--;
      throw new BusError('proxy.status: bus closed (1006)');
    }
    if ((tool === 'flow.detail' || tool === 'flow.get') && ctl.failDetail.has(args.id as string)) throw new BusError(`${tool}: flow ${String(args.id)} cannot be read`);
    if (tool === 'agent.activity' && ctl.activityWire) return ctl.activityWire as T;
    if (tool !== 'flow.detail') return mock.call<T>(tool, args);
    peak.detail = Math.max(peak.detail, ++detailInFlight);
    try {
      const gate = ctl.holdReply.get(args.id as string);
      if (gate) ctl.holdReply.delete(args.id as string);
      const reply = await mock.call<T>(tool, args);
      if (gate) await gate;
      return reply;
    } finally {
      detailInFlight--;
    }
  }
}

/** A copy of a flow reply without its `seq`, which is what the real core sends. */
function withoutSeq(reply: unknown): unknown {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) return reply;
  const copy: Record<string, unknown> = { ...reply };
  delete copy.seq;
  return copy;
}

/** A flow appears in the core with no notification — what the bridge does for every capture. */
export function captureSilently(bus: TestBus, seq: number): string {
  const now = Date.now();
  const flow = generateResponse(generateRequest({ rng: mulberry32(seq), seq, now, armed: false, scope: [] }), mulberry32(seq), now);
  bus.flowsById().set(flow.id, flow);
  return flow.id;
}

/** A flow still waiting for its response: `status` is null, so the loop keeps re-reading it. */
export function captureInFlight(bus: TestBus, seq: number): string {
  const flow = generateRequest({ rng: mulberry32(seq), seq, now: Date.now(), armed: false, scope: [] });
  bus.flowsById().set(flow.id, flow);
  return flow.id;
}

/** The core answers that in-flight flow's request, so its next read has a status. */
export function complete(bus: TestBus, id: string) {
  bus.flowsById().set(id, generateResponse(bus.flowsById().get(id)!, mulberry32(1), Date.now()));
}
