// The shared test double for the store's live-list suites (`app.polling.test.ts`, `app.push.test.ts`,
// `app.resync.test.ts`, `app.activity.test.ts`) and, through `memoryBus`, for any suite that needs a
// `BusClient`: an in-memory bus that answers the few tools the store's bootstrap and those suites call,
// in the server's wire shapes, whose every flow is a literal written here or in the test. It has no
// sample set and sends no notifications of its own, like the /bus bridge; a test delivers them with
// `emit`. The file name is not `*.test.ts`, so vitest does not collect it; `tsc` still checks it and
// `vite build` never bundles it (nothing under the app imports it).

import { createSignal, type Accessor } from 'solid-js';
import { vi } from 'vitest';
import { BusError, type BusClient, type BusRole, type BusState, type NotificationHandler, type ToolDef } from '~/bus/types';

/** The `version` the test bus's `proxy.status` reports: never a real build's. */
export const TEST_VERSION = '0.0.0-test';

export const SUBSCRIBE: ToolDef = {
  name: 'flow.subscribe',
  description: 'Stream flow events (streaming MCP connections only).',
  inputSchema: { type: 'object', properties: {} },
};

/** Advance the fake clock by `ms`, running every timer and promise continuation that comes due. */
export const tick = (ms: number) => vi.advanceTimersByTimeAsync(ms);

/** A promise the test releases by hand, for `ctl.holdReply` and `ctl.holdFlowList`. */
export function gate() {
  let release!: () => void;
  const promise = new Promise<void>((r) => (release = r));
  return { promise, release };
}

/**
 * A flow notification with no summary, emitted to prove the flow stream is alive. It is still an
 * event to the store: on a bridge bus it queues `f_none`, whose `flow.detail` fails (the test bus has
 * no such flow) and is then held off for FAILED_RETRY_MS. A case that emits it counts `flow.list`, or
 * leaves room for that one failed read per hold-off; none asserts an exact `flow.detail` total after it.
 */
export const FLOW_PING = { event: 'meta', id: 'f_none' };

/** An audit line as the server sends it: epoch ms (2024-10-27T03:33:20.000Z), `client_label`, `args` as redacted JSON text. */
export const AGENT_LINE = { at: 1730000000000, origin: 'mcp', client_label: 'claude-code', command: 'flow.replay', args: '{"id":"f_1"}', result: 'ok' };

// ---- flows ----------------------------------------------------------------------------------------

/**
 * The server's `flow.get` / `flow.detail` object as `normalize.ts` documents it: epoch-ms times,
 * `request` / `response` nested with `[name, value]` headers and a base64 `body`, `client_conn` /
 * `server_conn`, `meta`, intercept as `observed | intercepted | resumed | killed`, and no `seq`.
 */
export type FlowWire = Record<string, unknown>;

/** 2024-10-27T03:33:20.000Z, the same instant `AGENT_LINE` uses. */
const STARTED_AT = 1730000000000;

/** The answered half of a flow: a 200 with a JSON body (`{"ok":true}`, 11 bytes, base64) and a duration. */
const RESPONDED: FlowWire = {
  status: 200,
  duration_ms: 12,
  response: {
    headers: [
      ['content-type', 'application/json'],
      ['content-length', '11'],
    ],
    body: 'eyJvayI6dHJ1ZX0=',
    body_size: 11,
    body_truncated: false,
  },
};

/** A tiny literal builder: one finished `GET https://api.example.test/v1/items` in the wire shape, with `over` written on top. */
export function flow(id: string, over: Partial<FlowWire> = {}): FlowWire {
  return {
    id,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    authority: 'api.example.test',
    path: '/v1/items',
    started_at: STARTED_AT,
    request: {
      headers: [
        ['host', 'api.example.test'],
        ['accept', 'application/json'],
      ],
      body: '',
      body_size: 0,
      body_truncated: false,
    },
    client_conn: { peer: '127.0.0.1:50123', tls: true },
    server_conn: { peer: 'api.example.test:443', tls: true },
    meta: { marks: [], comment: null },
    intercept: 'observed',
    ...RESPONDED,
    ...over,
  };
}

// ---- the in-memory bus ------------------------------------------------------------------------------

export interface MemoryBusOptions {
  /** The names `tools/list` returns. Default: every tool this bus answers, plus `flow.subscribe`. */
  tools?: string[];
  /** Names appended to that catalogue: the tools a test's own host answers on top of the bus (`script.enable`, …). */
  extraTools?: string[];
  /** What `script.list` returns. */
  scripts?: unknown[];
  address?: string;
}

export interface MemoryControls {
  /** The flows the bus serves, live: a test adds, replaces or removes entries between calls. */
  flowsById(): Map<string, FlowWire>;
  /** Deliver a server notification to the store, as a streaming bus would. */
  emit(method: string, params: unknown): void;
}

/** Every tool `memoryBus` answers; anything else throws `BusError`. */
const SERVED_TOOLS = ['flow.list', 'flow.get', 'flow.detail', 'flow.intercept', 'proxy.status', 'scope.list', 'agent.status', 'agent.activity', 'script.list', 'script.findings', 'poc.list'] as const;

/** A simulated loopback round trip on the fake clock, so loading states and in-flight counts are real. */
const LATENCY_MS = 5;

/**
 * A `BusClient` that serves `flow.list` (ids in insertion order), `flow.get` / `flow.detail` (the stored
 * object; an unknown id throws), `flow.intercept` (arms, as the core does; `enabled` defaults to true),
 * `proxy.status` (the server's shape, `version: TEST_VERSION`), and the empty side data
 * `createAppStore`'s bootstrap and the scripts store read. It starts `open`, resolves the `operator`
 * role, and pushes nothing by itself.
 */
export function memoryBus(opts: MemoryBusOptions = {}): BusClient & MemoryControls {
  const flows = new Map<string, FlowWire>();
  const catalogue: ToolDef[] = [...(opts.tools ?? [...SERVED_TOOLS, SUBSCRIBE.name]), ...(opts.extraTools ?? [])].map((name) =>
    name === SUBSCRIBE.name ? SUBSCRIBE : { name, description: `${name} (test bus)`, inputSchema: { type: 'object', properties: {} } },
  );
  const handlers = new Set<NotificationHandler>();
  const [state, setState] = createSignal<BusState>('open');
  const lastError: Accessor<string | null> = () => null;
  const role: Accessor<BusRole | null> = () => 'operator';
  let armed = false;

  async function answer(tool: string, args: Record<string, unknown>): Promise<unknown> {
    await new Promise((r) => setTimeout(r, LATENCY_MS));
    switch (tool) {
      case 'flow.list':
        return [...flows.keys()];
      case 'flow.get':
      case 'flow.detail': {
        const id = String(args.id ?? '');
        const f = flows.get(id);
        if (!f) throw new BusError(`${tool}: unknown flow ${id}`);
        return f;
      }
      case 'flow.intercept':
        armed = typeof args.enabled === 'boolean' ? args.enabled : true;
        return armed;
      case 'proxy.status':
        return { listening: true, address: '127.0.0.1:8080', capturing: true, intercept_armed: armed, paused: 0, flows: flows.size, version: TEST_VERSION };
      case 'scope.list':
        return [];
      case 'agent.status':
        return { policy: 'all', actions_last_minute: 0 };
      case 'agent.activity':
        return [];
      case 'script.list':
        return opts.scripts ?? [];
      case 'script.findings':
        return { findings: [], dropped: 0 };
      case 'poc.list':
        return [];
      default:
        throw new BusError(`${tool}: not served by the test bus`);
    }
  }

  return {
    address: opts.address ?? '127.0.0.1:8082',
    state,
    lastError,
    role,
    expectRole: null,
    roleMismatch: () => false,
    /** Open from the start, so there is nothing to connect; `bridgeBus`'s `ctl.setState` plays out an outage. */
    connect() {},
    close() {
      setState('closed');
    },
    async tools() {
      return catalogue;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      return (await answer(tool, args)) as T;
    },
    onNotification(h) {
      handlers.add(h);
      return () => handlers.delete(h);
    },
    emit(method, params) {
      for (const h of handlers) h(method, params);
    },
    flowsById: () => flows,
  };
}

// ---- the bridge-shaped bus the store suites share -----------------------------------------------------

export type TestBus = BusClient &
  MemoryControls & {
    /** Every tool called through the store, in order (`tools/list` included). */
    calls: string[];
    count(tool: string): number;
    /** The arguments of every call to `tool`, in order. */
    callArgs(tool: string): Record<string, unknown>[];
    /** The most `flow.detail` calls that were ever in flight at once. */
    peak: { detail: number };
    /**
     * Failure / latency injection: `flow.list` fails or is held, the next `tools/list` rejects, and
     * the next `failStatus` `proxy.status` calls throw (set these BEFORE `start()` to fail bootstrap);
     * `setState` moves the bus through open / reconnecting / closed, and `failDetail` lists flow ids
     * whose `flow.detail` / `flow.get` always error (a flow the core cannot render). `holdReply`
     * holds one `flow.detail` reply per id: the reply is computed when the bus answers (its few ms
     * of latency) but delivered only when the promise settles; the entry is used once and removed.
     * `replyWith` substitutes the `flow.detail` / `flow.get` reply for an id with that value, every
     * time, until the entry is removed (a core that answers with the wrong row, or no row).
     * `hideTools` names tools removed from the catalogue (set before `start()`). `activityWire`,
     * when set, is what `agent.activity` returns: the server's wire shape (epoch ms, `client_label`,
     * `args` as JSON text), un-normalized and un-filtered. `stripSeq`, when true, removes `seq` from
     * every `flow.detail` / `flow.get` reply, as the real core's reply carries none
     * (`aitm-plugins/src/detail.rs`); the testkit's own flows carry none either, so this guards a
     * flow a case writes by hand, since `toSummary` prefers a reply's own `seq` to the store's position.
     */
    ctl: {
      failDetail: Set<string>;
      failFlowList: boolean;
      holdFlowList: Promise<void> | null;
      holdReply: Map<string, Promise<void>>;
      replyWith: Map<string, unknown>;
      hideTools: Set<string>;
      failToolsOnce: boolean;
      failStatus: number;
      activityWire: unknown[] | null;
      stripSeq: boolean;
      setState(s: BusState): void;
    };
  };

/**
 * A bus shaped like the /bus bridge: `memoryBus` behind a call recorder with failure and latency
 * injection, `flow.subscribe` advertised, and NO notifications of its own. It starts `open`;
 * `ctl.setState` plays out an outage.
 */
export function bridgeBus(): TestBus {
  const mem = memoryBus();
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
    replyWith: new Map(),
    hideTools: new Set(),
    failToolsOnce: false,
    failStatus: 0,
    activityWire: null,
    stripSeq: false,
    setState,
  };

  /** One call: records it, applies the injected failures, holds and substitutes, then asks the memory bus. */
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
    if ((tool === 'flow.detail' || tool === 'flow.get') && ctl.replyWith.has(args.id as string)) return ctl.replyWith.get(args.id as string) as T;
    if (tool === 'agent.activity' && ctl.activityWire) return ctl.activityWire as T;
    if (tool !== 'flow.detail') return mem.call<T>(tool, args);
    peak.detail = Math.max(peak.detail, ++detailInFlight);
    try {
      // `held` is the test's promise for this id (made with `gate()` above), used once.
      const held = ctl.holdReply.get(args.id as string);
      if (held) ctl.holdReply.delete(args.id as string);
      const reply = await mem.call<T>(tool, args);
      if (held) await held;
      return reply;
    } finally {
      detailInFlight--;
    }
  }

  return {
    ...mem,
    state,
    close() {
      mem.close();
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
      return (await mem.tools()).filter((t) => !ctl.hideTools.has(t.name));
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      const reply = await answer<T>(tool, args);
      return ctl.stripSeq && (tool === 'flow.detail' || tool === 'flow.get') ? (withoutSeq(reply) as T) : reply;
    },
  };
}

/** A copy of a flow reply without its `seq`, which is what the real core sends. */
function withoutSeq(reply: unknown): unknown {
  if (!reply || typeof reply !== 'object' || Array.isArray(reply)) return reply;
  const copy: Record<string, unknown> = { ...reply };
  delete copy.seq;
  return copy;
}

// ---- captures -----------------------------------------------------------------------------------------

/** A flow appears in the core with no notification — what the bridge does for every capture. Its id is `f_<seq>`. */
export function captureSilently(bus: TestBus, seq: number): string {
  const id = `f_${seq}`;
  bus.flowsById().set(id, flow(id));
  return id;
}

/** A flow still waiting for its response: `status` is null, so the loop keeps re-reading it. */
export function captureInFlight(bus: TestBus, seq: number): string {
  const id = `f_${seq}`;
  bus.flowsById().set(id, flow(id, { status: null, duration_ms: null, response: null }));
  return id;
}

/** The core answers that in-flight flow's request, so its next read has a status (200) and a response. */
export function complete(bus: TestBus, id: string): void {
  const f = bus.flowsById().get(id);
  if (!f) throw new Error(`complete: no flow ${id} on the test bus`);
  bus.flowsById().set(id, { ...f, ...RESPONDED });
}
