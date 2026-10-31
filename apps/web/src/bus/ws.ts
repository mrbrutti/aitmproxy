// WebSocket bus client: one connection for calls and notifications, token as the first
// message (mirrors LoopbackTcp's token line, §4.1), reconnect with back-off (§4.2 step 5),
// `flow.subscribe` on every open before the bus is marked open (web-ui-bus-push D1).

import { createSignal } from 'solid-js';
import {
  asRole,
  BusError,
  CLIENT_INFO,
  PROTOCOL_VERSION,
  type BusClient,
  type BusRole,
  type BusState,
  type JsonRpcResponse,
  type NotificationHandler,
  type ServerInfo,
  type ToolCallResult,
  type ToolDef,
} from './types';

export interface WsBusOptions {
  url: string;
  token?: string | null;
  /** Client-side role expectation from the launch URL fragment (Decision B); never sent upstream. */
  expect?: BusRole | null;
  /** Back-off schedule in ms; the last value repeats. */
  backoff?: number[];
  /**
   * How long an open waits for the `flow.subscribe` reply before opening without it (default 3000).
   * Only a server that swallows unknown calls ever runs the clock out.
   */
  subscribeTimeoutMs?: number;
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  method: string;
}

export function createWsBus(opts: WsBusOptions): BusClient {
  const backoff = opts.backoff ?? [250, 500, 1000, 2000, 5000];
  const subscribeTimeoutMs = opts.subscribeTimeoutMs ?? 3000;
  const UNAUTHORIZED_MESSAGE = 'token expired — reopen the URL printed by `aitm web`';
  const [state, setState] = createSignal<BusState>('idle');
  const [lastError, setLastError] = createSignal<string | null>(null);
  const [role, setRole] = createSignal<BusRole | null>(null);
  const expectRole = opts.expect ?? null;
  const handlers = new Set<NotificationHandler>();
  const pending = new Map<number, Pending>();
  let ws: WebSocket | null = null;
  let nextId = 1;
  let attempt = 0;
  let closedByUser = false;
  // Set once the server refuses this connection's token (a 1008 close or an `id:null`/-32001 reply).
  // A stale tab must stop reconnecting and show why, instead of hammering a token that will never work.
  let authFailed = false;
  let toolsCache: ToolDef[] | null = null;
  let ready: Promise<void> = Promise.resolve();
  let readyPending = false;
  let resolveReady: () => void = () => {};
  let timer: ReturnType<typeof setTimeout> | null = null;

  const address = (() => {
    try {
      const u = new URL(opts.url, location.href);
      return u.host;
    } catch {
      return opts.url;
    }
  })();

  /**
   * Callers wait on `ready` until a connection is open. While one is pending it is KEPT across failed
   * attempts: replacing it would strand every caller that already holds it (they would never be
   * released, even once a later attempt succeeds). A fresh one is armed only after the last settled.
   */
  function armReady() {
    if (readyPending) return;
    readyPending = true;
    ready = new Promise<void>((r) => {
      resolveReady = () => {
        readyPending = false;
        r();
      };
    });
  }

  /** Release every waiter: the bus opened, or was closed (they then fail fast in `send`). */
  function settleReady() {
    if (readyPending) resolveReady();
  }

  function send(obj: unknown) {
    if (!ws || ws.readyState !== WebSocket.OPEN) throw new BusError('bus not connected');
    ws.send(JSON.stringify(obj) + '\n');
  }

  function request<T>(method: string, params?: unknown): Promise<T> {
    const id = nextId++;
    return new Promise<T>((resolve, reject) => {
      pending.set(id, { resolve: resolve as (v: unknown) => void, reject, method });
      try {
        send({ jsonrpc: '2.0', id, method, params });
      } catch (e) {
        pending.delete(id);
        reject(e as Error);
      }
    });
  }

  function failAllPending(reason: string) {
    for (const [, p] of pending) p.reject(new BusError(reason));
    pending.clear();
  }

  /**
   * The server rejected this connection's token. Latch `authFailed` so `scheduleReconnect` stops, go
   * to the `'unauthorized'` state with the reopen-the-URL message, fail any in-flight calls, and
   * release waiters. A stale tab reconnecting forever with a dead token is the thing to prevent.
   */
  function markAuthFailed() {
    authFailed = true;
    setState('unauthorized');
    setLastError(UNAUTHORIZED_MESSAGE);
    failAllPending(UNAUTHORIZED_MESSAGE);
    settleReady();
  }

  /**
   * Subscribe this connection to flow/agent pushes (`flow.subscribe {}`), awaited before the bus is
   * marked open so the stream exists before the bootstrap `flow.list` goes out (the bridge runs
   * frames concurrently; only an awaited reply orders them). Goes through `request`, not
   * `client.call`, which awaits `ready` and would deadlock here. Never throws: a refusal (`isError`),
   * an unknown-tool error, a closed socket and a silent server all resolve, the bus opens, and the
   * poll loop covers the missing stream. A timed-out request is dropped from `pending` so a late
   * reply is ignored.
   */
  async function subscribeOnOpen(): Promise<void> {
    const id = nextId; // `request` takes this id synchronously; kept so the timeout can drop its entry
    const reply = request<ToolCallResult>('tools/call', { name: 'flow.subscribe', arguments: {} });
    let expire: () => void = () => {};
    const timedOut = new Promise<void>((r) => (expire = r));
    const subscribeTimer = setTimeout(() => {
      pending.delete(id);
      expire();
    }, subscribeTimeoutMs);
    await Promise.race([
      reply.then(
        () => undefined,
        () => undefined,
      ),
      timedOut,
    ]);
    clearTimeout(subscribeTimer);
  }

  function onMessage(ev: MessageEvent) {
    const text = typeof ev.data === 'string' ? ev.data : '';
    // The bridge may batch several newline-delimited lines in one frame.
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let msg: JsonRpcResponse & { method?: string; params?: unknown };
      try {
        msg = JSON.parse(line);
      } catch {
        continue;
      }
      // `JSON.parse` also yields `null`, arrays and bare scalars; none is a message, and `null` would
      // throw on the property reads below, outside the handler try/catch, and lose the rest of the frame.
      if (!msg || typeof msg !== 'object' || Array.isArray(msg)) continue;
      if (typeof msg.method === 'string' && msg.id === undefined) {
        for (const h of handlers) {
          // A handler is the store's code. One that throws must not take the other handlers down, nor
          // the rest of this frame (it may carry the subscribe reply or a call's reply). Swallowed: this
          // client has no log, and the store's poll loop re-reads whatever the notification was about.
          try {
            h(msg.method, msg.params);
          } catch {
            // see above
          }
        }
        continue;
      }
      // Signal A — the definitive refusal reply: an error with no request id (`id:null`/undefined) and
      // the unauthorized code. Not a reply to any pending call, so it must be handled before that branch.
      if ((msg.id === null || msg.id === undefined) && msg.error?.code === -32001) {
        markAuthFailed();
        continue;
      }
      if (typeof msg.id === 'number') {
        const p = pending.get(msg.id);
        if (!p) continue;
        pending.delete(msg.id);
        if (msg.error) p.reject(new BusError(msg.error.message, msg.error.code, p.method));
        else p.resolve(msg.result);
      }
    }
  }

  function scheduleReconnect() {
    if (closedByUser || authFailed) return;
    const delay = backoff[Math.min(attempt, backoff.length - 1)] ?? 5000;
    attempt++;
    setState('reconnecting');
    timer = setTimeout(open, delay);
  }

  function open() {
    timer = null;
    armReady();
    setState(attempt === 0 ? 'connecting' : 'reconnecting');
    let sock: WebSocket;
    try {
      sock = new WebSocket(opts.url);
    } catch (e) {
      setLastError((e as Error).message);
      scheduleReconnect();
      return;
    }
    ws = sock;
    sock.onopen = async () => {
      try {
        if (opts.token) sock.send(JSON.stringify({ token: opts.token }) + '\n');
        const info = await request<ServerInfo>('initialize', {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: {},
          clientInfo: CLIENT_INFO,
        });
        // Decision C: read the resolved role echoed in the result; a missing/unknown value is
        // treated as "role unknown" (null), never asserted as a role.
        setRole(asRole(info?.role));
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        await subscribeOnOpen();
        // The socket may have closed, or the user closed the bus, while the subscribe was pending.
        // `onclose` has already scheduled the reconnect (or marked us closed): do not open this one.
        if (closedByUser || ws !== sock || sock.readyState !== WebSocket.OPEN) return;
        attempt = 0;
        setLastError(null);
        setState('open');
        settleReady();
      } catch (e) {
        // A pending `initialize` rejected by an auth-failure close/reply lands here; the unauthorized
        // state and message are already set and must not be overwritten with the rejection text.
        if (authFailed) return;
        setLastError((e as Error).message);
        sock.close();
      }
    };
    sock.onmessage = onMessage;
    sock.onerror = () => setLastError('connection error');
    sock.onclose = (ev) => {
      if (ws !== sock) return;
      ws = null;
      toolsCache = null;
      setRole(null); // role is per-connection; re-resolved on the next initialize.
      failAllPending(`bus closed (${ev.code})`);
      // A bad token is caught by Signal A (the `-32001` reply) in `onMessage`, which the bridge always
      // sends *before* it closes with `CloseCode::Policy` (1008) — so `authFailed` is already latched
      // here and `scheduleReconnect` returns early. The close code itself is NOT used to detect auth
      // failure: the bridge also closes with 1008 on an authentication *timeout* (a valid tab whose
      // first send was delayed), which is transient and must reconnect, not latch the tab into
      // `unauthorized`. So every close that is not an already-latched auth failure reconnects.
      if (closedByUser) setState('closed');
      else scheduleReconnect();
    };
  }

  const client: BusClient = {
    address,
    state,
    lastError,
    role,
    expectRole,
    // Warn whenever an expectation was set and the resolved role does not confirm it — including a
    // null role (server echoed none), so an operator URL that connects as agent never passes silently.
    roleMismatch: () => expectRole != null && role() !== expectRole,
    connect() {
      closedByUser = false;
      authFailed = false; // an explicit reconnect may carry a fresh token, so let it retry.
      if (ws || timer) return;
      attempt = 0;
      open();
    },
    close() {
      closedByUser = true;
      if (timer) clearTimeout(timer);
      timer = null;
      ws?.close();
      setState('closed');
      settleReady(); // callers still waiting for a connection proceed and fail with 'bus not connected'
    },
    async tools() {
      if (toolsCache) return toolsCache;
      await ready;
      const res = await request<{ tools: ToolDef[] }>('tools/list', {});
      toolsCache = res.tools;
      return toolsCache;
    },
    async call<T>(tool: string, args: Record<string, unknown> = {}): Promise<T> {
      await ready;
      const res = await request<ToolCallResult>('tools/call', { name: tool, arguments: args });
      if (res.isError) {
        throw new BusError(res.content?.[0]?.text ?? `${tool} failed`, null, tool);
      }
      if (res.structuredContent !== undefined) return res.structuredContent as T;
      const text = res.content?.[0]?.text ?? '';
      try {
        return JSON.parse(text) as T;
      } catch {
        return text as unknown as T;
      }
    },
    onNotification(handler) {
      handlers.add(handler);
      return () => handlers.delete(handler);
    },
  };
  return client;
}
