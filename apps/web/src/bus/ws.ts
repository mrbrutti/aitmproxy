// WebSocket bus client: one connection for calls and notifications, token as the first
// message (mirrors LoopbackTcp's token line, §4.1), reconnect with back-off (§4.2 step 5).

import { createSignal } from 'solid-js';
import {
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
}

interface Pending {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  method: string;
}

export function createWsBus(opts: WsBusOptions): BusClient {
  const backoff = opts.backoff ?? [250, 500, 1000, 2000, 5000];
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
  let toolsCache: ToolDef[] | null = null;
  let ready: Promise<void> = Promise.resolve();
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

  function armReady() {
    ready = new Promise<void>((r) => (resolveReady = r));
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
      if (typeof msg.method === 'string' && msg.id === undefined) {
        for (const h of handlers) h(msg.method, msg.params);
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
    if (closedByUser) return;
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
        setRole(info?.role === 'operator' || info?.role === 'agent' ? info.role : null);
        send({ jsonrpc: '2.0', method: 'notifications/initialized' });
        attempt = 0;
        setLastError(null);
        setState('open');
        resolveReady();
      } catch (e) {
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
