// Role echo + mismatch (Decisions C/D, Task 6): the bus client reads `result.role` from the
// `initialize` reply and compares it to the client-side `expect` carried in the launch-URL
// fragment. `expect` is never sent to the server; it only drives the mismatch warning.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createWsBus } from './ws';
import type { BusRole } from './types';

/** A WebSocket stand-in: captures sent lines and lets the test deliver replies. jsdom has none. */
class FakeWebSocket {
  static OPEN = 1;
  static last: FakeWebSocket | null = null;
  /** Sockets constructed since the last reset: one per connect attempt, so it counts reconnects. */
  static count = 0;
  readyState = FakeWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  sent: string[] = [];
  constructor(readonly url: string) {
    FakeWebSocket.last = this;
    FakeWebSocket.count++;
  }
  send(data: string) {
    this.sent.push(data);
  }
  close() {
    this.readyState = 3;
    this.onclose?.({ code: 1000 });
  }
}

/** Open a bus, drive the `initialize` handshake, and reply with `result`. Returns the open client. */
async function connectWith(result: Record<string, unknown>, expectRole: BusRole | null = null) {
  const client = createWsBus({ url: 'ws://127.0.0.1/bus', token: 'bridge-token', expect: expectRole });
  client.connect();
  const sock = FakeWebSocket.last!;
  sock.onopen?.();
  // The first JSON-RPC request on the socket is `initialize` (id 1); reply to it.
  await vi.waitFor(() => {
    if (!sock.sent.some((l) => l.includes('"method":"initialize"'))) throw new Error('no initialize yet');
  });
  sock.onmessage?.({ data: JSON.stringify({ jsonrpc: '2.0', id: 1, result }) + '\n' });
  // The client subscribes to pushes before it opens; answer that too.
  await answerTool(sock, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
  await vi.waitFor(() => {
    if (client.state() !== 'open') throw new Error('not open yet');
  });
  return client;
}

describe('createWsBus role echo', () => {
  beforeEach(() => {
    FakeWebSocket.last = null;
    vi.stubGlobal('WebSocket', FakeWebSocket);
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('reads_role_from_initialize', async () => {
    const client = await connectWith({ protocolVersion: '2025-06-18', role: 'operator' });
    expect(client.role()).toBe('operator');
    expect(client.expectRole).toBe(null);
    expect(client.roleMismatch()).toBe(false);
    client.close();
  });

  it('mismatch_when_expect_operator_but_agent', async () => {
    const mismatched = await connectWith({ role: 'agent' }, 'operator');
    expect(mismatched.role()).toBe('agent');
    expect(mismatched.roleMismatch()).toBe(true);
    mismatched.close();

    const matched = await connectWith({ role: 'operator' }, 'operator');
    expect(matched.role()).toBe('operator');
    expect(matched.roleMismatch()).toBe(false);
    matched.close();
  });

  it('missing_role_with_expectation_warns', async () => {
    const client = await connectWith({ protocolVersion: '2025-06-18' }, 'operator');
    expect(client.role()).toBe(null);
    expect(client.roleMismatch()).toBe(true);
    client.close();
  });
});

/** Resolves to `{ok}` / `{err}` when `p` settles, or `'hung'` if it has not within `ms`. */
const outcome = <T>(p: Promise<T>, ms = 300) =>
  Promise.race([
    p.then(
      (ok) => ({ ok }),
      (e: Error) => ({ err: e.message }),
    ),
    new Promise<'hung'>((r) => setTimeout(() => r('hung'), ms)),
  ]);

/** Reply to the next `method` request the client sent on `sock`. */
async function answer(sock: FakeWebSocket, method: string, result: unknown) {
  const sent = () => sock.sent.find((l) => l.includes(`"method":"${method}"`));
  await vi.waitFor(() => {
    if (!sent()) throw new Error(`no ${method} sent`);
  });
  const { id } = JSON.parse(sent()!) as { id: number };
  sock.onmessage?.({ data: JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n' });
}

/** Every JSON line the client sent on `sock`, parsed (the first is the token line, no `method`). */
const frames = (sock: FakeWebSocket) =>
  sock.sent.map((l) => JSON.parse(l) as { id?: number; method?: string; params?: { name?: string } });

/** Wait until the client has sent a `tools/call` for tool `name` on `sock`; returns that frame. */
async function toolCallSent(sock: FakeWebSocket, name: string) {
  const find = () => frames(sock).find((m) => m.method === 'tools/call' && m.params?.name === name);
  await vi.waitFor(() => {
    if (!find()) throw new Error(`no tools/call ${name} sent`);
  });
  return find()!;
}

/** Reply to the `tools/call` whose `params.name` is `name` (not to any other tool's call). */
async function answerTool(sock: FakeWebSocket, name: string, result: unknown) {
  const { id } = await toolCallSent(sock, name);
  sock.onmessage?.({ data: JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n' });
}

/** Answer the `tools/call` for tool `name` with a JSON-RPC error (what an unknown tool gets). */
async function failTool(sock: FakeWebSocket, name: string, code: number, message: string) {
  const { id } = await toolCallSent(sock, name);
  sock.onmessage?.({ data: JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }) + '\n' });
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

/** The attempt is refused: the socket errors and closes without ever opening. */
const refuse = (sock: FakeWebSocket) => {
  sock.onerror?.();
  sock.readyState = 3;
  sock.onclose?.({ code: 1006 });
};

/** Let the back-off timer fire and bring the NEXT attempt up: handshake answered, state open. */
async function openNextAttempt(client: ReturnType<typeof createWsBus>, previous: FakeWebSocket) {
  await vi.waitFor(() => {
    if (FakeWebSocket.last === previous) throw new Error('next attempt not started');
  });
  const next = FakeWebSocket.last!;
  next.onopen?.();
  await answer(next, 'initialize', { protocolVersion: '2025-06-18', role: 'operator' });
  await answerTool(next, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
  await vi.waitFor(() => {
    if (client.state() !== 'open') throw new Error('not open yet');
  });
  return next;
}

describe('createWsBus calls across a failed connect attempt', () => {
  let clients: ReturnType<typeof createWsBus>[] = [];
  const bus = () => {
    const c = createWsBus({ url: 'ws://127.0.0.1/bus', token: 'bridge-token', backoff: [5] });
    clients.push(c);
    return c;
  };
  beforeEach(() => {
    FakeWebSocket.last = null;
    vi.stubGlobal('WebSocket', FakeWebSocket);
  });
  afterEach(() => {
    for (const c of clients) c.close();
    clients = [];
    vi.unstubAllGlobals();
  });

  it('a call made while an attempt is failing resolves after the next successful open', async () => {
    const client = bus();
    client.connect();
    const first = FakeWebSocket.last!;
    refuse(first);
    expect(client.state()).toBe('reconnecting');

    // A caller arrives between the refused attempt and the next one…
    const call = client.call<string[]>('flow.list');
    // …the next attempt succeeds…
    const second = await openNextAttempt(client, first);
    await answerTool(second, 'flow.list', { structuredContent: ['f_1', 'f_2'] });

    // …and the call made earlier is answered, not stranded on the first attempt's ready-promise.
    expect(await outcome(call)).toEqual({ ok: ['f_1', 'f_2'] });
    const sentCall = JSON.parse(second.sent.find((l) => l.includes('"name":"flow.list"'))!);
    expect(sentCall.params).toEqual({ name: 'flow.list', arguments: {} });
  });

  it('tools() awaited at bootstrap survives a refused first connect', async () => {
    const client = bus();
    client.connect();
    const first = FakeWebSocket.last!;
    const tools = client.tools(); // bootstrap: connect(), then await bus.tools() — before anything fails
    refuse(first);

    const second = await openNextAttempt(client, first);
    await answer(second, 'tools/list', { tools: [{ name: 'flow.list', description: '', inputSchema: { type: 'object' } }] });

    expect(await outcome(tools)).toEqual({ ok: [{ name: 'flow.list', description: '', inputSchema: { type: 'object' } }] });
  });

  it('close() releases a call that is still waiting for a connection, with an error', async () => {
    const client = bus();
    client.connect();
    refuse(FakeWebSocket.last!);
    const call = client.call('flow.list');

    client.close();

    expect(await outcome(call)).toEqual({ err: 'bus not connected' });
  });
});

// Subscribe on every open (web-ui-bus-push D1, AC1-AC5): after the `initialize` handshake the client
// sends `flow.subscribe` and is not `open` until that call settles. Any failure of the subscribe is
// swallowed (the poll loop is the fallback); a socket that dies meanwhile is never marked open.
describe('createWsBus subscribes on every open', () => {
  let clients: ReturnType<typeof createWsBus>[] = [];
  const bus = (extra: Partial<Parameters<typeof createWsBus>[0]> = {}) => {
    const c = createWsBus({ url: 'ws://127.0.0.1/bus', token: 'bridge-token', backoff: [5], ...extra });
    clients.push(c);
    return c;
  };
  const SERVER = { protocolVersion: '2025-06-18', role: 'operator' };
  const isSubscribe = (l: string) => l.includes('"method":"tools/call"') && l.includes('"name":"flow.subscribe"');

  /** Connect and drive the handshake up to (not including) the subscribe reply. */
  async function handshake(client: ReturnType<typeof createWsBus>) {
    client.connect();
    const sock = FakeWebSocket.last!;
    sock.onopen?.();
    await answer(sock, 'initialize', SERVER);
    return sock;
  }

  beforeEach(() => {
    FakeWebSocket.last = null;
    FakeWebSocket.count = 0;
    vi.stubGlobal('WebSocket', FakeWebSocket);
  });
  afterEach(() => {
    for (const c of clients) c.close();
    clients = [];
    vi.unstubAllGlobals();
  });

  it('subscribes_after_initialized_and_before_open', async () => {
    const client = bus();
    const sock = await handshake(client);
    // The bootstrap's first call arrives while the subscribe is still pending…
    const call = client.call<string[]>('flow.list');

    const sub = await toolCallSent(sock, 'flow.subscribe');
    expect(sock.sent.slice(1).map((l) => JSON.parse(l).method)).toEqual([
      'initialize',
      'notifications/initialized',
      'tools/call',
    ]);
    expect(JSON.parse(sock.sent.at(-1)!).params).toEqual({ name: 'flow.subscribe', arguments: {} });
    expect(sub.params).toEqual({ name: 'flow.subscribe', arguments: {} });
    expect(client.state()).toBe('connecting');
    // …and does not go on the wire before the subscribe reply: the only tools/call so far is the subscribe.
    expect(frames(sock).filter((m) => m.method === 'tools/call')).toHaveLength(1);
    expect(await outcome(call, 50)).toBe('hung');

    await answerTool(sock, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await vi.waitFor(() => expect(client.state()).toBe('open'));

    await answerTool(sock, 'flow.list', { structuredContent: ['f_1'] });
    expect(await outcome(call)).toEqual({ ok: ['f_1'] });
    const calls = frames(sock).filter((m) => m.method === 'tools/call');
    expect(calls.map((m) => m.params?.name)).toEqual(['flow.subscribe', 'flow.list']);
  });

  it('resubscribes_on_every_reconnect', async () => {
    const client = bus();
    const first = await handshake(client);
    await toolCallSent(first, 'flow.subscribe');
    expect(client.state()).toBe('connecting');
    await answerTool(first, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await vi.waitFor(() => expect(client.state()).toBe('open'));

    first.close();
    expect(client.state()).toBe('reconnecting');
    await vi.waitFor(() => {
      if (FakeWebSocket.last === first) throw new Error('next attempt not started');
    });
    const second = FakeWebSocket.last!;
    second.onopen?.();
    await answer(second, 'initialize', SERVER);
    await toolCallSent(second, 'flow.subscribe');
    expect(client.state()).toBe('reconnecting');
    await answerTool(second, 'flow.subscribe', { structuredContent: { sub_id: 2 } });
    await vi.waitFor(() => expect(client.state()).toBe('open'));

    expect(FakeWebSocket.count).toBe(2);
    expect(first.sent.filter(isSubscribe)).toHaveLength(1);
    expect(second.sent.filter(isSubscribe)).toHaveLength(1);
  });

  it('a_refused_subscribe_still_opens', async () => {
    const client = bus();
    const sock = await handshake(client);
    await answerTool(sock, 'flow.subscribe', {
      isError: true,
      content: [{ type: 'text', text: '`flow.subscribe` refused: the agent policy is `paused`' }],
    });
    await vi.waitFor(() => expect(client.state()).toBe('open'));
    await sleep(30); // long enough for a back-off (5 ms) reconnect to have shown up, had one been scheduled
    expect(client.state()).toBe('open');
    expect(client.lastError()).toBe(null);
    expect(FakeWebSocket.count).toBe(1);
  });

  it('an_unknown_tool_error_still_opens', async () => {
    const client = bus();
    const sock = await handshake(client);
    await failTool(sock, 'flow.subscribe', -32602, 'unknown tool `flow.subscribe`');
    await vi.waitFor(() => expect(client.state()).toBe('open'));
    await sleep(30);
    expect(client.state()).toBe('open');
    expect(client.lastError()).toBe(null);
    expect(FakeWebSocket.count).toBe(1);
  });

  it('a_silent_subscribe_times_out_and_opens', async () => {
    const client = bus({ subscribeTimeoutMs: 20 });
    const sock = await handshake(client);
    await toolCallSent(sock, 'flow.subscribe');
    expect(client.state()).toBe('connecting');

    // Never answered: the timeout opens the bus.
    await vi.waitFor(() => expect(client.state()).toBe('open'));
    expect(client.lastError()).toBe(null);
    expect(FakeWebSocket.count).toBe(1);

    // A reply that turns up after the timeout is ignored, not an error.
    await answerTool(sock, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await sleep(10);
    expect(client.state()).toBe('open');
    expect(client.lastError()).toBe(null);
  });

  it('a_socket_that_closes_during_subscribe_is_not_marked_open', async () => {
    const client = bus();
    const first = await handshake(client);
    await toolCallSent(first, 'flow.subscribe');

    refuse(first); // closes before the subscribe reply
    expect(client.state()).toBe('reconnecting');
    await sleep(50);
    expect(client.state()).toBe('reconnecting');

    // The back-off brought the next attempt up; it subscribes on its own socket and opens.
    const second = FakeWebSocket.last!;
    expect(second).not.toBe(first);
    second.onopen?.();
    await answer(second, 'initialize', SERVER);
    await toolCallSent(second, 'flow.subscribe');
    expect(client.state()).toBe('reconnecting');
    await answerTool(second, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await vi.waitFor(() => expect(client.state()).toBe('open'));
    expect(second.sent.filter(isSubscribe)).toHaveLength(1);
  });

  it('a_user_close_during_subscribe_leaves_the_bus_closed', async () => {
    const client = bus();
    const sock = await handshake(client);
    await toolCallSent(sock, 'flow.subscribe');

    client.close();
    expect(client.state()).toBe('closed');
    await sleep(50);
    expect(client.state()).toBe('closed');
    expect(FakeWebSocket.count).toBe(1);
  });

  // The belt and braces behind `ws !== sock`: a browser flips `readyState` before it delivers the close
  // event, and `close()` does not deliver it synchronously either. A reply landing in that gap must not
  // open a dead or user-closed socket.
  it('a_socket_that_is_closing_when_the_subscribe_reply_lands_is_not_marked_open', async () => {
    const client = bus();
    const sock = await handshake(client);
    await toolCallSent(sock, 'flow.subscribe');

    sock.readyState = 2; // CLOSING; `onclose` has not run, so the client still holds this socket
    await answerTool(sock, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await sleep(50);
    expect(client.state()).toBe('connecting');

    sock.readyState = 3;
    sock.onclose?.({ code: 1006 }); // the close event arrives late: now the reconnect is scheduled
    expect(client.state()).toBe('reconnecting');
  });

  it('a_user_close_whose_close_event_is_still_pending_stays_closed_when_the_reply_lands', async () => {
    const client = bus();
    const sock = await handshake(client);
    await toolCallSent(sock, 'flow.subscribe');

    sock.close = () => {}; // the close event is delivered later, as in a browser; the socket still reads OPEN
    client.close();
    expect(client.state()).toBe('closed');
    await answerTool(sock, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await sleep(50);

    expect(client.state()).toBe('closed');
    expect(FakeWebSocket.count).toBe(1);
  });

  // The bridge may batch several newline-delimited lines in one frame, and the subscribe reply now gates
  // `open`: a notification and a garbage line riding in the same frame must not lose it.
  it('a_frame_batching_a_notification_a_garbage_line_and_the_subscribe_reply_still_opens', async () => {
    const client = bus();
    const h = vi.fn();
    client.onNotification(h);
    const sock = await handshake(client);
    const { id } = await toolCallSent(sock, 'flow.subscribe');

    sock.onmessage?.({
      data:
        [
          JSON.stringify({ jsonrpc: '2.0', method: 'notifications/aitm/flow', params: { event: 'created', id: 'f_1' } }),
          '{"jsonrpc":"2.0","id":', // cut mid-line
          'not json at all',
          JSON.stringify({ jsonrpc: '2.0', id, result: { structuredContent: { sub_id: 1 } } }),
        ].join('\n') + '\n',
    });

    await vi.waitFor(() => expect(client.state()).toBe('open'));
    expect(h).toHaveBeenCalledTimes(1);
    expect(client.lastError()).toBe(null);
  });

  it('notifications_before_the_subscribe_reply_reach_handlers', async () => {
    const client = bus();
    const h = vi.fn();
    client.onNotification(h);
    const sock = await handshake(client);
    await toolCallSent(sock, 'flow.subscribe');

    sock.onmessage?.({
      data:
        JSON.stringify({
          jsonrpc: '2.0',
          method: 'notifications/aitm/flow',
          params: { event: 'created', id: 'f_1' },
        }) + '\n',
    });
    expect(client.state()).toBe('connecting');
    expect(h).toHaveBeenCalledTimes(1);
    expect(h).toHaveBeenCalledWith('notifications/aitm/flow', { event: 'created', id: 'f_1' });

    await answerTool(sock, 'flow.subscribe', { structuredContent: { sub_id: 1 } });
    await vi.waitFor(() => expect(client.state()).toBe('open'));
    expect(h).toHaveBeenCalledTimes(1);
  });
});
