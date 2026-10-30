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
  readyState = FakeWebSocket.OPEN;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  onclose: ((ev: { code: number }) => void) | null = null;
  sent: string[] = [];
  constructor(readonly url: string) {
    FakeWebSocket.last = this;
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
    await answer(second, 'tools/call', { structuredContent: ['f_1', 'f_2'] });

    // …and the call made earlier is answered, not stranded on the first attempt's ready-promise.
    expect(await outcome(call)).toEqual({ ok: ['f_1', 'f_2'] });
    const sentCall = JSON.parse(second.sent.find((l) => l.includes('"method":"tools/call"'))!);
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
