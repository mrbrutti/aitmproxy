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
