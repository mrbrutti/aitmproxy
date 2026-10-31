// The bus shapes here follow the landed `flow.get` / `flow.detail` on the operator-commands
// branch (crates/aitm-plugins/src/{capture,detail,meta}.rs): if the core changes, change this.
import { describe, expect, it } from 'vitest';
import { bytesToBase64, utf8Encode } from '~/lib/bytes';
import { toAgentEntry, toDetail, toSummary } from './normalize';

const b64 = (s: string) => bytesToBase64(utf8Encode(s));

const busDetail = {
  id: 'f_1',
  kind: 'http',
  intercept: 'observed',
  edited: false,
  request: {
    method: 'POST',
    scheme: 'https',
    authority: 'auth.shop-staging.test',
    path: '/api/auth/login?next=%2F',
    version: 'HTTP/2',
    headers: [
      ['host', 'auth.shop-staging.test'],
      ['content-type', 'application/json'],
    ],
    body: b64('{"email":"ops@shop-staging.test"}'),
    body_size: 33,
    body_truncated: false,
  },
  response: {
    status: 200,
    version: 'HTTP/2',
    headers: [
      ['content-type', 'application/json; charset=utf-8'],
      ['set-cookie', 'session=abc; HttpOnly'],
    ],
    body: b64('{"token":"t"}'),
    body_size: 13,
    body_truncated: false,
  },
  client_conn: { peer: '127.0.0.1:52114', sni: 'auth.shop-staging.test', alpn: 'h2', tls: true, established: '2026-10-27T11:05:22.994Z', process: null },
  server_conn: { peer: '93.184.216.34:443', sni: 'auth.shop-staging.test', alpn: 'h2', tls: true, established: '2026-10-27T11:05:23.010Z' },
  meta: { marks: ['red'], comment: 'reflected', is_replay: false, created: '2026-10-27T11:05:22.994Z', duration_ms: 412, truncated: false, edited: false, origin: null },
};

describe('toSummary (bus flow.get)', () => {
  it('maps the summary fields and leaves what the bus does not send as null', () => {
    const s = toSummary({ id: 'f_2', kind: 'http', intercept: 'intercepted', is_replay: true, method: 'GET', scheme: 'https', authority: 'api.shop-staging.test', path: '/api/me', status: null }, 7);
    expect(s).toMatchObject({ id: 'f_2', seq: 7, method: 'GET', authority: 'api.shop-staging.test', path: '/api/me', status: null, intercept: 'paused', isReplay: true, origin: 'human' });
    expect(s.reqSize).toBeNull();
    expect(s.client.id).toBe('unknown');
    // Unknown TLS on an https flow is a tunnel, not decrypted (MITM): the core
    // did not report interception, so we must not claim it.
    expect(s.tls).toBe('tunnel');
  });

  it('labels an unknown-TLS https flow as a tunnel, and a decrypted one as mitm', () => {
    const base = { id: 'f_3', kind: 'http', intercept: 'observed', is_replay: false, method: 'GET', authority: 'h.test', path: '/' };
    // No tls field, no client_conn → unknown → tunnel (pinned/passthrough safe default).
    expect(toSummary({ ...base, scheme: 'https' }, 1).tls).toBe('tunnel');
    // A plain http flow is plain.
    expect(toSummary({ ...base, scheme: 'http' }, 2).tls).toBe('plain');
    // The core affirmatively reporting interception → mitm.
    expect(toSummary({ ...base, scheme: 'https', tls: 'mitm' }, 3).tls).toBe('mitm');
    expect(toSummary({ ...base, scheme: 'https', client_conn: { tls: true } }, 4).tls).toBe('mitm');
  });

  it('reads a websocket summary (handshake id, message count)', () => {
    const s = toSummary({ id: 'w_1', kind: 'websocket', intercept: 'observed', is_replay: false, handshake: 'f_9', messages: 6 }, 1);
    expect(s.kind).toBe('websocket');
    expect(s.status).toBe(101);
    expect(s.ws).toEqual({ up: 6, down: 0 });
  });
});

describe('toDetail (bus flow.detail)', () => {
  const d = toDetail(busDetail, 3);

  it('lifts request fields to the row and splits the query', () => {
    expect(d.method).toBe('POST');
    expect(d.authority).toBe('auth.shop-staging.test');
    expect(d.path).toBe('/api/auth/login');
    expect(d.query).toBe('next=%2F');
    expect(d.httpVersion).toBe('HTTP/2');
    expect(d.status).toBe(200);
    expect(d.intercept).toBe('none');
  });

  it('decodes base64 bodies to text when textual and keeps sizes', () => {
    expect(d.request.body.text).toBe('{"email":"ops@shop-staging.test"}');
    expect(d.request.body.size).toBe(33);
    expect(d.request.body.contentType).toBe('application/json');
    expect(d.response?.body.text).toBe('{"token":"t"}');
    expect(d.contentType).toBe('application/json; charset=utf-8');
    expect(d.reqSize).toBe(33);
    expect(d.resSize).toBe(13);
  });

  it('keeps binary bodies as base64', () => {
    const png = bytesToBase64(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0, 1, 2, 3]));
    const bin = toDetail({ ...busDetail, response: { ...busDetail.response, headers: [['content-type', 'image/png']], body: png, body_size: 8 } }, 1);
    expect(bin.response?.body.text).toBeNull();
    expect(bin.response?.body.base64).toBe(png);
  });

  it('reads headers as [name, value] pairs', () => {
    expect(d.request.headers).toEqual([
      { name: 'host', value: 'auth.shop-staging.test' },
      { name: 'content-type', value: 'application/json' },
    ]);
  });

  it('maps meta, client_conn and server_conn', () => {
    expect(d.mark).toBe('red');
    expect(d.comment).toBe('reflected');
    expect(d.durationMs).toBe(412);
    expect(d.startedAt).toBe(Date.parse('2026-10-27T11:05:22.994Z'));
    expect(d.client).toEqual({ id: 'unknown', name: '—', addr: '127.0.0.1:52114' });
    expect(d.tls).toBe('mitm');
    expect(d.conn).toMatchObject({ peer: '127.0.0.1:52114', sni: 'auth.shop-staging.test', alpn: 'h2', upstream: '93.184.216.34:443' });
  });

  it('reads websocket messages (direction, base64 text, timestamp)', () => {
    const ws = toDetail(
      {
        id: 'w_1',
        kind: 'websocket',
        intercept: 'observed',
        handshake: 'f_1',
        client_conn: busDetail.client_conn,
        meta: busDetail.meta,
        messages: [
          { dir: 'client_to_server', opcode: 'text', length: 9, injected: false, timestamp: '2026-10-27T11:05:30Z', data: b64('{"a":1}') },
          { dir: 'server_to_client', opcode: 'binary', length: 2, injected: true, timestamp: '2026-10-27T11:05:31Z', data: bytesToBase64(new Uint8Array([0xff, 0x00])) },
        ],
      },
      2,
    );
    expect(ws.wsMessages?.[0]).toMatchObject({ dir: 'up', opcode: 'text', text: '{"a":1}', size: 9, injected: false, at: Date.parse('2026-10-27T11:05:30Z') });
    expect(ws.wsMessages?.[1]).toMatchObject({ dir: 'down', opcode: 'binary', text: null, size: 2, injected: true });
    expect(ws.ws).toEqual({ up: 1, down: 1 });
  });

  it('still accepts the fixture (client-model) shape', () => {
    const fx = toDetail(
      { id: 'x', kind: 'http', method: 'GET', scheme: 'https', authority: 'h', path: '/p', query: 'q=1', status: 204, startedAt: 5, client: { id: 'curl', name: 'curl' }, intercept: 'none', request: { headers: [{ name: 'a', value: 'b' }], body: { text: 'hi', contentType: 'text/plain', size: 2, truncated: false } }, response: null },
      1,
    );
    expect(fx.request.body.text).toBe('hi');
    expect(fx.request.headers[0]).toEqual({ name: 'a', value: 'b' });
    expect(fx.client.name).toBe('curl');
  });
});

// The audit line the server pushes on `notifications/aitm/agent` and returns from `agent.activity`
// (crates/aitm-core/src/audit.rs): `at` epoch ms, `client_label`, `args` a redacted JSON string,
// `result` `"ok"` or `{error}`. The fixture bus sends the UI model directly.
describe('toAgentEntry (audit line)', () => {
  const wire = { at: 1730000000000, origin: 'mcp', client_label: 'claude-code', command: 'flow.replay', args: '{"id":"f_1"}', result: 'ok' };

  it('maps the server shape', () => {
    expect(toAgentEntry(wire)).toStrictEqual({
      at: '2024-10-27T03:33:20.000Z',
      origin: 'mcp',
      clientLabel: 'claude-code',
      command: 'flow.replay',
      args: { id: 'f_1' },
      result: 'ok',
    });
    // An unlabelled connection (the bridge today) keeps the explicit null, so own-ness can be inferred.
    expect(toAgentEntry({ ...wire, client_label: null })?.clientLabel).toBeNull();
  });

  it('maps an error result', () => {
    const e = toAgentEntry({ ...wire, result: { error: 'refused: x' } });
    expect(e?.result).toBe('error');
    expect(e?.detail).toBe('refused: x');
    // An already-model error (fixture bus) stays as it is.
    const model = toAgentEntry({ origin: 'cli', command: 'scope.add', result: 'error', detail: 'refused', at: '2024-10-27T03:33:20.000Z' });
    expect(model?.result).toBe('error');
    expect(model?.detail).toBe('refused');
  });

  it('keeps unparseable args as text', () => {
    expect(toAgentEntry({ ...wire, args: '{"id":"f_' })?.args).toBe('{"id":"f_');
    // A JSON scalar is not an args object either; the redacted text stays as text.
    expect(toAgentEntry({ ...wire, args: '"f_1"' })?.args).toBe('"f_1"');
  });

  it('accepts the fixture model', () => {
    const fx = { origin: 'web', command: 'flow.kill', args: { id: 'f_2' }, result: 'ok', at: '2024-10-27T03:33:20.000Z' };
    const e = toAgentEntry(fx);
    expect(e?.origin).toBe('web');
    expect(e?.args).toEqual({ id: 'f_2' });
    expect(e?.at).toBe('2024-10-27T03:33:20.000Z');
    expect(e?.command).toBe('flow.kill');
    expect(e?.result).toBe('ok');
  });

  it('rejects non-audit lines', () => {
    // The operator-role approval request rides the same notification but is not an audit entry.
    expect(toAgentEntry({ event: 'approval_requested', command: 'ca.install', args_summary: '{}', prompt: 'x', request_id: 'apr_1' })).toBeNull();
    expect(toAgentEntry({ origin: 'mcp', result: 'ok' })).toBeNull();
    expect(toAgentEntry({ ...wire, command: '' })).toBeNull();
    expect(toAgentEntry(null)).toBeNull();
    expect(toAgentEntry('flow.list')).toBeNull();
  });

  it('rejects an event line whatever else it carries', () => {
    // `event` alone marks it: even a line that also has an origin and a command is not an audit entry.
    expect(toAgentEntry({ ...wire, event: 'approval_requested' })).toBeNull();
    // A line that cannot be attributed to a frontend is not an entry either (it could not be filtered or labelled).
    expect(toAgentEntry({ at: wire.at, command: 'flow.replay', args: wire.args, result: 'ok' })).toBeNull();
  });

  it('survives hostile and oversized fields', () => {
    // A timestamp outside Date's range is not a time: the entry is still produced, stamped now.
    for (const at of [1e20, -1e20, Number.NaN, Number.POSITIVE_INFINITY, undefined, null, {}]) {
      const e = toAgentEntry({ ...wire, at });
      expect(e, String(at)).not.toBeNull();
      expect(Number.isFinite(Date.parse(e!.at)), String(at)).toBe(true);
    }
    // The server caps `args` at 512 bytes, so a long one is cut mid-JSON; a client must still survive far
    // more, and keeps no more than its own cap of it (see the cap cases below).
    const big = '{"x":"' + 'a'.repeat(1_000_000);
    expect(toAgentEntry({ ...wire, args: big })?.args).toBe(big.slice(0, 2048));
    // Nesting no parser will take stays text; a prototype key stays plain data.
    expect(toAgentEntry({ ...wire, args: '['.repeat(200_000) })?.args).toBe('['.repeat(2048));
    const proto = toAgentEntry({ ...wire, args: '{"__proto__":{"polluted":true}}' });
    expect(typeof proto?.args).toBe('object');
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
    // A result that is neither "ok" nor an error object is an error, with no reason to show.
    for (const result of [null, undefined, 'fine', 7, {}, { error: 5 }]) {
      const e = toAgentEntry({ ...wire, result });
      expect(e?.result, JSON.stringify(result)).toBe('error');
      expect(e?.detail, JSON.stringify(result)).toBeUndefined();
    }
  });

  // The 500-entry cap bounds how many lines the log keeps, not how big each is: `client_label` is a
  // self-declared `clientInfo.name` the server does not cap, and `args`/`error` are server text. Each
  // string the model keeps is cut to a fixed size; a line within the caps is untouched (the cases above).
  it('caps clientLabel at 128 chars', () => {
    expect(toAgentEntry({ ...wire, client_label: 'L'.repeat(128) })?.clientLabel).toBe('L'.repeat(128));
    expect(toAgentEntry({ ...wire, client_label: 'L'.repeat(129) })?.clientLabel).toBe('L'.repeat(128));
    expect(toAgentEntry({ ...wire, client_label: 'L'.repeat(10_000) })?.clientLabel).toBe('L'.repeat(128));
  });

  it('caps detail at 2048 chars', () => {
    expect(toAgentEntry({ ...wire, result: { error: 'e'.repeat(2048) } })?.detail).toBe('e'.repeat(2048));
    expect(toAgentEntry({ ...wire, result: { error: 'e'.repeat(2049) } })?.detail).toBe('e'.repeat(2048));
    // The model shape's `detail` is cut the same way.
    const model = toAgentEntry({ origin: 'cli', command: 'scope.add', result: 'error', detail: 'd'.repeat(5000), at: '2024-10-27T03:33:20.000Z' });
    expect(model?.detail).toBe('d'.repeat(2048));
  });

  it('caps a string args at 2048 chars before parsing it', () => {
    // Exactly at the cap: still parsed.
    const atCap = '{"id":"' + 'f'.repeat(2039) + '"}';
    expect(atCap).toHaveLength(2048);
    expect(toAgentEntry({ ...wire, args: atCap })?.args).toEqual({ id: 'f'.repeat(2039) });
    // One over: valid JSON on the wire, but the cut text (the closing brace is gone) no longer parses, so
    // it stays text, 2048 chars of it.
    const over = '{"id":"' + 'f'.repeat(2040) + '"}';
    expect(over).toHaveLength(2049);
    const cut = '{"id":"' + 'f'.repeat(2040) + '"';
    expect(cut).toHaveLength(2048);
    expect(toAgentEntry({ ...wire, args: over })?.args).toBe(cut);
    // A non-string args (the fixture model's object) is not text and is passed through.
    expect(toAgentEntry({ ...wire, args: { id: 'f_1' } })?.args).toEqual({ id: 'f_1' });
  });
});
