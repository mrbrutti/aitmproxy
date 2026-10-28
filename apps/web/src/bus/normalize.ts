// Tolerant mapping from bus JSON (today's `flow.get` summary, F5's `flow.detail`, and the
// mock bus) to the client model. Anything the server does not send stays null.

import type { Body, FlowDetail, FlowSummary, Header, InterceptState, Origin, TlsState, WsMessage } from '~/model/flow';

type Rec = Record<string, unknown>;
const rec = (v: unknown): Rec => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Rec) : {});
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean => v === true;

function interceptOf(v: unknown): InterceptState {
  if (typeof v === 'string') {
    const s = v.toLowerCase();
    if (s.startsWith('intercept') || s === 'paused') return 'paused';
    if (s === 'resumed') return 'resumed';
    if (s === 'killed') return 'killed';
    return 'none';
  }
  const r = rec(v);
  const tag = str(r.state) ?? str(r.kind) ?? Object.keys(r)[0] ?? '';
  return interceptOf(tag);
}

function schemeOf(v: unknown, kind: string): FlowSummary['scheme'] {
  const s = (str(v) ?? '').toLowerCase();
  if (s === 'http' || s === 'https' || s === 'ws' || s === 'wss') return s;
  return kind === 'websocket' ? 'wss' : 'https';
}

function tlsOf(v: unknown, scheme: string): TlsState {
  const s = str(v);
  if (s === 'mitm' || s === 'tunnel' || s === 'pinned' || s === 'plain') return s;
  return scheme === 'http' || scheme === 'ws' ? 'plain' : 'mitm';
}

function originOf(v: unknown, isReplay: boolean): Origin {
  const s = str(v);
  if (s === 'agent' || s === 'mcp') return 'agent';
  if (s === 'human' || s === 'cli' || s === 'web' || s === 'mac' || s === 'tui') return 'human';
  return isReplay ? 'human' : 'client';
}

function splitPath(p: string): { path: string; query: string | null } {
  const i = p.indexOf('?');
  return i < 0 ? { path: p, query: null } : { path: p.slice(0, i), query: p.slice(i + 1) };
}

export function toSummary(raw: unknown, seqFallback: number): FlowSummary {
  const r = rec(raw);
  const kind = str(r.kind) === 'websocket' ? 'websocket' : 'http';
  const isReplay = bool(r.is_replay) || bool(r.isReplay);
  const scheme = schemeOf(r.scheme, kind);
  const rawPath = str(r.path) ?? '/';
  const { path, query } = r.query === undefined ? splitPath(rawPath) : { path: rawPath, query: str(r.query) };
  const client = rec(r.client);
  const ws = rec(r.ws);
  const messages = Array.isArray(r.messages) ? r.messages.length : null;
  const handshake = rec(r.handshake);
  const method = kind === 'websocket' ? 'GET' : (str(r.method) ?? 'GET').toUpperCase();
  const startedAt = num(r.started_at) ?? num(r.startedAt) ?? Date.now();
  const status = num(r.status) ?? (kind === 'websocket' && Object.keys(handshake).length ? 101 : null);
  return {
    id: String(r.id ?? ''),
    seq: num(r.seq) ?? seqFallback,
    kind,
    method,
    scheme,
    authority: str(r.authority) ?? str(handshake.authority) ?? '',
    path: path || str(handshake.path) || '/',
    query,
    status,
    statusText: str(r.status_text) ?? str(r.statusText),
    startedAt,
    durationMs: num(r.duration_ms) ?? num(r.durationMs),
    reqSize: num(r.req_size) ?? num(r.reqSize),
    resSize: num(r.res_size) ?? num(r.resSize),
    client: {
      id: str(client.id) ?? str(client.name) ?? 'unknown',
      name: str(client.name) ?? str(client.id) ?? '—',
      ...(str(client.addr) ? { addr: str(client.addr)! } : {}),
    },
    tls: tlsOf(r.tls, scheme),
    httpVersion: (str(r.http_version) ?? str(r.httpVersion)) as FlowSummary['httpVersion'],
    intercept: interceptOf(r.intercept),
    edited: bool(r.edited),
    isReplay,
    origin: originOf(r.origin, isReplay),
    inScope: r.in_scope === undefined && r.inScope === undefined ? true : bool(r.in_scope) || bool(r.inScope),
    contentType: str(r.content_type) ?? str(r.contentType),
    mark: (str(r.mark) as FlowSummary['mark']) ?? null,
    comment: str(r.comment),
    ...(kind === 'websocket'
      ? { ws: { up: num(ws.up) ?? messages ?? 0, down: num(ws.down) ?? 0 } }
      : {}),
    error: str(r.error),
  };
}

function headersOf(v: unknown): Header[] {
  if (Array.isArray(v)) {
    return v
      .map((h) => {
        if (Array.isArray(h)) return { name: String(h[0] ?? ''), value: String(h[1] ?? '') };
        const r = rec(h);
        return { name: String(r.name ?? ''), value: String(r.value ?? '') };
      })
      .filter((h) => h.name);
  }
  const r = rec(v);
  return Object.entries(r).map(([name, value]) => ({ name, value: String(value) }));
}

function bodyOf(v: unknown): Body {
  if (typeof v === 'string') return { text: v, contentType: null, size: v.length, truncated: false };
  const r = rec(v);
  const text = str(r.text);
  const base64 = str(r.base64) ?? str(r.bytes);
  return {
    text,
    ...(base64 ? { base64 } : {}),
    contentType: str(r.content_type) ?? str(r.contentType),
    size: num(r.size) ?? (text ? new TextEncoder().encode(text).length : base64 ? Math.floor((base64.length * 3) / 4) : 0),
    truncated: bool(r.truncated),
  };
}

export function toDetail(raw: unknown, seqFallback: number): FlowDetail {
  const r = rec(raw);
  const summary = toSummary(raw, seqFallback);
  const req = rec(r.request);
  const res = r.response == null ? null : rec(r.response);
  const original = r.original == null ? null : rec(r.original);
  const reqBody = bodyOf(req.body);
  if (!summary.reqSize) summary.reqSize = reqBody.size;
  const resBody = res ? bodyOf(res.body) : null;
  if (res && !summary.resSize && resBody) summary.resSize = resBody.size;
  if (!summary.contentType && resBody?.contentType) summary.contentType = resBody.contentType;
  return {
    ...summary,
    request: { headers: headersOf(req.headers), body: reqBody },
    response: res && resBody ? { headers: headersOf(res.headers), body: resBody } : null,
    conn: rec(r.conn) as FlowDetail['conn'],
    timing: r.timing ? (rec(r.timing) as FlowDetail['timing']) : null,
    ...(Array.isArray(r.ws_messages ?? r.wsMessages) ? { wsMessages: (r.ws_messages ?? r.wsMessages) as WsMessage[] } : {}),
    original: original
      ? {
          method: str(original.method) ?? summary.method,
          path: str(original.path) ?? summary.path,
          headers: headersOf(original.headers),
          body: bodyOf(original.body),
        }
      : null,
  };
}
