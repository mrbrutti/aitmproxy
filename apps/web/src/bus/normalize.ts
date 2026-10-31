// Mapping from bus JSON to the client model. The authority is the landed `flow.get` /
// `flow.detail` (crates/aitm-plugins/src/{capture,detail,meta}.rs on the operator-commands
// branch): request/response nested, headers as [name, value] pairs, bodies as base64 `body`
// with `body_size`/`body_truncated`, `client_conn`/`server_conn`, `meta`, intercept as
// observed|intercepted|resumed|killed, WebSocket `messages`. The fixture bus and push
// notifications may send the client model directly; both are accepted. Missing stays null.

import { base64ToBytes } from '~/lib/bytes';
import type { AgentNotification } from '~/bus/types';
import type {
  Body,
  Client,
  ConnInfo,
  FlowDetail,
  FlowSummary,
  Header,
  InterceptState,
  Origin,
  TlsState,
  WsMessage,
} from '~/model/flow';

type Rec = Record<string, unknown>;
const rec = (v: unknown): Rec => (v && typeof v === 'object' && !Array.isArray(v) ? (v as Rec) : {});
const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean => v === true;
const first = <T,>(...vals: (T | null | undefined)[]): T | null => {
  for (const v of vals) if (v !== null && v !== undefined) return v;
  return null;
};

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
  return tag ? interceptOf(tag) : 'none';
}

function schemeOf(v: unknown, kind: string): FlowSummary['scheme'] {
  const s = (str(v) ?? '').toLowerCase();
  if (s === 'http' || s === 'https' || s === 'ws' || s === 'wss') return s;
  return kind === 'websocket' ? 'wss' : 'https';
}

function tlsOf(v: unknown, connTls: boolean | null, scheme: string): TlsState {
  const s = str(v);
  if (s === 'mitm' || s === 'tunnel' || s === 'pinned' || s === 'plain') return s;
  const plain = scheme === 'http' || scheme === 'ws';
  if (connTls === true) return 'mitm';
  if (connTls === false) return plain ? 'plain' : 'tunnel';
  // Unknown TLS: an https flow is a CONNECT tunnel until the core affirmatively
  // reports interception (`tls: 'mitm'` or `conn.tls: true`, both handled above).
  // Defaulting to 'mitm' here would mislabel a pinned/passed-through flow as decrypted.
  return plain ? 'plain' : 'tunnel';
}

function originOf(v: unknown, isReplay: boolean): Origin {
  const s = str(v);
  if (s === 'agent' || s === 'mcp') return 'agent';
  if (s === 'human' || s === 'cli' || s === 'web' || s === 'mac' || s === 'tui') return 'human';
  return isReplay ? 'human' : 'client';
}

/** `marks: [str]` (FlowMeta.marks); the UI shows the first. `mark` is the fixture shorthand. */
function markOf(r: Rec, meta: Rec): FlowSummary['mark'] {
  const marks = r.marks ?? meta.marks;
  if (Array.isArray(marks)) return (str(marks[0]) as FlowSummary['mark']) ?? null;
  return (str(r.mark) as FlowSummary['mark']) ?? null;
}

function timeOf(v: unknown): number | null {
  if (typeof v === 'number') return v;
  if (typeof v === 'string') {
    const t = Date.parse(v);
    return Number.isFinite(t) ? t : null;
  }
  return null;
}

function splitPath(p: string): { path: string; query: string | null } {
  const i = p.indexOf('?');
  return i < 0 ? { path: p, query: null } : { path: p.slice(0, i), query: p.slice(i + 1) };
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
  return Object.entries(rec(v)).map(([name, value]) => ({ name, value: String(value) }));
}

const headerValue = (headers: Header[], name: string): string | null =>
  headers.find((h) => h.name.toLowerCase() === name)?.value ?? null;

function clientOf(r: Rec): Client {
  const given = rec(r.client);
  if (Object.keys(given).length) {
    return {
      id: str(given.id) ?? str(given.name) ?? 'unknown',
      name: str(given.name) ?? str(given.id) ?? '—',
      ...(str(given.addr) ? { addr: str(given.addr)! } : {}),
    };
  }
  const conn = rec(r.client_conn);
  const process = str(conn.process);
  const peer = str(conn.peer);
  return { id: process ?? 'unknown', name: process ?? '—', ...(peer ? { addr: peer } : {}) };
}

const TEXTUAL = /^(text\/|application\/(json|xml|javascript|ecmascript|x-www-form-urlencoded|graphql|yaml|x-yaml|ld\+json|problem\+json)|multipart\/form-data|image\/svg)/i;

/** Decodes a base64 body to text when it is textual; keeps bytes otherwise. */
function bodyFromBase64(b64: string, contentType: string | null, size: number | null, truncated: boolean): Body {
  const bytes = base64ToBytes(b64);
  const ct = contentType ?? '';
  let text: string | null = null;
  if (TEXTUAL.test(ct) || !ct) {
    try {
      const decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      // Without a content type, only accept text free of control characters.
      // eslint-disable-next-line no-control-regex
      if (ct || !/[\x00-\x08\x0E-\x1F]/.test(decoded.slice(0, 4096))) text = decoded;
    } catch {
      text = null;
    }
  }
  return { text, ...(text == null ? { base64: b64 } : {}), contentType, size: size ?? bytes.length, truncated };
}

/** `body` is base64 (bus) or a model-shaped object (fixtures); `body_size`/`body_truncated` ride beside it. */
function bodyOf(msg: Rec, contentType: string | null): Body {
  const size = num(msg.body_size) ?? num(msg.bodySize);
  const truncated = bool(msg.body_truncated) || bool(msg.bodyTruncated);
  const v = msg.body;
  if (typeof v === 'string') return bodyFromBase64(v, contentType, size, truncated);
  if (v && typeof v === 'object') {
    const r = rec(v);
    const text = str(r.text);
    const base64 = str(r.base64) ?? str(r.bytes);
    return {
      text,
      ...(base64 ? { base64 } : {}),
      contentType: str(r.content_type) ?? str(r.contentType) ?? contentType,
      size: num(r.size) ?? size ?? (text ? new TextEncoder().encode(text).length : base64 ? Math.floor((base64.length * 3) / 4) : 0),
      truncated: bool(r.truncated) || truncated,
    };
  }
  return { text: null, contentType, size: size ?? 0, truncated };
}

function wsMessagesOf(v: unknown): WsMessage[] | null {
  if (!Array.isArray(v)) return null;
  return v.map((m) => {
    const r = rec(m);
    const dirRaw = str(r.dir) ?? 'up';
    const dir: WsMessage['dir'] = dirRaw === 'down' || dirRaw === 'server_to_client' || dirRaw === 's2c' ? 'down' : 'up';
    const opcode = (str(r.opcode) ?? 'text') as WsMessage['opcode'];
    const b64 = str(r.data) ?? str(r.base64);
    let text = str(r.text) ?? str(r.data_text);
    if (text == null && b64 && opcode === 'text') {
      try {
        text = new TextDecoder('utf-8', { fatal: true }).decode(base64ToBytes(b64));
      } catch {
        text = null;
      }
    }
    return {
      dir,
      opcode,
      at: timeOf(r.at ?? r.timestamp ?? r.time) ?? 0,
      text,
      ...(b64 && text == null ? { base64: b64 } : {}),
      size: num(r.size) ?? num(r.length) ?? (text ? text.length : 0),
      injected: bool(r.injected),
    };
  });
}

export function toSummary(raw: unknown, seqFallback: number): FlowSummary {
  const r = rec(raw);
  const req = rec(r.request);
  const res = r.response == null ? {} : rec(r.response);
  const meta = rec(r.meta);
  const conn = rec(r.client_conn);
  const kind = str(r.kind) === 'websocket' ? 'websocket' : 'http';
  const isReplay = bool(r.is_replay) || bool(r.isReplay) || bool(meta.is_replay);
  const scheme = schemeOf(first(r.scheme, req.scheme), kind);
  const rawPath = first(str(r.path), str(req.path)) ?? '/';
  const { path, query } = r.query === undefined ? splitPath(rawPath) : { path: rawPath, query: str(r.query) };
  const messages = Array.isArray(r.messages) ? r.messages.length : num(r.messages);
  const handshake = rec(r.handshake);
  const method = kind === 'websocket' ? 'GET' : (first(str(r.method), str(req.method)) ?? 'GET').toUpperCase();
  const startedAt = first(num(r.started_at), num(r.startedAt), timeOf(meta.created), timeOf(conn.established)) ?? Date.now();
  const status = first(num(r.status), num(res.status)) ?? (kind === 'websocket' && (Object.keys(handshake).length || str(r.handshake)) ? 101 : null);
  const resHeaders = headersOf(res.headers);
  const contentType = first(str(r.content_type), str(r.contentType), headerValue(resHeaders, 'content-type'));
  const inScopeGiven = r.in_scope ?? r.inScope;
  return {
    id: String(r.id ?? ''),
    seq: num(r.seq) ?? seqFallback,
    kind,
    method,
    scheme,
    authority: first(str(r.authority), str(req.authority), str(handshake.authority)) ?? '',
    path: path || str(handshake.path) || '/',
    query,
    status,
    statusText: first(str(r.status_text), str(r.statusText), str(res.reason)),
    startedAt,
    durationMs: first(num(r.duration_ms), num(r.durationMs), num(meta.duration_ms)),
    reqSize: first(num(r.req_size), num(r.reqSize), num(req.body_size)),
    resSize: first(num(r.res_size), num(r.resSize), num(res.body_size)),
    client: clientOf(r),
    tls: tlsOf(r.tls, typeof conn.tls === 'boolean' ? conn.tls : null, scheme),
    httpVersion: first(str(r.http_version), str(r.httpVersion), str(req.version)) as FlowSummary['httpVersion'],
    intercept: interceptOf(r.intercept),
    edited: bool(r.edited) || bool(meta.edited),
    isReplay,
    origin: originOf(r.origin ?? meta.origin, isReplay),
    inScope: inScopeGiven === undefined ? true : bool(inScopeGiven),
    contentType,
    mark: markOf(r, meta),
    comment: first(str(r.comment), str(meta.comment)),
    ...(kind === 'websocket' ? { ws: { up: num(rec(r.ws).up) ?? messages ?? 0, down: num(rec(r.ws).down) ?? 0 } } : {}),
    error: first(str(r.error), str(meta.error)),
  };
}

function connOf(client: Rec, server: Rec, given: Rec): ConnInfo {
  if (Object.keys(given).length) return given as ConnInfo;
  const out: ConnInfo = {};
  const peer = str(client.peer);
  const sni = str(client.sni) ?? str(server.sni);
  const alpn = str(client.alpn) ?? str(server.alpn);
  const upstream = str(server.peer);
  if (peer) out.peer = peer;
  if (sni) out.sni = sni;
  if (alpn) out.alpn = alpn;
  if (upstream) out.upstream = upstream;
  // The bus reports only whether TLS was used, not the version; say nothing for plain.
  if (client.tls === true) out.tlsVersion = 'TLS';
  return out;
}

export function toDetail(raw: unknown, seqFallback: number): FlowDetail {
  const r = rec(raw);
  const summary = toSummary(raw, seqFallback);
  const req = rec(r.request);
  const res = r.response == null ? null : rec(r.response);
  const original = r.original == null ? null : rec(r.original);
  const reqHeaders = headersOf(req.headers);
  const reqBody = bodyOf(req, headerValue(reqHeaders, 'content-type'));
  if (!summary.reqSize) summary.reqSize = reqBody.size;
  const resHeaders = res ? headersOf(res.headers) : [];
  const resBody = res ? bodyOf(res, headerValue(resHeaders, 'content-type')) : null;
  if (res && !summary.resSize && resBody) summary.resSize = resBody.size;
  if (!summary.contentType && resBody?.contentType) summary.contentType = resBody.contentType;
  const wsMessages = wsMessagesOf(r.ws_messages ?? r.wsMessages ?? (Array.isArray(r.messages) ? r.messages : null));
  if (wsMessages && summary.kind === 'websocket') {
    summary.ws = { up: wsMessages.filter((m) => m.dir === 'up').length, down: wsMessages.filter((m) => m.dir === 'down').length };
  }
  return {
    ...summary,
    request: { headers: reqHeaders, body: reqBody },
    response: res && resBody ? { headers: resHeaders, body: resBody } : null,
    conn: connOf(rec(r.client_conn), rec(r.server_conn), rec(r.conn)),
    timing: r.timing ? (rec(r.timing) as FlowDetail['timing']) : null,
    ...(wsMessages ? { wsMessages } : {}),
    original: original
      ? {
          method: str(original.method) ?? summary.method,
          path: str(original.path) ?? summary.path,
          headers: headersOf(original.headers),
          body: bodyOf(original, headerValue(headersOf(original.headers), 'content-type')),
        }
      : null,
  };
}

/** Epoch ms (the server) or an ISO string (the fixture bus) to ISO; anything else is now. */
function isoOf(v: unknown): string {
  const n = num(v);
  if (n !== null) {
    try {
      return new Date(n).toISOString();
    } catch {
      // Out of Date's range: not a timestamp we can show.
    }
  }
  return str(v) ?? new Date().toISOString();
}

/** The audit `args` is redacted JSON text; an object or array is shown structured, anything else as the text it is. */
function argsOf(v: unknown): unknown {
  if (typeof v !== 'string') return v;
  try {
    const parsed: unknown = JSON.parse(v);
    return parsed !== null && typeof parsed === 'object' ? parsed : v;
  } catch {
    return v;
  }
}

/**
 * One audit line (`notifications/aitm/agent`, `agent.activity`) to the Activity model. Accepts the
 * server's wire shape (crates/aitm-core/src/audit.rs) and the fixture bus's model shape alike.
 * Returns null for what is not an audit entry: an `approval_requested` line (it carries `event`)
 * or a line without a command.
 */
export function toAgentEntry(raw: unknown): AgentNotification | null {
  const r = rec(raw);
  if (r.event !== undefined) return null;
  const command = str(r.command);
  const origin = str(r.origin);
  if (!command || !origin) return null;
  const detail = str(rec(r.result).error) ?? str(r.detail);
  const out: AgentNotification = {
    origin: origin as AgentNotification['origin'],
    command,
    result: r.result === 'ok' ? 'ok' : 'error',
    at: isoOf(r.at),
  };
  if ('client_label' in r || 'clientLabel' in r) out.clientLabel = str(r.client_label ?? r.clientLabel);
  if (r.args !== undefined) out.args = argsOf(r.args);
  if (detail !== null) out.detail = detail;
  return out;
}
