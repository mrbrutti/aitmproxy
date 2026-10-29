// The client-side flow model. A superset of what `flow.get` returns today (§4.3) and what
// `flow.detail` (F5) will add; fields the bus cannot fill yet are optional and render as a
// grey dash (§2.8: "missing as a grey dash").

export type FlowId = string;

export type FlowKind = 'http' | 'websocket';

/** Intercept lifecycle mirrors aitm-core's InterceptState. */
export type InterceptState = 'none' | 'paused' | 'resumed' | 'killed';

/** Who caused the flow: a proxied client, the human operator (compose/replay), or the agent over MCP. */
export type Origin = 'client' | 'human' | 'agent';

/** SSL column (§2.7): decrypted, tunnelled, pinned/failed, or plain HTTP. */
export type TlsState = 'mitm' | 'tunnel' | 'pinned' | 'plain';

/** Proxyman's 11 mark colours (§2.7). */
export type MarkColor =
  | 'red'
  | 'orange'
  | 'yellow'
  | 'green'
  | 'mint'
  | 'teal'
  | 'cyan'
  | 'blue'
  | 'indigo'
  | 'purple'
  | 'pink';

export interface Header {
  name: string;
  value: string;
}

export interface Body {
  /** Decoded text when the body is textual; null for binary (use `base64`). */
  text: string | null;
  /** Raw bytes, base64, for binary bodies (images, protobuf). */
  base64?: string;
  contentType: string | null;
  size: number;
  truncated: boolean;
}

export interface Client {
  /** Stable id for grouping (process name or `obscura`). */
  id: string;
  name: string;
  addr?: string;
}

/** One row of the flow list. */
export interface FlowSummary {
  id: FlowId;
  /** 1-based capture sequence; the `#` column. */
  seq: number;
  kind: FlowKind;
  method: string;
  scheme: 'http' | 'https' | 'ws' | 'wss';
  authority: string;
  path: string;
  query: string | null;
  status: number | null;
  statusText: string | null;
  /** ms since epoch */
  startedAt: number;
  durationMs: number | null;
  reqSize: number | null;
  resSize: number | null;
  client: Client;
  tls: TlsState;
  httpVersion: 'HTTP/1.1' | 'HTTP/2' | 'HTTP/3' | null;
  intercept: InterceptState;
  edited: boolean;
  isReplay: boolean;
  origin: Origin;
  inScope: boolean;
  contentType: string | null;
  mark: MarkColor | null;
  comment: string | null;
  /** WebSocket frame counts, when kind === 'websocket'. */
  ws?: { up: number; down: number };
  /** Transport-level failure text (DNS, connect, TLS) when there is no response. */
  error?: string | null;
}

export interface WsMessage {
  dir: 'up' | 'down';
  opcode: 'text' | 'binary' | 'ping' | 'pong' | 'close';
  at: number;
  text: string | null;
  base64?: string;
  size: number;
  injected: boolean;
}

export interface Timing {
  dnsMs?: number;
  connectMs?: number;
  tlsMs?: number;
  waitMs?: number;
  downloadMs?: number;
}

export interface ConnInfo {
  peer?: string;
  sni?: string;
  alpn?: string;
  tlsVersion?: string;
  cipher?: string;
  upstream?: string;
}

/** The inspector's view of a flow (`flow.detail`, F5). */
export interface FlowDetail extends FlowSummary {
  request: { headers: Header[]; body: Body };
  response: { headers: Header[]; body: Body } | null;
  conn: ConnInfo;
  timing: Timing | null;
  wsMessages?: WsMessage[];
  /** The original request before `flow.mutate`, when edited. */
  original?: { method: string; path: string; headers: Header[]; body: Body } | null;
}

// ---- derived helpers ------------------------------------------------------

export type MethodHue = 'get' | 'post' | 'put' | 'patch' | 'delete' | 'grey' | 'ws';

export function methodHue(flow: Pick<FlowSummary, 'method' | 'kind'>): MethodHue {
  if (flow.kind === 'websocket') return 'ws';
  switch (flow.method) {
    case 'GET':
      return 'get';
    case 'POST':
      return 'post';
    case 'PUT':
      return 'put';
    case 'PATCH':
      return 'patch';
    case 'DELETE':
      return 'delete';
    default:
      return 'grey';
  }
}

export type StatusHue =
  | 'informational'
  | 'success'
  | 'redirect'
  | 'client-error'
  | 'server-error'
  | 'pending'
  | 'killed'
  | 'paused';

export function statusHue(flow: Pick<FlowSummary, 'status' | 'intercept' | 'error'>): StatusHue {
  if (flow.intercept === 'killed') return 'killed';
  if (flow.intercept === 'paused') return 'paused';
  if (flow.error) return 'server-error';
  const s = flow.status;
  if (s == null) return 'pending';
  if (s < 200) return 'informational';
  if (s < 300) return 'success';
  if (s < 400) return 'redirect';
  if (s < 500) return 'client-error';
  return 'server-error';
}

export function flowUrl(flow: Pick<FlowSummary, 'scheme' | 'authority' | 'path' | 'query'>): string {
  return `${flow.scheme}://${flow.authority}${flow.path}${flow.query ? `?${flow.query}` : ''}`;
}

export function flowOrigin(flow: Pick<FlowSummary, 'scheme' | 'authority'>): string {
  return `${flow.scheme}://${flow.authority}`;
}

/** The chip bar's content-type families (§2.7). */
export type ContentFamily =
  | 'json'
  | 'form'
  | 'xml'
  | 'js'
  | 'css'
  | 'graphql'
  | 'document'
  | 'media'
  | 'other';

export function contentFamily(flow: Pick<FlowSummary, 'contentType' | 'path' | 'kind'>): ContentFamily {
  const ct = (flow.contentType ?? '').toLowerCase();
  if (ct.includes('graphql') || /\/graphql\b/.test(flow.path)) return 'graphql';
  if (ct.includes('json')) return 'json';
  if (ct.includes('x-www-form-urlencoded') || ct.includes('multipart/form-data')) return 'form';
  if (ct.includes('xml')) return 'xml';
  if (ct.includes('javascript') || ct.includes('ecmascript')) return 'js';
  if (ct.includes('text/css')) return 'css';
  if (ct.includes('text/html') || ct.includes('text/plain') || ct.includes('text/markdown')) return 'document';
  if (ct.startsWith('image/') || ct.startsWith('video/') || ct.startsWith('audio/') || ct.startsWith('font/'))
    return 'media';
  return 'other';
}

export const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE', 'QUERY'] as const;

export const MARK_COLORS: readonly MarkColor[] = [
  'red',
  'orange',
  'yellow',
  'green',
  'mint',
  'teal',
  'cyan',
  'blue',
  'indigo',
  'purple',
  'pink',
];
