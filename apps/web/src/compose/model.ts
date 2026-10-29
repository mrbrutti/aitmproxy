// Compose sheet model (§2.7 "Compose / repeat", §4.6): the draft, header/query round-trips,
// body encoders, templates, the scope pre-check and the send history. Pure; the sheet renders it.

import type { FlowDetail, Header } from '~/model/flow';
import type { ParsedCurl } from '~/lib/curl-parse';

export interface KV {
  name: string;
  value: string;
}

export interface FilePart {
  name: string;
  type: string;
  size: number;
  base64: string;
}

export interface MultipartRow extends KV {
  file: FilePart | null;
}

export type BodyMode = 'raw' | 'json' | 'form' | 'multipart';
export const BODY_MODES: readonly { id: BodyMode; label: string }[] = [
  { id: 'raw', label: 'Raw' },
  { id: 'json', label: 'JSON' },
  { id: 'form', label: 'Form' },
  { id: 'multipart', label: 'Multipart' },
];

export interface Draft {
  method: string;
  url: string;
  headers: KV[];
  bodyMode: BodyMode;
  /** Raw and JSON share this text. */
  raw: string;
  form: KV[];
  multipart: MultipartRow[];
}

export const emptyDraft = (): Draft => ({ method: 'GET', url: '', headers: [], bodyMode: 'raw', raw: '', form: [], multipart: [] });

// ---- headers ----------------------------------------------------------------

export const isBlankKV = (kv: KV): boolean => kv.name.trim() === '' && kv.value.trim() === '';
export const compactKV = <T extends KV>(rows: T[]): T[] => rows.filter((r) => !isBlankKV(r));

/** `name: value` per line → rows. Lines without a colon keep the text as the name. */
export function parseHeaderLines(text: string): KV[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const colon = line.indexOf(':');
      if (colon < 0) return { name: line, value: '' };
      return { name: line.slice(0, colon).trim(), value: line.slice(colon + 1).trim() };
    });
}

export const formatHeaderLines = (rows: KV[]): string =>
  compactKV(rows)
    .map((r) => (r.value ? `${r.name}: ${r.value}` : `${r.name}:`))
    .join('\n');

// ---- query ↔ URL ---------------------------------------------------------------

const safeDecode = (s: string): string => {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
};
const encode = (s: string): string => encodeURIComponent(s).replace(/%3A/gi, ':').replace(/%2F/gi, '/').replace(/%40/gi, '@').replace(/%2C/gi, ',');

/** Query rows of a URL (or of a bare `?a=b` string). */
export function parseQuery(url: string): KV[] {
  const q = url.indexOf('?');
  if (q < 0) return [];
  let s = url.slice(q + 1);
  const hash = s.indexOf('#');
  if (hash >= 0) s = s.slice(0, hash);
  if (!s) return [];
  return s.split('&').map((pair) => {
    const eq = pair.indexOf('=');
    return eq < 0 ? { name: safeDecode(pair), value: '' } : { name: safeDecode(pair.slice(0, eq)), value: safeDecode(pair.slice(eq + 1)) };
  });
}

/** Rebuild the URL's query from rows, keeping everything else (and the fragment). */
export function applyQuery(url: string, rows: KV[]): string {
  let base = url;
  let fragment = '';
  const hash = base.indexOf('#');
  if (hash >= 0) {
    fragment = base.slice(hash);
    base = base.slice(0, hash);
  }
  const q = base.indexOf('?');
  if (q >= 0) base = base.slice(0, q);
  const kept = rows.filter((r) => r.name.trim() !== '');
  const qs = kept.map((r) => (r.value === '' ? encode(r.name) : `${encode(r.name)}=${encode(r.value)}`)).join('&');
  return qs ? `${base}?${qs}${fragment}` : `${base}${fragment}`;
}

// ---- scope pre-check (§4.6) ---------------------------------------------------------

export interface ScopeCheck {
  /** null when the URL does not parse. */
  host: string | null;
  inScope: boolean;
}

const DEFAULT_PORT: Record<string, string> = { 'http:': '80', 'https:': '443', 'ws:': '80', 'wss:': '443' };

export function parseTarget(url: string): URL | null {
  const s = url.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return null;
  try {
    const u = new URL(s);
    return u.hostname ? u : null;
  } catch {
    return null;
  }
}

/** True when `entry` (host, host:port or *.wildcard) authorises `u`. Wildcards match subdomains. */
export function scopeEntryMatches(entry: string, u: URL): boolean {
  const e = entry.trim().toLowerCase();
  if (!e) return false;
  const hostname = u.hostname.toLowerCase();
  const port = u.port || DEFAULT_PORT[u.protocol] || '';
  if (e.startsWith('*.')) return hostname.endsWith(e.slice(1)) && hostname.length > e.length - 1;
  const colon = e.lastIndexOf(':');
  if (colon > 0 && !e.includes(']') && /^\d+$/.test(e.slice(colon + 1))) {
    return e.slice(0, colon) === hostname && e.slice(colon + 1) === port;
  }
  return e === hostname;
}

export function scopeCheck(url: string, scope: readonly { host: string }[]): ScopeCheck {
  const u = parseTarget(url);
  if (!u) return { host: null, inScope: false };
  return { host: u.hostname, inScope: scope.some((s) => scopeEntryMatches(s.host, u)) };
}

// ---- body -----------------------------------------------------------------------------

export const encodeForm = (rows: KV[]): string =>
  compactKV(rows)
    .map((r) => `${encodeURIComponent(r.name)}=${encodeURIComponent(r.value)}`)
    .join('&');

export const newBoundary = (): string => `----aitm${Math.random().toString(36).slice(2, 14)}${Date.now().toString(36)}`;

/** multipart/form-data as text; file parts carry their bytes base64 with a transfer-encoding header. */
export function buildMultipart(rows: MultipartRow[], boundary: string): string {
  const parts = rows.filter((r) => r.name.trim() !== '' || r.file);
  let out = '';
  for (const r of parts) {
    const name = r.name.replace(/"/g, '%22');
    if (r.file) {
      out += `--${boundary}\r\nContent-Disposition: form-data; name="${name}"; filename="${r.file.name.replace(/"/g, '%22')}"\r\n`;
      out += `Content-Type: ${r.file.type || 'application/octet-stream'}\r\nContent-Transfer-Encoding: base64\r\n\r\n${r.file.base64}\r\n`;
    } else {
      out += `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${r.value}\r\n`;
    }
  }
  return out + `--${boundary}--\r\n`;
}

export function contentTypeFor(mode: BodyMode, boundary: string): string | null {
  switch (mode) {
    case 'json':
      return 'application/json';
    case 'form':
      return 'application/x-www-form-urlencoded';
    case 'multipart':
      return `multipart/form-data; boundary=${boundary}`;
    default:
      return null;
  }
}

export function buildBody(d: Draft, boundary: string): string {
  switch (d.bodyMode) {
    case 'form':
      return encodeForm(d.form);
    case 'multipart':
      return buildMultipart(d.multipart, boundary);
    default:
      return d.raw;
  }
}

export const hasBody = (d: Draft): boolean =>
  d.bodyMode === 'form' ? compactKV(d.form).length > 0 : d.bodyMode === 'multipart' ? d.multipart.some((r) => r.name.trim() || r.file) : d.raw.length > 0;

/** JSON body check: null when valid or empty, else a short message. */
export function jsonProblem(text: string): string | null {
  if (!text.trim()) return null;
  try {
    JSON.parse(text);
    return null;
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    const lc = /line (\d+) column (\d+)/.exec(msg);
    const pos = /position (\d+)/.exec(msg);
    if (lc) return `Invalid JSON at line ${lc[1]}, column ${lc[2]}`;
    if (pos) return `Invalid JSON at offset ${pos[1]}`;
    return 'Invalid JSON';
  }
}

export const userHeader = (d: Draft, name: string): KV | undefined => d.headers.find((h) => h.name.trim().toLowerCase() === name);

/** The content-type the sheet adds itself, or null when the user set one or the body has none. */
export function autoContentType(d: Draft, boundary: string): string | null {
  if (userHeader(d, 'content-type')) return null;
  if (!hasBody(d)) return null;
  return contentTypeFor(d.bodyMode, boundary);
}

/** Headers as sent: user rows (compacted) plus the automatic content-type. */
export function effectiveHeaders(d: Draft, boundary: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const h of compactKV(d.headers)) if (h.name.trim()) out[h.name.trim()] = h.value;
  const auto = autoContentType(d, boundary);
  if (auto) out['Content-Type'] = auto;
  return out;
}

// ---- templates ---------------------------------------------------------------------------

export type TemplateId = 'empty' | 'get' | 'post-json' | 'post-form' | 'multipart' | 'websocket';
export const TEMPLATES: readonly { id: TemplateId; label: string; disabled?: boolean; title?: string }[] = [
  { id: 'empty', label: 'Empty' },
  { id: 'get', label: 'GET' },
  { id: 'post-json', label: 'POST JSON' },
  { id: 'post-form', label: 'POST Form' },
  { id: 'multipart', label: 'Multipart' },
  { id: 'websocket', label: 'WebSocket', disabled: true, title: 'Needs F9 (WebSocket compose on the bus)' },
];

export function templateDraft(id: TemplateId, keepUrl = ''): Draft {
  const d = emptyDraft();
  d.url = keepUrl;
  switch (id) {
    case 'get':
      d.headers = [{ name: 'Accept', value: '*/*' }];
      break;
    case 'post-json':
      d.method = 'POST';
      d.bodyMode = 'json';
      d.raw = '{\n  \n}';
      d.headers = [{ name: 'Accept', value: 'application/json' }];
      break;
    case 'post-form':
      d.method = 'POST';
      d.bodyMode = 'form';
      d.form = [{ name: '', value: '' }];
      break;
    case 'multipart':
      d.method = 'POST';
      d.bodyMode = 'multipart';
      d.multipart = [{ name: '', value: '', file: null }];
      break;
    default:
      break;
  }
  return d;
}

// ---- prefill -----------------------------------------------------------------------------------

const HOP = new Set(['host', 'content-length', 'connection', 'transfer-encoding', ':authority', ':method', ':path', ':scheme']);

function guessMode(contentType: string | null, text: string): BodyMode {
  const ct = (contentType ?? '').toLowerCase();
  if (ct.includes('json')) return 'json';
  if (ct.includes('x-www-form-urlencoded')) return 'form';
  if (!ct && text.trim().startsWith('{')) return 'json';
  return 'raw';
}

const decodeForm = (text: string): KV[] =>
  text
    .split('&')
    .filter(Boolean)
    .map((p) => {
      const eq = p.indexOf('=');
      return eq < 0 ? { name: safeDecode(p), value: '' } : { name: safeDecode(p.slice(0, eq)), value: safeDecode(p.slice(eq + 1)) };
    });

export function detailToDraft(detail: FlowDetail): Draft {
  const d = emptyDraft();
  d.method = detail.kind === 'websocket' ? 'GET' : detail.method;
  d.url = `${detail.scheme}://${detail.authority}${detail.path}${detail.query ? `?${detail.query}` : ''}`;
  d.headers = detail.request.headers.filter((h) => !HOP.has(h.name.toLowerCase())).map((h) => ({ name: h.name, value: h.value }));
  const body = detail.request.body;
  const text = body.text ?? '';
  d.bodyMode = guessMode(body.contentType ?? d.headers.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? null, text);
  if (d.bodyMode === 'form') d.form = decodeForm(text);
  else d.raw = text;
  if (d.bodyMode === 'json' && jsonProblem(text)) d.bodyMode = 'raw';
  return d;
}

export function curlToDraft(p: ParsedCurl): Draft {
  const d = emptyDraft();
  d.method = p.method;
  d.url = p.url;
  d.headers = p.headers.filter((h: Header) => !HOP.has(h.name.toLowerCase())).map((h) => ({ name: h.name, value: h.value }));
  const text = p.body ?? '';
  d.bodyMode = guessMode(d.headers.find((h) => h.name.toLowerCase() === 'content-type')?.value ?? null, text);
  if (d.bodyMode === 'form') d.form = decodeForm(text);
  else d.raw = text;
  if (d.bodyMode === 'json' && jsonProblem(text)) d.bodyMode = 'raw';
  return d;
}

// ---- history ------------------------------------------------------------------------------------

export const HISTORY_KEY = 'aitm.compose.history';
export const HISTORY_MAX = 20;

export interface HistoryEntry {
  at: number;
  draft: Draft;
}

export function readHistory(storage: Pick<Storage, 'getItem'> | null = typeof localStorage === 'undefined' ? null : localStorage): HistoryEntry[] {
  try {
    const raw = storage?.getItem(HISTORY_KEY);
    const list = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(list) ? (list as HistoryEntry[]).filter((e) => e && typeof e.at === 'number' && e.draft && typeof e.draft.url === 'string') : [];
  } catch {
    return [];
  }
}

/** Newest first; dedupes on method+URL; files are not kept. */
export function pushHistory(draft: Draft, storage: Pick<Storage, 'getItem' | 'setItem'> | null = typeof localStorage === 'undefined' ? null : localStorage, now = Date.now()): HistoryEntry[] {
  const slim: Draft = { ...draft, headers: compactKV(draft.headers), form: compactKV(draft.form), multipart: draft.multipart.filter((r) => r.name.trim()).map((r) => ({ name: r.name, value: r.value, file: null })) };
  const prev = readHistory(storage).filter((e) => !(e.draft.method === slim.method && e.draft.url === slim.url));
  const next = [{ at: now, draft: slim }, ...prev].slice(0, HISTORY_MAX);
  try {
    storage?.setItem(HISTORY_KEY, JSON.stringify(next));
  } catch {
    /* private mode */
  }
  return next;
}
