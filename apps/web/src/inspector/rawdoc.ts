// The Raw tab's document: `METHOD path HTTP/x`, header lines, a blank line, the body. While a
// request is paused it is serialised from the draft and parsed back on apply (§3.4 "raw-message
// edit of a paused request"); for any other flow it is built read-only from the detail, and the
// response gets the same shape behind a status line.

import type { Body, FlowDetail, Header } from '~/model/flow';

export interface RawRequest {
  method: string;
  /** Path including the query string. */
  path: string;
  version: string;
  headers: Header[];
  body: string;
}

export function serializeRaw(r: RawRequest): string {
  const head = [`${r.method} ${r.path} ${r.version}`, ...r.headers.map((h) => `${h.name}: ${h.value}`)];
  return `${head.join('\n')}\n\n${r.body}`;
}

/** What a captured body contributes to a read-only raw document: its text, or a note when the bytes are not text / not here. */
export function bodyLine(body: Body | null | undefined): string {
  if (!body || body.size === 0) return '';
  if (body.text != null) return body.text;
  return `[${body.size} bytes — binary body, see Body › Hex]`;
}

/** The read-only raw request of any flow: request line, headers, blank line, body. */
export function requestDocument(d: Pick<FlowDetail, 'method' | 'path' | 'query' | 'httpVersion' | 'request'>): string {
  return serializeRaw({
    method: d.method,
    path: d.path + (d.query ? `?${d.query}` : ''),
    version: d.httpVersion ?? 'HTTP/1.1',
    headers: d.request.headers,
    body: bodyLine(d.request.body),
  });
}

export interface RawResponse {
  version: string;
  status: number | null;
  statusText: string | null;
  headers: Header[];
  body: string;
}

/** `HTTP/x status reason`, headers, blank line, body. */
export function serializeRawResponse(r: RawResponse): string {
  const line = [r.version, r.status == null ? '' : String(r.status), r.statusText ?? ''].filter(Boolean).join(' ');
  const head = [line, ...r.headers.map((h) => `${h.name}: ${h.value}`)];
  return `${head.join('\n')}\n\n${r.body}`;
}

/** The read-only raw response of a flow, or null when it has none. */
export function responseDocument(d: Pick<FlowDetail, 'status' | 'statusText' | 'httpVersion' | 'response'>): string | null {
  if (!d.response) return null;
  return serializeRawResponse({
    version: d.httpVersion ?? 'HTTP/1.1',
    status: d.status,
    statusText: d.statusText,
    headers: d.response.headers,
    body: bodyLine(d.response.body),
  });
}

export type RawParse = { ok: true; value: RawRequest } | { ok: false; error: string; line: number };

const METHOD = /^[A-Za-z]+$/;

export function parseRaw(doc: string): RawParse {
  const text = doc.replace(/\r\n?/g, '\n');
  const lines = text.split('\n');
  const first = (lines[0] ?? '').trim();
  if (!first) return { ok: false, error: 'Line 1 must be the request line: METHOD /path HTTP/x', line: 1 };
  const parts = first.split(/\s+/);
  if (parts.length < 2 || parts.length > 3) return { ok: false, error: 'Request line needs METHOD, path and (optionally) version', line: 1 };
  const [m, path, version = 'HTTP/1.1'] = parts as [string, string, string?];
  if (!METHOD.test(m)) return { ok: false, error: `"${m}" is not a method`, line: 1 };
  if (!(path.startsWith('/') || path === '*' || /^[a-z][a-z0-9+.-]*:\/\//i.test(path))) return { ok: false, error: `Path must start with "/" (got "${path}")`, line: 1 };
  if (!/^HTTP\/\d(\.\d)?$/i.test(version)) return { ok: false, error: `"${version}" is not an HTTP version`, line: 1 };

  const headers: Header[] = [];
  let i = 1;
  for (; i < lines.length; i++) {
    const l = lines[i]!;
    if (l.trim() === '') break;
    const c = l.indexOf(':');
    if (c <= 0) return { ok: false, error: `Line ${i + 1}: expected "name: value"`, line: i + 1 };
    const name = l.slice(0, c).trim();
    if (/\s/.test(name)) return { ok: false, error: `Line ${i + 1}: header name "${name}" contains whitespace`, line: i + 1 };
    headers.push({ name, value: l.slice(c + 1).trim() });
  }
  const body = i < lines.length ? lines.slice(i + 1).join('\n') : '';
  return { ok: true, value: { method: m.toUpperCase(), path, version: version.toUpperCase(), headers, body } };
}
