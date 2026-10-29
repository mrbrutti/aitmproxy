// Content sniffing for the body viewers: content-type first, then the bytes. Returns the
// viewer family and the language CodeMirror should use. No extra grammars in v1 (XML/HTML/JS/CSS
// render as plain text with line numbers; JSON is the one highlighted language).

import type { Body } from '~/model/flow';
import { base64ToBytes, looksBinary } from '~/lib/bytes';

export type BodyKind =
  | 'empty'
  | 'json'
  | 'form'
  | 'multipart'
  | 'xml'
  | 'html'
  | 'js'
  | 'css'
  | 'text'
  | 'image'
  | 'binary';

export interface Detection {
  kind: BodyKind;
  /** Lower-cased media type without parameters, e.g. `application/json`. */
  mime: string | null;
  /** Multipart boundary, when kind === 'multipart'. */
  boundary?: string;
  charset?: string;
}

const TEXT_MIMES = new Set(['application/x-www-form-urlencoded', 'application/javascript', 'text/javascript', 'application/ecmascript']);

export function parseContentType(ct: string | null | undefined): { mime: string | null; params: Record<string, string> } {
  if (!ct) return { mime: null, params: {} };
  const [m, ...rest] = ct.split(';');
  const params: Record<string, string> = {};
  for (const p of rest) {
    const i = p.indexOf('=');
    if (i < 0) continue;
    const k = p.slice(0, i).trim().toLowerCase();
    let v = p.slice(i + 1).trim();
    if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
    params[k] = v;
  }
  return { mime: (m ?? '').trim().toLowerCase() || null, params };
}

function kindFromMime(mime: string): BodyKind | null {
  if (mime === 'application/json' || mime.endsWith('+json') || mime === 'text/json') return 'json';
  if (mime === 'application/x-www-form-urlencoded') return 'form';
  if (mime.startsWith('multipart/')) return 'multipart';
  if (mime === 'text/html' || mime === 'application/xhtml+xml') return 'html';
  if (mime === 'application/xml' || mime === 'text/xml' || mime.endsWith('+xml')) return 'xml';
  if (mime === 'application/javascript' || mime === 'text/javascript' || mime === 'application/ecmascript') return 'js';
  if (mime === 'text/css') return 'css';
  if (mime.startsWith('image/') && mime !== 'image/svg+xml') return 'image';
  if (mime === 'image/svg+xml') return 'xml';
  if (mime.startsWith('text/')) return 'text';
  if (TEXT_MIMES.has(mime)) return 'text';
  if (mime === 'application/octet-stream' || mime.startsWith('audio/') || mime.startsWith('video/') || mime.startsWith('font/')) return 'binary';
  return null;
}

/** Sniffs text that arrived without a usable content-type. */
export function sniffText(text: string): BodyKind {
  const head = text.slice(0, 512).trimStart();
  if (!head) return 'empty';
  const c = head[0];
  if ((c === '{' || c === '[') && looksJson(text)) return 'json';
  if (/^--[^\r\n]+\r?\n/.test(head)) return 'multipart';
  if (head.startsWith('<?xml') || /^<[a-zA-Z][^>]*xmlns/.test(head)) return 'xml';
  if (/^<!doctype html/i.test(head) || /^<html[\s>]/i.test(head)) return 'html';
  if (/^<[a-zA-Z]/.test(head)) return 'xml';
  if (/^[\w%.+~-]+=[^&\s]*(&[\w%.+~-]+=[^&\s]*)*$/.test(head) && !text.includes('\n')) return 'form';
  return 'text';
}

function looksJson(text: string): boolean {
  // Cheap check for small inputs; large ones trust the leading bracket (the parser confirms later).
  if (text.length > 64 * 1024) return true;
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

export function detectBody(body: Body | null | undefined): Detection {
  if (!body) return { kind: 'empty', mime: null };
  const { mime, params } = parseContentType(body.contentType);
  const base: Detection = { kind: 'empty', mime, ...(params.charset ? { charset: params.charset } : {}) };
  if (body.size === 0 && !body.text && !body.base64) return base;
  if (body.text == null && !body.base64) return base;

  const byMime = mime ? kindFromMime(mime) : null;

  if (body.text == null) {
    // Binary payload: trust an image mime; otherwise peek at the bytes.
    if (byMime === 'image') return { ...base, kind: 'image' };
    if (byMime === 'binary' || !body.base64) return { ...base, kind: 'binary' };
    const bytes = base64ToBytes(body.base64.slice(0, 1024));
    if (looksBinary(bytes)) return { ...base, kind: 'binary' };
    return { ...base, kind: byMime ?? 'binary' };
  }

  if (body.text.length === 0) return base;

  if (byMime === 'multipart') {
    const boundary = params.boundary ?? sniffBoundary(body.text);
    return boundary ? { ...base, kind: 'multipart', boundary } : { ...base, kind: 'text' };
  }
  if (byMime === 'image' || byMime === 'binary') {
    // Text arrived for a "binary" type: the server lied or it is svg-like; show as text.
    return { ...base, kind: sniffText(body.text) };
  }
  if (byMime === 'json') return { ...base, kind: body.text.trimStart()[0] === '{' || body.text.trimStart()[0] === '[' ? 'json' : 'text' };
  if (byMime) return { ...base, kind: byMime };

  const sniffed = sniffText(body.text);
  if (sniffed === 'multipart') {
    const boundary = sniffBoundary(body.text);
    return boundary ? { ...base, kind: 'multipart', boundary } : { ...base, kind: 'text' };
  }
  return { ...base, kind: sniffed };
}

function sniffBoundary(text: string): string | undefined {
  const m = /^--([^\r\n]+)\r?\n/.exec(text);
  return m?.[1];
}

/** The label the format picker shows for an auto-detected kind. */
export function kindLabel(kind: BodyKind): string {
  switch (kind) {
    case 'json':
      return 'JSON';
    case 'form':
      return 'Form';
    case 'multipart':
      return 'Multipart';
    case 'xml':
      return 'XML';
    case 'html':
      return 'HTML';
    case 'js':
      return 'JS';
    case 'css':
      return 'CSS';
    case 'image':
      return 'Image';
    case 'binary':
      return 'Hex';
    case 'empty':
      return 'Empty';
    default:
      return 'Text';
  }
}
