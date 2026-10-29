// Formatters for the pretty view: JSON (sync, small bodies), form-urlencoded, multipart.
// JSON above SYNC_LIMIT goes through lib/json-worker.ts instead.

export function prettyJson(text: string): string | null {
  try {
    return JSON.stringify(JSON.parse(text), null, 2) ?? '';
  } catch {
    return null;
  }
}

export interface FormField {
  name: string;
  value: string;
  /** The field as it appeared on the wire. */
  raw: string;
}

function decode(s: string): string {
  try {
    return decodeURIComponent(s.replace(/\+/g, ' '));
  } catch {
    return s;
  }
}

export function parseForm(text: string): FormField[] {
  if (!text) return [];
  return text
    .split('&')
    .filter((p) => p.length)
    .map((raw) => {
      const i = raw.indexOf('=');
      return i < 0 ? { name: decode(raw), value: '', raw } : { name: decode(raw.slice(0, i)), value: decode(raw.slice(i + 1)), raw };
    });
}

/** `key = value` lines, one per field, decoded. */
export function formatForm(text: string): string {
  return parseForm(text)
    .map((f) => `${f.name} = ${f.value}`)
    .join('\n');
}

/** `a=1&b=2` (also used for the Query tab). Same parser; URL query strings share the grammar. */
export const parseQuery = parseForm;

export interface MultipartPart {
  headers: { name: string; value: string }[];
  name: string | null;
  filename: string | null;
  contentType: string | null;
  body: string;
}

export function parseMultipart(text: string, boundary: string): MultipartPart[] {
  const delim = `--${boundary}`;
  const parts: MultipartPart[] = [];
  const chunks = text.split(delim);
  for (let i = 1; i < chunks.length; i++) {
    let chunk = chunks[i]!;
    if (chunk.startsWith('--')) break; // closing delimiter
    chunk = chunk.replace(/^\r?\n/, '').replace(/\r?\n$/, '');
    const sep = chunk.search(/\r?\n\r?\n/);
    const headText = sep < 0 ? chunk : chunk.slice(0, sep);
    const body = sep < 0 ? '' : chunk.slice(sep).replace(/^\r?\n\r?\n/, '');
    const headers = headText
      .split(/\r?\n/)
      .filter(Boolean)
      .map((l) => {
        const j = l.indexOf(':');
        return j < 0 ? { name: l.trim(), value: '' } : { name: l.slice(0, j).trim().toLowerCase(), value: l.slice(j + 1).trim() };
      });
    const disp = headers.find((h) => h.name === 'content-disposition')?.value ?? '';
    const name = /\bname="([^"]*)"/.exec(disp)?.[1] ?? /\bname=([^;]+)/.exec(disp)?.[1] ?? null;
    const filename = /\bfilename="([^"]*)"/.exec(disp)?.[1] ?? null;
    const contentType = headers.find((h) => h.name === 'content-type')?.value ?? null;
    parts.push({ headers, name, filename, contentType, body });
  }
  return parts;
}

/** A readable rendering of a multipart body: one block per part with its disposition. */
export function formatMultipart(text: string, boundary: string): string {
  const parts = parseMultipart(text, boundary);
  if (!parts.length) return text;
  return parts
    .map((p, i) => {
      const title = [`part ${i + 1}`, p.name ? `name=${p.name}` : null, p.filename ? `filename=${p.filename}` : null, p.contentType ?? null]
        .filter(Boolean)
        .join(' · ');
      const body = p.filename && p.body.length > 2048 ? `[${p.body.length} bytes]` : p.body;
      return `── ${title}\n${body}`;
    })
    .join('\n\n');
}
