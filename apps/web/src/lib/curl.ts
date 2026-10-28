// Copy as cURL (§3.3 "code generator / copy as cURL"), built client-side from a FlowDetail when
// headers are loaded, or from the FlowSummary alone (method + URL) when they are not.
import { flowUrl, type FlowDetail, type FlowSummary } from '~/model/flow';

/** POSIX single-quote escaping: `'` → `'\''`. */
export const shQuote = (s: string): string => `'${s.replace(/'/g, `'\\''`)}'`;

const SKIP = new Set(['host', 'content-length', 'connection', 'transfer-encoding', 'accept-encoding']);

const isDetail = (f: FlowSummary | FlowDetail): f is FlowDetail => 'request' in f && f.request != null;

export function toCurl(flow: FlowSummary | FlowDetail): string {
  const parts: string[] = ['curl'];
  const method = flow.kind === 'websocket' ? 'GET' : flow.method;
  const detail = isDetail(flow) ? flow : null;
  const body = detail?.request.body;
  const hasBody = !!body && (body.text != null ? body.text.length > 0 : !!body.base64);

  if (method !== 'GET' && !(method === 'POST' && hasBody)) parts.push(`-X ${method}`);
  if (method === 'POST' && hasBody) {
    /* --data implies POST */
  } else if (method === 'HEAD') {
    parts.length = 1;
    parts.push('-I');
  }
  if (flow.httpVersion === 'HTTP/2') parts.push('--http2');
  parts.push(shQuote(flowUrl(flow)));

  if (detail) {
    for (const h of detail.request.headers) {
      const name = h.name.toLowerCase();
      if (name.startsWith(':') || SKIP.has(name)) continue;
      parts.push(`-H ${shQuote(`${h.name}: ${h.value}`)}`);
    }
    if (hasBody && body) {
      if (body.text != null) parts.push(`--data-raw ${shQuote(body.text)}`);
      else if (body.base64) parts.push(`--data-binary @<(echo ${shQuote(body.base64)} | base64 -d)`);
    }
  }
  if (flow.kind === 'websocket') {
    parts.push(`-H ${shQuote('Connection: Upgrade')}`, `-H ${shQuote('Upgrade: websocket')}`);
  }
  return parts.join(' \\\n  ');
}
