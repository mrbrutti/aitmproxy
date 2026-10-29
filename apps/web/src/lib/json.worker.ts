// Web Worker: JSON parse + pretty-print off the main thread (the 5 MB body bar, §2.10(b)).
// Protocol: { id, op: 'pretty' | 'value', key, text? } → { id, ok, text?, value?, ms, error? }.
// Parsed values are cached per key (small LRU) so a 'value' request after a 'pretty' is free.

export interface JsonWorkerRequest {
  id: number;
  op: 'pretty' | 'value';
  key: string;
  text?: string;
}

export interface JsonWorkerResponse {
  id: number;
  ok: boolean;
  text?: string;
  value?: unknown;
  ms: number;
  error?: string;
}

const CACHE_MAX = 4;
const cache = new Map<string, unknown>();

function remember(key: string, value: unknown) {
  if (cache.has(key)) cache.delete(key);
  cache.set(key, value);
  if (cache.size > CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
}

export function handle(req: JsonWorkerRequest): JsonWorkerResponse {
  const t0 = performance.now();
  try {
    let value: unknown;
    if (cache.has(req.key)) value = cache.get(req.key);
    else {
      if (typeof req.text !== 'string') throw new Error('no text for uncached key');
      value = JSON.parse(req.text);
      remember(req.key, value);
    }
    if (req.op === 'pretty') {
      const text = JSON.stringify(value, null, 2) ?? '';
      return { id: req.id, ok: true, text, ms: performance.now() - t0 };
    }
    return { id: req.id, ok: true, value, ms: performance.now() - t0 };
  } catch (e) {
    return { id: req.id, ok: false, ms: performance.now() - t0, error: (e as Error).message };
  }
}

// `self` is the worker scope in production; the module is also imported by the inline fallback
// and by tests, where there is no `onmessage` to install.
const scope = globalThis as unknown as { onmessage?: unknown; postMessage?: (v: unknown) => void; document?: unknown };
if (typeof scope.postMessage === 'function' && typeof scope.document === 'undefined') {
  scope.onmessage = (ev: MessageEvent<JsonWorkerRequest>) => {
    scope.postMessage!(handle(ev.data));
  };
}
