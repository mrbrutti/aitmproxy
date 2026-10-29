// Main-thread client for json.worker.ts. One worker per page, lazily created; falls back to an
// inline call where Workers do not exist (vitest/jsdom). Results are cached per key on this side
// too, so re-opening a tab never re-parses.

import type { JsonWorkerRequest, JsonWorkerResponse } from './json.worker';

export interface JsonResult<T> {
  value: T;
  /** Time the worker spent (parse + stringify), not including transfer. */
  workerMs: number;
  /** Wall time from request to resolution on the main thread. */
  totalMs: number;
  fromCache: boolean;
}

/** Bodies at or below this size are pretty-printed synchronously; above it, in the worker. */
export const SYNC_LIMIT = 256 * 1024;
/** Above this size only the raw text is shown (§3.3 "large bodies paged" is a later step). */
export const PRETTY_CAP = 20 * 1024 * 1024;

const prettyCache = new Map<string, string>();
const valueCache = new Map<string, unknown>();
const CACHE_MAX = 6;

function put<T>(map: Map<string, T>, key: string, v: T) {
  if (map.has(key)) map.delete(key);
  map.set(key, v);
  if (map.size > CACHE_MAX) {
    const oldest = map.keys().next().value;
    if (oldest !== undefined) map.delete(oldest);
  }
}

let worker: Worker | null | undefined;
let nextId = 1;
const pending = new Map<number, { resolve: (r: JsonWorkerResponse) => void }>();

function getWorker(): Worker | null {
  if (worker !== undefined) return worker;
  try {
    if (typeof Worker === 'undefined') {
      worker = null;
      return null;
    }
    worker = new Worker(new URL('./json.worker.ts', import.meta.url), { type: 'module' });
    worker.onmessage = (ev: MessageEvent<JsonWorkerResponse>) => {
      const p = pending.get(ev.data.id);
      if (p) {
        pending.delete(ev.data.id);
        p.resolve(ev.data);
      }
    };
    worker.onerror = () => {
      // A failed worker load: answer everything inline from now on.
      for (const [id, p] of pending) p.resolve({ id, ok: false, ms: 0, error: 'worker failed' });
      pending.clear();
      worker = null;
    };
  } catch {
    worker = null;
  }
  return worker;
}

async function send(req: JsonWorkerRequest): Promise<JsonWorkerResponse> {
  const w = getWorker();
  if (!w) {
    const { handle } = await import('./json.worker');
    return handle(req);
  }
  return new Promise((resolve) => {
    pending.set(req.id, { resolve });
    w.postMessage(req);
  });
}

/** Pretty-prints JSON text (2-space indent). Rejects with the parse error message. */
export async function prettyJsonAsync(key: string, text: string): Promise<JsonResult<string>> {
  const t0 = performance.now();
  const hit = prettyCache.get(key);
  if (hit !== undefined) return { value: hit, workerMs: 0, totalMs: performance.now() - t0, fromCache: true };
  const r = await send({ id: nextId++, op: 'pretty', key, text });
  if (!r.ok || typeof r.text !== 'string') throw new Error(r.error ?? 'invalid JSON');
  put(prettyCache, key, r.text);
  return { value: r.text, workerMs: r.ms, totalMs: performance.now() - t0, fromCache: false };
}

/** Parses JSON text to a value (for the tree viewer). */
export async function parseJsonAsync(key: string, text: string): Promise<JsonResult<unknown>> {
  const t0 = performance.now();
  if (valueCache.has(key)) return { value: valueCache.get(key), workerMs: 0, totalMs: performance.now() - t0, fromCache: true };
  const r = await send({ id: nextId++, op: 'value', key, text });
  if (!r.ok) throw new Error(r.error ?? 'invalid JSON');
  put(valueCache, key, r.value);
  return { value: r.value, workerMs: r.ms, totalMs: performance.now() - t0, fromCache: false };
}

/** Synchronous path for small bodies; null when the text is not JSON. */
export function prettyJsonSync(key: string, text: string): string | null {
  const hit = prettyCache.get(key);
  if (hit !== undefined) return hit;
  try {
    const v = JSON.parse(text);
    const out = JSON.stringify(v, null, 2) ?? '';
    put(prettyCache, key, out);
    put(valueCache, key, v);
    return out;
  } catch {
    return null;
  }
}

export function cachedValue(key: string): unknown | undefined {
  return valueCache.get(key);
}
