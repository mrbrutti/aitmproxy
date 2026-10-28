// The worker's parse + pretty-print on a 5 MB body, timed in node (the browser number is the
// `inspector.prettyWorker` perf mark). Also the bytes helpers.
import { describe, expect, it } from 'vitest';
import { handle } from './json.worker';
import { prettyJsonAsync, parseJsonAsync, prettyJsonSync } from './json-worker';
import { base64ToBytes, bytesToBase64, looksBinary, utf8Decode, utf8Encode } from './bytes';

function bigJson(targetBytes: number): string {
  const items: unknown[] = [];
  let size = 0;
  let i = 0;
  while (size < targetBytes) {
    items.push({
      id: 1000 + i,
      sku: `SKU-${(1000 + i).toString(36).toUpperCase()}`,
      name: 'Aurora Lamp',
      price: (i % 400) + 0.5,
      in_stock: i % 5 !== 0,
      tags: ['electronics', 'home'],
      description: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore.',
      variants: [
        { color: 'graphite', stock: i % 50 },
        { color: 'sand', stock: (i * 7) % 50 },
      ],
      dimensions_mm: { w: 120 + (i % 40), h: 300 + (i % 90), d: 80 },
    });
    size += 420;
    i++;
  }
  return JSON.stringify({ exported_at: '2026-10-27T11:05:00Z', count: items.length, items }, null, 2);
}

describe('json worker', () => {
  it('pretty-prints and parses a 5 MB body (timed)', () => {
    const text = bigJson(5 * 1024 * 1024);
    expect(text.length).toBeGreaterThan(5 * 1024 * 1024);
    const r = handle({ id: 1, op: 'pretty', key: 'k', text });
    expect(r.ok).toBe(true);
    expect(r.text!.length).toBeGreaterThan(1000);
    const v = handle({ id: 2, op: 'value', key: 'k' });
    expect(v.ok).toBe(true);
    expect((v.value as { count: number }).count).toBeGreaterThan(10_000);
    // eslint-disable-next-line no-console
    console.log(`[perf] worker pretty 5 MB: ${r.ms.toFixed(1)} ms (parse+stringify), cached value: ${v.ms.toFixed(2)} ms, chars=${text.length}`);
    expect(r.ms).toBeLessThan(2000);
  });

  it('reports parse errors', () => {
    expect(handle({ id: 3, op: 'pretty', key: 'bad', text: '{nope' })).toMatchObject({ ok: false });
  });

  it('client falls back inline without Worker and caches', async () => {
    const r1 = await prettyJsonAsync('a:1', '{"a":1}');
    expect(r1.value).toBe('{\n  "a": 1\n}');
    const r2 = await prettyJsonAsync('a:1', 'ignored because cached');
    expect(r2.fromCache).toBe(true);
    const v = await parseJsonAsync('a:1', '{"a":1}');
    expect(v.value).toEqual({ a: 1 });
    expect(prettyJsonSync('b:1', '[1]')).toBe('[\n  1\n]');
    expect(prettyJsonSync('b:2', 'nope')).toBeNull();
  });
});

describe('bytes', () => {
  it('round-trips base64', () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    expect(bytesToBase64(utf8Encode('hi'))).toBe('aGk=');
    expect(utf8Decode(base64ToBytes('aGk='))).toBe('hi');
    expect(utf8Decode(base64ToBytes('aGk'))).toBe('hi'); // unpadded
  });
  it('spots binary', () => {
    expect(looksBinary(new Uint8Array([104, 105, 0]))).toBe(true);
    expect(looksBinary(utf8Encode('plain text\n'))).toBe(false);
  });
});
