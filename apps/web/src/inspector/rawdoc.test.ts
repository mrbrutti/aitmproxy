import { describe, expect, it } from 'vitest';
import { parseRaw, serializeRaw, type RawRequest } from './rawdoc';

const req: RawRequest = {
  method: 'POST',
  path: '/api/auth/login?next=%2F',
  version: 'HTTP/2',
  headers: [
    { name: 'host', value: 'auth.shop-staging.test' },
    { name: 'content-type', value: 'application/json' },
    { name: 'x-forwarded-for', value: '127.0.0.1' },
  ],
  body: '{\n  "email": "ops@shop-staging.test",\n  "remember": true\n}',
};

describe('raw request document', () => {
  it('serialises as request line, headers, blank line, body', () => {
    expect(serializeRaw(req)).toBe(
      'POST /api/auth/login?next=%2F HTTP/2\nhost: auth.shop-staging.test\ncontent-type: application/json\nx-forwarded-for: 127.0.0.1\n\n{\n  "email": "ops@shop-staging.test",\n  "remember": true\n}',
    );
  });
  it('round-trips through parse', () => {
    const r = parseRaw(serializeRaw(req));
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.value).toEqual(req);
      expect(serializeRaw(r.value)).toBe(serializeRaw(req));
    }
  });
  it('round-trips an empty body and CRLF input', () => {
    const r = parseRaw('GET /x HTTP/1.1\r\nhost: a\r\n\r\n');
    expect(r.ok && r.value).toEqual({ method: 'GET', path: '/x', version: 'HTTP/1.1', headers: [{ name: 'host', value: 'a' }], body: '' });
  });
  it('defaults the version and upper-cases the method', () => {
    const r = parseRaw('get /');
    expect(r.ok && r.value.method).toBe('GET');
    expect(r.ok && r.value.version).toBe('HTTP/1.1');
  });
  it('reports the bad line inline', () => {
    expect(parseRaw('')).toMatchObject({ ok: false, line: 1 });
    expect(parseRaw('POST nopath HTTP/1.1')).toMatchObject({ ok: false, line: 1 });
    expect(parseRaw('POST / HTTP/1.1\nhost auth.test\n\n')).toMatchObject({ ok: false, line: 2 });
    const r = parseRaw('POST / HTTP/1.1\nhost auth.test\n\n');
    expect(!r.ok && r.error).toMatch(/Line 2/);
  });
  it('keeps a header value containing colons', () => {
    const r = parseRaw('GET / HTTP/1.1\nreferer: https://a.test/x?y=1\n\n');
    expect(r.ok && r.value.headers[0]).toEqual({ name: 'referer', value: 'https://a.test/x?y=1' });
  });
});
