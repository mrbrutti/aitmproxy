import { describe, expect, it } from 'vitest';
import type { FlowDetail } from '~/model/flow';
import { parseRaw, requestDocument, responseDocument, serializeRaw, type RawRequest } from './rawdoc';

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

describe('read-only raw documents', () => {
  const body = (text: string | null, size = text?.length ?? 0) => ({ text, contentType: null, size, truncated: false });
  const detail = {
    id: 'f1',
    method: 'GET',
    path: '/api/me',
    query: 'v=1',
    httpVersion: 'HTTP/1.1',
    status: 200,
    statusText: 'OK',
    request: { headers: [{ name: 'host', value: '127.0.0.1:1' }, { name: 'accept', value: '*/*' }], body: body(null, 0) },
    response: { headers: [{ name: 'content-type', value: 'application/json' }], body: body('{"user":"ops"}') },
  } as unknown as FlowDetail;

  it('builds the request document: request line with the query, headers, blank line, (empty) body', () => {
    expect(requestDocument(detail)).toBe('GET /api/me?v=1 HTTP/1.1\nhost: 127.0.0.1:1\naccept: */*\n\n');
  });
  it('builds the response document behind a status line', () => {
    expect(responseDocument(detail)).toBe('HTTP/1.1 200 OK\ncontent-type: application/json\n\n{"user":"ops"}');
  });
  it('notes a binary body instead of dropping it, and has no response document without a response', () => {
    const bin = { ...detail, request: { headers: [], body: body(null, 12) }, response: null } as unknown as FlowDetail;
    expect(requestDocument(bin)).toBe('GET /api/me?v=1 HTTP/1.1\n\n[12 bytes — binary body, see Body › Hex]');
    expect(responseDocument(bin)).toBeNull();
  });
});
